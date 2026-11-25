//go:build linux

package vm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

// Template snapshots (FirecrackerConfig.Snapshots, issue #46). A VM starts
// by restoring a snapshot of a template VM instead of booting.
//
// Build, once per snapshot key (fcSnapshotKey: the VM's exact configuration
// and image, the Firecracker binary and its version, the guest kernel, the
// host kernel and the host CPU). The first VM that needs a missing snapshot
// cold boots and starts the build in the background: a VM in its own jail
// and namespace, as the reserved build UID pair (fcBuildSlot), boots, waits
// until its agent (and an e2b guest's envd) serves, flushes its disks,
// pauses and writes a full snapshot. Root/snapshots/<name> then holds the VM
// state, the guest memory, the template's home disk and meta.json (the key).
// Nothing personal is in it: no sandbox ran there and envd had no /init.
//
// Restore. A clone's jail holds hard links of the image, the VM state and
// the memory file (all root-owned and read-only) and its own sparse copy of
// the template's home disk, which the restored guest already has mounted.
// Its namespace has the tap, gateway MAC and guest address every VM has.
// Firecracker maps the memory file MAP_PRIVATE, so clones share its
// unchanged pages in the host page cache and copy only what they write.
// The guest's vsock device resets on restore; the host redials the agent
// with a bounded retry and sends OpRestore (fresh entropy, the wall clock).
// Any failure destroys the clone, which then cold boots; the reason is
// logged.
//
// Lifetime. A clone's record names its snapshot. A snapshot that no longer
// matches this host (after an upgrade) or was retired is deleted once no
// record names it, and each clone holds hard links of the files it maps, so
// even a deleted snapshot stays readable until its last clone is gone.

const (
	fcSnapshotFormat = 1
	// fcSnapshotJail is the chroot directory holding a clone's links of
	// the snapshot files, or the files a build VMM writes.
	fcSnapshotJail     = "/snapshot"
	fcSnapshotState    = "vmstate"
	fcSnapshotMemory   = "mem"
	fcSnapshotHome     = "home.ext4"
	fcSnapshotMetaName = "meta.json"
	fcAPIName          = "api.sock"
	fcAPIPath          = "/" + fcVsockDir + "/" + fcAPIName
	fcBuildPrefix      = "template-"
	// fcBuildSlot is the UID pair of the one build VM: the last of each
	// stride, never a sandbox slot (fcMaxSlots).
	fcBuildSlot = fcUIDStride - 1
	// fcBuildTime bounds a build beyond the boot timeout: pausing and
	// writing the guest memory to disk.
	fcBuildTime = 5 * time.Minute
	// fcBuildRetry is how long a snapshot whose build failed, or that was
	// retired, is not built again.
	fcBuildRetry = 15 * time.Minute
	// fcRestoreTime bounds a restore from the VMM's start to an agent that
	// accepted OpRestore. A clone that misses it is destroyed (fail closed).
	fcRestoreTime = 10 * time.Second
	// fcRestoreFaults consecutive rejected loads retire a snapshot.
	fcRestoreFaults = 3
)

var (
	fcSnapshotName = regexp.MustCompile(`^[0-9a-f]{24}$`)
	// fcBuildID is a build VM's ID; validAppleID refuses it, so it never
	// names a sandbox.
	fcBuildID = regexp.MustCompile(`^` + fcBuildPrefix + `[0-9a-f]{24}$`)
	// errSnapshotRejected: Firecracker refused to load the snapshot.
	errSnapshotRejected = errors.New("Firecracker rejected the snapshot")
)

// fcHostFacts are what SnapshotFacts reports.
type fcHostFacts struct {
	Firecracker, HostKernel, CPU string
}

// fcSnapshotKey is everything a template snapshot depends on. A VM restores
// a snapshot only when every field equals what it would be built with now;
// any change names another snapshot (fcSnapshotKey.name), which is built,
// and the old one is collected once unused.
type fcSnapshotKey struct {
	Format            int    `json:"format"`
	Firecracker       string `json:"firecracker"`
	FirecrackerSHA256 string `json:"firecrackerSha256"`
	KernelSHA256      string `json:"kernelSha256"`
	HostKernel        string `json:"hostKernel"`
	CPU               string `json:"cpu"`
	// CPUTemplate is the Firecracker CPU template: none is configured, so
	// a snapshot restores only on this exact CPU (CPU above).
	CPUTemplate string `json:"cpuTemplate"`
	Image       string `json:"image"`
	// ImageID is the image file's identity (device, inode, size, change
	// times): images are immutable, so a replaced image is another one.
	ImageID     string `json:"imageId"`
	HomeDiskMiB int    `json:"homeDiskMiB"`
	// Config is the exact VM configuration (vm.json) the template booted.
	Config string `json:"config"`
}

func (k fcSnapshotKey) name() string {
	data, _ := json.Marshal(k)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:12])
}

// fcSnapshotMeta is a stored snapshot's meta.json.
type fcSnapshotMeta struct {
	Key fcSnapshotKey `json:"key"`
	// The shape of the VMs it starts, from which Key is recomputed.
	CPUs      int       `json:"cpus"`
	MemoryMiB int       `json:"memoryMiB"`
	Envd      bool      `json:"envd,omitempty"`
	Hardened  bool      `json:"hardened,omitempty"`
	Created   time.Time `json:"created"`
}

func (m fcSnapshotMeta) spec() Spec {
	return Spec{Image: m.Key.Image, CPUs: m.CPUs, MemoryMiB: m.MemoryMiB, Envd: m.Envd, Hardened: m.Hardened}
}

// fcSnapshots is the driver's snapshot bookkeeping.
type fcSnapshots struct {
	mu sync.Mutex
	// digests caches file SHA-256s by path: {identity, sum}.
	digests map[string][2]string
	// facts are SnapshotFacts for the Firecracker binary whose digest is
	// factsFor.
	facts    fcHostFacts
	factsFor string
	// building names the snapshot being built ("" when none); cancel stops
	// it and done closes when it has ended and removed its VM.
	building string
	cancel   context.CancelFunc
	done     chan struct{}
	// failed holds when a snapshot's build last failed or it was retired;
	// faults counts its consecutive rejected loads.
	failed map[string]time.Time
	faults map[string]int
	// gc serializes collections.
	gc sync.Mutex
}

func (d *FirecrackerDriver) snapshotsDir() string { return filepath.Join(d.cfg.Root, "snapshots") }
func (d *FirecrackerDriver) snapshotDir(name string) string {
	return filepath.Join(d.snapshotsDir(), name)
}

// fileIdentity names a file's current content without reading it: a
// replacement (another inode) or a write (size, modification time) changes
// it. The change time is left out: every VM's jail hard-links the kernel
// and the image, which changes theirs.
func fileIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: no file identity", path)
	}
	return fmt.Sprintf("%d:%d:%d:%d", stat.Dev, stat.Ino, stat.Size, stat.Mtim.Nano()), nil
}

// fileDigest is path's SHA-256, hashed again only when its identity changed.
func (d *FirecrackerDriver) fileDigest(path string) (string, error) {
	identity, err := fileIdentity(path)
	if err != nil {
		return "", err
	}
	s := &d.snap
	s.mu.Lock()
	cached := s.digests[path]
	s.mu.Unlock()
	if cached[0] == identity {
		return cached[1], nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if again, err := fileIdentity(path); err != nil || again != identity {
		return "", errors.Join(fmt.Errorf("%s changed while it was hashed", path), err)
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	s.mu.Lock()
	if s.digests == nil {
		s.digests = map[string][2]string{}
	}
	s.digests[path] = [2]string{identity, sum}
	s.mu.Unlock()
	return sum, nil
}

// hostFacts is SnapshotFacts, asked again only for another binary.
func (d *FirecrackerDriver) hostFacts(ctx context.Context, binary string) (fcHostFacts, error) {
	s := &d.snap
	s.mu.Lock()
	facts, cached := s.facts, s.factsFor == binary
	s.mu.Unlock()
	if cached {
		return facts, nil
	}
	facts, err := d.host.SnapshotFacts(ctx, d.cfg.Firecracker)
	if err != nil {
		return fcHostFacts{}, err
	}
	if facts.Firecracker == "" || facts.HostKernel == "" || facts.CPU == "" {
		return fcHostFacts{}, errors.New("incomplete Firecracker host facts")
	}
	s.mu.Lock()
	s.facts, s.factsFor = facts, binary
	s.mu.Unlock()
	return facts, nil
}

// snapshotKey is the key of spec's template snapshot as this host would
// build it now.
func (d *FirecrackerDriver) snapshotKey(ctx context.Context, spec Spec) (fcSnapshotKey, error) {
	if _, ok := d.images[spec.Image]; !ok {
		return fcSnapshotKey{}, fmt.Errorf("Firecracker image %q is not allowlisted", spec.Image)
	}
	binary, err := d.fileDigest(d.cfg.Firecracker)
	if err != nil {
		return fcSnapshotKey{}, err
	}
	kernel, err := d.fileDigest(d.cfg.Kernel)
	if err != nil {
		return fcSnapshotKey{}, err
	}
	facts, err := d.hostFacts(ctx, binary)
	if err != nil {
		return fcSnapshotKey{}, err
	}
	image, err := fileIdentity(spec.Image)
	if err != nil {
		return fcSnapshotKey{}, err
	}
	config, err := d.vmConfig(Spec{Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, Envd: spec.Envd, Hardened: spec.Hardened})
	if err != nil {
		return fcSnapshotKey{}, err
	}
	return fcSnapshotKey{
		Format: fcSnapshotFormat, Firecracker: facts.Firecracker, FirecrackerSHA256: binary, KernelSHA256: kernel,
		HostKernel: facts.HostKernel, CPU: facts.CPU, CPUTemplate: "none",
		Image: spec.Image, ImageID: image, HomeDiskMiB: d.cfg.HomeDiskMiB, Config: string(config),
	}, nil
}

func readSnapshotMeta(dir string) (fcSnapshotMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, fcSnapshotMetaName))
	if err != nil {
		return fcSnapshotMeta{}, err
	}
	var meta fcSnapshotMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return fcSnapshotMeta{}, fmt.Errorf("unreadable snapshot metadata: %w", err)
	}
	return meta, nil
}

// errNoSnapshot: the snapshot has not been built yet.
var errNoSnapshot = errors.New("no template snapshot yet")

// checkSnapshot requires snapshot name to be stored, complete and built
// with exactly key: a snapshot of another Firecracker, kernel, image, CPU or
// configuration is refused, whatever its directory is called.
func (d *FirecrackerDriver) checkSnapshot(name string, key fcSnapshotKey) error {
	dir := d.snapshotDir(name)
	meta, err := readSnapshotMeta(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", errNoSnapshot, name)
	}
	if err != nil {
		return fmt.Errorf("template snapshot %s: %w", name, err)
	}
	if meta.Key != key {
		return fmt.Errorf("template snapshot %s was built for another Firecracker, kernel, image, host CPU or VM configuration", name)
	}
	for _, file := range []string{fcSnapshotState, fcSnapshotMemory, fcSnapshotHome} {
		info, err := os.Lstat(filepath.Join(dir, file))
		if err != nil {
			return fmt.Errorf("template snapshot %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("template snapshot %s: %s is not a regular file", name, file)
		}
	}
	return nil
}

// createFromSnapshot starts spec by restoring its template snapshot. It
// reports false when the VM must cold boot instead, after logging why and
// removing every trace of the attempt; true with the outcome otherwise. A
// missing snapshot is built in the background for the next VM.
func (d *FirecrackerDriver) createFromSnapshot(ctx context.Context, spec Spec, meta fcMeta) (bool, error) {
	coldBoot := func(format string, args ...any) (bool, error) {
		log.Printf("firecracker: %s cold boots: "+format, append([]any{spec.ID}, args...)...)
		return false, nil
	}
	if spec.Volume != nil {
		return coldBoot("an attached volume is never part of a template snapshot")
	}
	key, err := d.snapshotKey(ctx, spec)
	if err != nil {
		return coldBoot("no snapshot key: %v", err)
	}
	name := key.name()
	if err := d.checkSnapshot(name, key); err != nil {
		if !errors.Is(err, errNoSnapshot) {
			d.retireSnapshot(name)
		}
		d.buildSnapshot(spec, key, name)
		return coldBoot("%v", err)
	}
	meta.Snapshot = name
	if err := d.writeRecord(spec, &meta); err != nil {
		return true, err
	}
	started := time.Now()
	startup := &fcStartup{}
	err = d.restore(ctx, spec, meta, startup)
	if err == nil {
		d.restoreFault(name, false)
		log.Printf("firecracker: %s restored from template snapshot %s in %v", spec.ID, name, time.Since(started).Round(time.Millisecond))
		return true, nil
	}
	if d.cfg.ConsoleLog {
		startup.readFile(d.consoleLogPath(spec.ID)) // before cleanup removes the jail
	}
	cleanupErr := d.cleanupCreated(spec.ID)
	err = startup.annotate(errors.Join(err, cleanupErr))
	if cleanupErr != nil {
		return true, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return true, errors.Join(ctxErr, err)
	}
	if errors.Is(err, errSnapshotRejected) && d.restoreFault(name, true) {
		d.retireSnapshot(name)
	}
	return coldBoot("restore from template snapshot %s failed: %v", name, err)
}

// restoreFault counts a snapshot's consecutive rejected loads (rejected) or
// resets the count, and reports whether it reached fcRestoreFaults.
func (d *FirecrackerDriver) restoreFault(name string, rejected bool) bool {
	s := &d.snap
	s.mu.Lock()
	defer s.mu.Unlock()
	if !rejected {
		delete(s.faults, name)
		return false
	}
	if s.faults == nil {
		s.faults = map[string]int{}
	}
	s.faults[name]++
	return s.faults[name] >= fcRestoreFaults
}

// restore starts the recorded VM from its snapshot in a fresh jail and
// network, then personalises it.
func (d *FirecrackerDriver) restore(ctx context.Context, spec Spec, meta fcMeta, startup *fcStartup) error {
	if err := d.prepareRestoreJail(spec, meta); err != nil {
		return err
	}
	if err := d.launch(ctx, spec, meta, startup, "--api-sock", fcAPIPath); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, fcRestoreTime)
	defer cancel()
	if err := d.waitAPI(ctx, spec.ID, meta.VMMUID); err != nil {
		return err
	}
	err := d.callAPI(ctx, spec.ID, meta.VMMUID, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": fcSnapshotJail + "/" + fcSnapshotState,
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": fcSnapshotJail + "/" + fcSnapshotMemory},
		"resume_vm":     true,
	})
	if fault := (*fcAPIError)(nil); errors.As(err, &fault) {
		return errors.Join(errSnapshotRejected, err)
	}
	if err != nil {
		return err
	}
	if err := d.personalise(ctx, spec.ID, meta.VMMUID); err != nil {
		return err
	}
	return d.confirmStarted(ctx, spec.ID)
}

// prepareRestoreJail lays out a clone's chroot: a hard link of the image
// (the root drive the snapshot names), a sparse copy of the template's home
// disk owned by the VMM UID, the socket directory, and hard links of the VM
// state and memory file, root-owned and read-only. The kernel and the VM
// configuration are not needed: the guest is already booted.
func (d *FirecrackerDriver) prepareRestoreJail(spec Spec, meta fcMeta) error {
	root, err := d.makeJail(spec.ID)
	if err != nil {
		return err
	}
	if err := os.Link(spec.Image, filepath.Join(root, "rootfs.ext4")); err != nil {
		return fmt.Errorf("link image into jail (same filesystem required): %w", err)
	}
	store := d.snapshotDir(meta.Snapshot)
	home := filepath.Join(root, "home.ext4")
	if err := copySparse(filepath.Join(store, fcSnapshotHome), home, 0o600); err != nil {
		return fmt.Errorf("copy the template home disk: %w", err)
	}
	if err := d.host.Chown(home, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	if err := d.makeRunDir(root, meta); err != nil {
		return err
	}
	dir := filepath.Join(root, fcSnapshotJail)
	if err := mkdirExact(dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{fcSnapshotState, fcSnapshotMemory} {
		if err := os.Link(filepath.Join(store, name), filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("link template snapshot into jail: %w", err)
		}
	}
	return nil
}

// copySparse copies src to a new file dst, only the ranges that hold data:
// holes stay holes, so a mostly empty disk image copies in milliseconds.
func copySparse(src, dst string, mode os.FileMode) (err error) {
	in, err := os.OpenFile(src, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, out.Close())
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	size := info.Size()
	if err := out.Truncate(size); err != nil {
		return err
	}
	inFD, outFD := int(in.Fd()), int(out.Fd())
	for offset := int64(0); offset < size; {
		data, err := unix.Seek(inFD, offset, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // only a hole remains
		}
		if err != nil {
			return err
		}
		hole, err := unix.Seek(inFD, data, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		for data < hole {
			from, to := data, data
			n, err := unix.CopyFileRange(inFD, &from, outFD, &to, int(min(hole-data, 1<<30)), 0)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("%s ended while it was copied", src)
			}
			data += int64(n)
		}
		offset = hole
	}
	return out.Chmod(mode)
}

// personalise redials a just-restored guest's agent and sends it OpRestore:
// fresh entropy for its kernel and the wall clock. The guest's vsock device
// reset on restore, closing every connection; the agent still listens but
// can need a moment, so a failed dial is retried with backoff until ctx
// (fcRestoreTime) ends. An agent that answers with an error is not
// retried. Either way the guest is not handed out (fail closed).
func (d *FirecrackerDriver) personalise(ctx context.Context, id string, uid int) error {
	entropy := make([]byte, guestagent.RestoreEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return err
	}
	delay := time.Millisecond
	var last error
	for {
		conn, err := d.dialAgentAs(ctx, id, uid)
		if err == nil {
			err = guestagent.Restore(ctx, conn, entropy, time.Now())
			_ = conn.Close()
			if err == nil {
				return nil
			}
			if errors.Is(err, guestagent.ErrRefused) {
				return fmt.Errorf("guest agent of %q after restore: %w", id, err)
			}
		}
		last = err
		if populated, perr := d.host.CgroupPopulated(id); perr != nil || !populated {
			return errors.Join(fmt.Errorf("Firecracker VMM for %q exited after restore", id), last, perr)
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("guest agent of %q did not answer after restore: %w", id, ctx.Err()), last)
		case <-time.After(delay):
		}
		delay = min(2*delay, 50*time.Millisecond)
	}
}

// waitAPI waits until the VMM of id, running as uid, accepts connections on
// its API socket, or it exits, or ctx ends.
func (d *FirecrackerDriver) waitAPI(ctx context.Context, id string, uid int) error {
	delay := time.Millisecond
	for {
		conn, err := d.host.DialAPI(ctx, d.chroot(id), uid)
		if err == nil {
			return conn.Close()
		}
		if populated, perr := d.host.CgroupPopulated(id); perr != nil || !populated {
			return errors.Join(fmt.Errorf("Firecracker VMM for %q exited before serving its API", id), err, perr)
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("Firecracker API of %q did not come up: %w", id, ctx.Err()), err)
		case <-time.After(delay):
		}
		delay = min(2*delay, 20*time.Millisecond)
	}
}

// fcAPIError is a request the Firecracker API answered with an error.
type fcAPIError struct {
	Status int
	Fault  string
}

func (e *fcAPIError) Error() string {
	return fmt.Sprintf("Firecracker API answered %d: %s", e.Status, e.Fault)
}

// callAPI sends one JSON request to the API of VM id's VMM (running as
// uid). The VMM is not trusted: its reply is read only up to a bound.
func (d *FirecrackerDriver) callAPI(ctx context.Context, id string, uid int, method, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.host.DialAPI(ctx, d.chroot(id), uid)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return fmt.Errorf("Firecracker API %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode/100 == 2 {
		return nil
	}
	var fault struct {
		Message string `json:"fault_message"`
	}
	if json.Unmarshal(reply, &fault) != nil || fault.Message == "" {
		fault.Message = strings.TrimSpace(string(reply))
	}
	return &fcAPIError{Status: response.StatusCode, Fault: fault.Message}
}

// buildSnapshot starts the background build of snapshot name for spec's
// shape, unless a build is running or this one failed (or was retired)
// within fcBuildRetry.
func (d *FirecrackerDriver) buildSnapshot(spec Spec, key fcSnapshotKey, name string) {
	s := &d.snap
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.building != "" || time.Since(s.failed[name]) < fcBuildRetry {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.BootTimeout+fcBuildTime)
	done := make(chan struct{})
	s.building, s.cancel, s.done = name, cancel, done
	build := Spec{ID: fcBuildPrefix + name, Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, Envd: spec.Envd, Hardened: spec.Hardened}
	go func() {
		defer close(done)
		defer cancel()
		started := time.Now()
		err := d.runBuild(ctx, build, key, name)
		s.mu.Lock()
		s.building, s.cancel = "", nil
		if err != nil {
			if s.failed == nil {
				s.failed = map[string]time.Time{}
			}
			s.failed[name] = time.Now()
		}
		s.mu.Unlock()
		took := time.Since(started).Round(time.Millisecond)
		if err != nil {
			log.Printf("firecracker: template snapshot %s of %s: build failed after %v (next attempt in %v at the earliest): %v", name, spec.Image, took, fcBuildRetry, err)
		} else {
			log.Printf("firecracker: template snapshot %s of %s built in %v", name, spec.Image, took)
		}
		d.collectSnapshots()
	}()
}

// stopBuilds stops a running build, waits until it has removed its VM, and
// removes what an interrupted build left.
func (d *FirecrackerDriver) stopBuilds(ctx context.Context) error {
	s := &d.snap
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("template snapshot build did not stop: %w", ctx.Err())
		}
	}
	return d.removeBuilds(ctx)
}

// buildTraces lists the IDs of build VMs with any trace on the host.
func (d *FirecrackerDriver) buildTraces() ([]string, error) {
	found := map[string]bool{}
	jails, err := readDirNames(d.jailsDir())
	if err != nil {
		return nil, err
	}
	namespaces, err := d.host.Netns()
	if err != nil {
		return nil, err
	}
	cgroups, err := d.host.Cgroups()
	if err != nil {
		return nil, err
	}
	for _, name := range namespaces {
		if id, ok := strings.CutPrefix(name, d.names.netnsPrefix); ok {
			jails = append(jails, id)
		}
	}
	for _, name := range cgroups {
		id, _ := strings.CutPrefix(name, fcNetCgroup)
		jails = append(jails, id)
	}
	for _, id := range jails {
		if fcBuildID.MatchString(id) {
			found[id] = true
		}
	}
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

// removeBuilds destroys every build VM but the running build's.
func (d *FirecrackerDriver) removeBuilds(ctx context.Context) error {
	d.snap.mu.Lock()
	building := d.snap.building
	d.snap.mu.Unlock()
	ids, err := d.buildTraces()
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if building == "" || id != fcBuildPrefix+building {
			errs = append(errs, d.destroyBuild(ctx, id))
		}
	}
	return errors.Join(errs...)
}

// destroyBuild removes every trace of build VM id, from any partial state.
func (d *FirecrackerDriver) destroyBuild(ctx context.Context, id string) error {
	if !fcBuildID.MatchString(id) {
		return fmt.Errorf("invalid template build ID %q", id)
	}
	defer d.dropConsole(id)
	for _, cgroup := range []string{id, fcNetCgroup + id} {
		if err := d.host.KillCgroup(ctx, cgroup); err != nil {
			return err
		}
	}
	if err := d.host.DeleteNetns(ctx, d.names.netnsPrefix+id); err != nil {
		return err
	}
	return os.RemoveAll(d.jailDir(id))
}

// runBuild builds snapshot name: boot spec as the build VM, wait until it
// serves, flush its disks, pause it, write a full snapshot, stop it and
// store the files. The build VM is removed whatever happens.
func (d *FirecrackerDriver) runBuild(ctx context.Context, spec Spec, key fcSnapshotKey, name string) (err error) {
	id := spec.ID
	if err := d.Ready(ctx); err != nil {
		return fmt.Errorf("firewall is not armed before the build: %w", err)
	}
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return err
	}
	if need := uint64(d.cfg.DiskFloorMiB+d.cfg.HomeDiskMiB+spec.MemoryMiB) << 20; free < need {
		return fmt.Errorf("%w: %d MiB free, %d MiB floor plus the snapshot's memory and home disk needed", ErrDiskFloor, free>>20, d.cfg.DiskFloorMiB)
	}
	// The build VM runs beside the VM whose create started it: it must not
	// take the host below the memory floor either.
	if d.cfg.MemoryFloorMiB > 0 {
		memory, err := d.host.HostMemory()
		if err != nil {
			return err
		}
		if need := uint64(d.cfg.MemoryFloorMiB+spec.MemoryMiB+fcVMMOverhead) << 20; memory.AvailableBytes < need {
			return fmt.Errorf("%w: %d MiB available, the floor plus the build VM need %d MiB", ErrMemoryPressure, memory.AvailableBytes>>20, need>>20)
		}
	}
	if err := d.destroyBuild(ctx, id); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, d.destroyBuild(cleanup, id))
	}()
	meta := fcMeta{ID: id, VMMUID: d.cfg.UIDBase + fcBuildSlot, NetUID: d.cfg.UIDBase + fcUIDStride + fcBuildSlot,
		Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, Envd: spec.Envd, Hardened: spec.Hardened}
	if err := d.prepareJail(spec, meta); err != nil {
		return err
	}
	out := filepath.Join(d.chroot(id), fcSnapshotJail)
	if err := mkdirExact(out, 0o700); err != nil {
		return err
	}
	if err := d.host.Chown(out, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	startup := &fcStartup{}
	if err := d.launch(ctx, spec, meta, startup, "--api-sock", fcAPIPath, "--config-file", fcConfigPath); err != nil {
		return err
	}
	features, err := d.waitAgent(ctx, spec, meta.VMMUID)
	if err != nil {
		return startup.annotate(err)
	}
	if !slices.Contains(features, guestagent.FeatureRestore) {
		return fmt.Errorf("%w: the guest agent of %s cannot be restored from a snapshot", ErrImageTooOld, spec.Image)
	}
	if spec.Envd {
		if err := d.waitEnvd(ctx, id, meta.VMMUID); err != nil {
			return err
		}
	}
	conn, err := d.dialAgentAs(ctx, id, meta.VMMUID)
	if err != nil {
		return err
	}
	err = guestagent.Sync(ctx, conn)
	_ = conn.Close()
	if err != nil {
		return fmt.Errorf("flush the template's disks: %w", err)
	}
	if err := d.callAPI(ctx, id, meta.VMMUID, http.MethodPatch, "/vm", map[string]string{"state": "Paused"}); err != nil {
		return err
	}
	if err := d.callAPI(ctx, id, meta.VMMUID, http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_type": "Full",
		"snapshot_path": fcSnapshotJail + "/" + fcSnapshotState,
		"mem_file_path": fcSnapshotJail + "/" + fcSnapshotMemory,
	}); err != nil {
		return err
	}
	// The VMM must be gone before its files are taken.
	if err := d.host.KillCgroup(ctx, id); err != nil {
		return err
	}
	return d.storeSnapshot(spec, key, name)
}

// waitEnvd waits until envd accepts connections in build VM id: a snapshot
// of a guest whose envd is still starting would start every clone that way.
func (d *FirecrackerDriver) waitEnvd(ctx context.Context, id string, uid int) error {
	for {
		conn, err := d.dialAgentAs(ctx, id, uid)
		if err == nil {
			if err = guestagent.OpenPort(ctx, conn, EnvdPort); err == nil {
				return conn.Close()
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("envd of template build %q did not start: %w", id, ctx.Err()), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// storeSnapshot moves the stopped build VM's snapshot and home disk into
// Root/snapshots/<name>, root-owned and read-only, beside its meta.json.
// The VMM wrote the files as the build UID inside its jail: each must be a
// regular file with one link, so nothing else on the host is ever taken.
func (d *FirecrackerDriver) storeSnapshot(spec Spec, key fcSnapshotKey, name string) error {
	root := d.chroot(spec.ID)
	base := d.snapshotsDir()
	if err := mkdirExact(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	tmp := d.snapshotDir(name + ".tmp")
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := mkdirExact(tmp, 0o700); err != nil {
		return err
	}
	for _, file := range []struct {
		from, to string
		mode     os.FileMode
	}{
		{filepath.Join(root, fcSnapshotJail, fcSnapshotState), fcSnapshotState, 0o444},
		{filepath.Join(root, fcSnapshotJail, fcSnapshotMemory), fcSnapshotMemory, 0o444},
		{filepath.Join(root, "home.ext4"), fcSnapshotHome, 0o400},
	} {
		info, err := os.Lstat(file.from)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
			return fmt.Errorf("template snapshot file %s is not a regular file of the build VM", file.to)
		}
		to := filepath.Join(tmp, file.to)
		if err := os.Rename(file.from, to); err != nil {
			return err
		}
		if err := errors.Join(d.host.Chown(to, 0, 0), os.Chmod(to, file.mode)); err != nil {
			return err
		}
	}
	meta, err := json.Marshal(fcSnapshotMeta{Key: key, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB,
		Envd: spec.Envd, Hardened: spec.Hardened, Created: time.Now().UTC()})
	if err != nil {
		return err
	}
	if err := writeFileExcl(filepath.Join(tmp, fcSnapshotMetaName), meta, 0o444); err != nil {
		return err
	}
	if err := fcSyncPath(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, d.snapshotDir(name)); err != nil {
		return err
	}
	return fcSyncPath(base)
}

// retireSnapshot sets snapshot name aside for collection and builds it
// again no sooner than fcBuildRetry.
func (d *FirecrackerDriver) retireSnapshot(name string) {
	dir := d.snapshotDir(name)
	if err := os.Rename(dir, fmt.Sprintf("%s.retired-%d", dir, time.Now().UnixNano())); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("firecracker: retire template snapshot %s: %v", name, err)
	} else if err == nil {
		log.Printf("firecracker: template snapshot %s retired", name)
	}
	s := &d.snap
	s.mu.Lock()
	if s.failed == nil {
		s.failed = map[string]time.Time{}
	}
	s.failed[name] = time.Now()
	delete(s.faults, name)
	s.mu.Unlock()
	d.collectSnapshots()
}

// collectSnapshots deletes each stored snapshot that no VM record names and
// that this host will not restore again: one whose key differs from what it
// would be built with now (Firecracker, kernel, image, host or VM
// configuration changed, or snapshots are off), a retired one, and what an
// interrupted build left. Anything else in the directory is left alone.
func (d *FirecrackerDriver) collectSnapshots() {
	s := &d.snap
	s.gc.Lock()
	defer s.gc.Unlock()
	names, err := readDirNames(d.snapshotsDir())
	if err != nil || len(names) == 0 {
		if err != nil {
			log.Printf("firecracker: template snapshots: %v", err)
		}
		return
	}
	vms, err := d.inventory()
	if err != nil {
		log.Printf("firecracker: template snapshots not collected: %v", err)
		return
	}
	refs := map[string]int{}
	for _, vm := range vms {
		if vm.meta != nil && vm.meta.Snapshot != "" {
			refs[vm.meta.Snapshot]++
		}
	}
	s.mu.Lock()
	building := s.building
	s.mu.Unlock()
	for _, entry := range names {
		base, suffix, _ := strings.Cut(entry, ".")
		if !fcSnapshotName.MatchString(base) {
			continue
		}
		var remove bool
		switch {
		case suffix == "tmp":
			remove = base != building
		case strings.HasPrefix(suffix, "retired-"):
			remove = refs[base] == 0
		case suffix == "":
			remove = refs[base] == 0 && d.snapshotStale(base)
		}
		if !remove {
			continue
		}
		if err := os.RemoveAll(filepath.Join(d.snapshotsDir(), entry)); err != nil {
			log.Printf("firecracker: remove template snapshot %s: %v", entry, err)
		} else {
			log.Printf("firecracker: template snapshot %s removed: no VM uses it and none will", entry)
		}
	}
}

// snapshotStale reports whether stored snapshot name would not be restored
// by this driver now. A key that cannot be computed for a passing reason
// (the version check failed) keeps the snapshot until the next collection.
func (d *FirecrackerDriver) snapshotStale(name string) bool {
	if !d.cfg.Snapshots {
		return true
	}
	meta, err := readSnapshotMeta(d.snapshotDir(name))
	if err != nil {
		return true
	}
	if _, ok := d.images[meta.Key.Image]; !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key, err := d.snapshotKey(ctx, meta.spec())
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	return key != meta.Key || key.name() != name
}
