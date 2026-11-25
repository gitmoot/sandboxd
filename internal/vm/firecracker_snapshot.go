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
// even a deleted snapshot stays readable until its last clone is gone. A
// current snapshot is deleted too once no record names it and none was
// built or restored from for fcSnapshotIdle, or fcSnapshotServedIdle when
// it is of the shape this host serves (FirecrackerConfig CPUs and
// MemoryMiB). Whether its image, envd and hardening are still asked for is
// the gateway's to know (a template's profile can change), so no snapshot
// is kept for good.
//
// Trust. Each key names files by path, which are resolved again to link
// them into a jail: the links are checked to be the files the key was
// computed from (checkLinked), and so is the copy of the Firecracker binary
// the jailer made in a build's jail and ran (launchedDigest). A build VMM
// owns its chroot and may replace anything in it, so its output is taken
// only through directories opened before it started (takeVMMFile).

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
	// fcSnapshotIdle is how long a snapshot no VM uses is kept after it was
	// built or last restored from, when its shape is not the one this host
	// serves; fcSnapshotServedIdle, when it is.
	fcSnapshotIdle       = time.Hour
	fcSnapshotServedIdle = 24 * time.Hour
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
	// gc serializes collections; sweep is the next one, due when a kept
	// snapshot expires. From stopBuilds until Arm the driver is stopped: no
	// build or due collection starts. sweeps counts the due collections
	// running; swept closes when the last of them has ended.
	gc      sync.Mutex
	sweep   *time.Timer
	stopped bool
	sweeps  int
	swept   chan struct{}
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
	return d.linkDigest(path, path)
}

// linkDigest is the SHA-256 of link, a hard link of path (or path itself),
// cached as path's: one digest per path, of the inode it was computed for,
// so a link of the file the cache holds is not read again.
func (d *FirecrackerDriver) linkDigest(path, link string) (string, error) {
	identity, err := fileIdentity(link)
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
	file, err := os.Open(link)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if again, err := fileIdentity(link); err != nil || again != identity {
		return "", errors.Join(fmt.Errorf("%s changed while it was hashed", link), err)
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

// checkLinked requires the image linked into chroot, and with kernel the
// kernel, to be the files key was computed from. Linking resolved their
// paths again, so a file replaced in between would otherwise boot under the
// key of the one it replaced, or a snapshot would resume on another root
// disk. The links are the inodes the VMM opens: the image's identity is
// checked, and the kernel's digest (one hash per kernel, see linkDigest).
func (d *FirecrackerDriver) checkLinked(chroot string, key fcSnapshotKey, kernel bool) error {
	image, err := fileIdentity(filepath.Join(chroot, "rootfs.ext4"))
	if err != nil {
		return err
	}
	if image != key.ImageID {
		return fmt.Errorf("image %s is not the one its template snapshot key was computed from: it was replaced", key.Image)
	}
	if !kernel {
		return nil
	}
	sum, err := d.linkDigest(d.cfg.Kernel, filepath.Join(chroot, "vmlinux"))
	if err != nil {
		return err
	}
	if sum != key.KernelSHA256 {
		return fmt.Errorf("guest kernel %s is not the one its template snapshot key was computed from: it was replaced", d.cfg.Kernel)
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
	// A restore is a use: its time is the directory's (unusedSnapshot).
	now := time.Now()
	if err := os.Chtimes(d.snapshotDir(name), now, now); err != nil {
		log.Printf("firecracker: template snapshot %s: %v", name, err)
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
// (the root drive the snapshot names), which must be the very image the
// snapshot was built from, a sparse copy of the template's home disk owned
// by the VMM UID, the socket directory, and hard links of the VM state and
// memory file, root-owned and read-only. The kernel and the VM
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
	built, err := readSnapshotMeta(store)
	if err != nil {
		return fmt.Errorf("template snapshot %s: %w", meta.Snapshot, err)
	}
	if err := d.checkLinked(root, built.Key, false); err != nil {
		return err
	}
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
// shape, unless the driver is stopped (stopBuilds), a build is running or
// this one failed (or was retired) within fcBuildRetry.
func (d *FirecrackerDriver) buildSnapshot(spec Spec, key fcSnapshotKey, name string) {
	s := &d.snap
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.building != "" || time.Since(s.failed[name]) < fcBuildRetry {
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

// stopBuilds stops the driver's snapshot work until Arm: no build or due
// collection starts any more, a running build is stopped and awaited until
// it has removed its VM, and so is a due collection already running. It
// then removes what an interrupted build left. Whatever starts the driver
// again collects (Arm).
func (d *FirecrackerDriver) stopBuilds(ctx context.Context) error {
	s := &d.snap
	s.mu.Lock()
	s.stopped = true
	if s.sweep != nil {
		s.sweep.Stop()
		s.sweep = nil
	}
	cancel, done, swept := s.cancel, s.done, s.swept
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, ended := range []chan struct{}{done, swept} {
		if ended == nil {
			continue
		}
		select {
		case <-ended:
		case <-ctx.Done():
			return fmt.Errorf("template snapshot build or collection did not stop: %w", ctx.Err())
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
	defer d.dropConsole(id)
	if err := d.stopBuild(ctx, id); err != nil {
		return err
	}
	return d.removeBuild(ctx, id)
}

// stopBuild stops build VM id's VMM: once it returns nil the VMM cgroup is
// empty, and nothing of the build can write its jail.
func (d *FirecrackerDriver) stopBuild(ctx context.Context, id string) error {
	if !fcBuildID.MatchString(id) {
		return fmt.Errorf("invalid template build ID %q", id)
	}
	return d.host.KillCgroup(ctx, id)
}

// removeBuild removes the network stack, namespace and jail of build VM id,
// whose VMM is stopped.
func (d *FirecrackerDriver) removeBuild(ctx context.Context, id string) error {
	if err := d.host.KillCgroup(ctx, fcNetCgroup+id); err != nil {
		return err
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
	// held is what the build holds while its VMM may still write: the
	// directories its admission reads and the admission itself. They go
	// once the build's VMM is stopped, whatever removing its network stack,
	// namespace and jail then does; if the VMM cannot be stopped, it may
	// still be writing and the admission stays held until the daemon exits.
	var held []func()
	admitted := false
	defer func() {
		defer d.dropConsole(id)
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if stopErr := d.stopBuild(cleanup, id); stopErr != nil {
			err = errors.Join(err, stopErr)
			if admitted {
				log.Printf("firecracker: template build %s could not be stopped; its snapshot space stays held", id)
				return
			}
		} else if removeErr := d.removeBuild(cleanup, id); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove the stopped template build: %w", removeErr))
		}
		for _, free := range slices.Backward(held) {
			free()
		}
	}()
	meta := fcMeta{ID: id, VMMUID: d.cfg.UIDBase + fcBuildSlot, NetUID: d.cfg.UIDBase + fcUIDStride + fcBuildSlot,
		Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB, Envd: spec.Envd, Hardened: spec.Hardened}
	if err := d.prepareJail(spec, meta); err != nil {
		return err
	}
	root := d.chroot(id)
	if err := d.checkLinked(root, key, true); err != nil {
		return err
	}
	out := filepath.Join(root, fcSnapshotJail)
	if err := mkdirExact(out, 0o700); err != nil {
		return err
	}
	if err := d.host.Chown(out, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	// The VMM owns its chroot and can replace anything in it: its output is
	// taken only through the chroot and output directories opened now,
	// while the jail is still the daemon's alone.
	const dirFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	chrootDir, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		return fmt.Errorf("open the build jail: %w", err)
	}
	held = append(held, func() { _ = unix.Close(chrootDir) })
	outDir, err := unix.Openat(chrootDir, filepath.Base(fcSnapshotJail), dirFlags, 0)
	if err != nil {
		return fmt.Errorf("open the build jail: %w", err)
	}
	held = append(held, func() { _ = unix.Close(outDir) })
	// The snapshot's memory and state files and the home disk the guest
	// writes are admitted as one write, as a pause's snapshot is. Firecracker
	// offers the guest no discard, so the home disk's blocks only grow.
	release, err := d.admitWrite(&fcWrite{
		what: "snapshot memory, VM state and home disk", need: uint64(d.cfg.HomeDiskMiB+spec.MemoryMiB+fcSnapshotStateMiB) << 20, owner: meta.VMMUID,
		files: []fcWrittenFile{{chrootDir, "home.ext4"}, {outDir, fcSnapshotState}, {outDir, fcSnapshotMemory}},
	})
	if err != nil {
		return err
	}
	admitted = true
	held = append(held, release)
	startup := &fcStartup{}
	if err := d.launch(ctx, spec, meta, startup, fcBootArgs...); err != nil {
		return err
	}
	// The jailer copied the Firecracker binary into the jail and runs the
	// copy: it must be the binary key was computed from, whatever the
	// install path holds by now.
	if sum, err := launchedDigest(chrootDir, filepath.Base(d.cfg.Firecracker)); err != nil || sum != key.FirecrackerSHA256 {
		return errors.Join(fmt.Errorf("Firecracker binary %s was replaced as the template build started", d.cfg.Firecracker), err)
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
	// The VMM must be gone before its files are taken. Then the write is
	// done: the files are moved, not copied, so their space is counted.
	if err := d.host.KillCgroup(ctx, id); err != nil {
		return err
	}
	release()
	return d.storeSnapshot(spec, key, name, chrootDir, outDir)
}

// launchedDigest is the SHA-256 of file name in the open build jail chroot:
// the copy of the Firecracker binary the jailer made there and ran. The VMM
// owns the jail, so name is opened without following a symlink or waiting
// for a FIFO's writer, and must be a regular file.
func launchedDigest(chroot int, name string) (string, error) {
	fd, err := unix.Openat(chroot, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s in the build jail is not a regular file", name)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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
// chroot and out are the build jail's chroot and output directories, opened
// before the VMM started. The VMM wrote the files there as the build UID,
// which owns out; they are taken through those directories (takeVMMFile).
func (d *FirecrackerDriver) storeSnapshot(spec Spec, key fcSnapshotKey, name string, chroot, out int) error {
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
	to, err := unix.Open(tmp, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(to)
	var build unix.Stat_t
	if err := unix.Fstat(out, &build); err != nil {
		return err
	}
	for _, file := range []struct {
		dir      int
		from, to string
		mode     uint32
	}{
		{out, fcSnapshotState, fcSnapshotState, 0o444},
		{out, fcSnapshotMemory, fcSnapshotMemory, 0o444},
		{chroot, "home.ext4", fcSnapshotHome, 0o400},
	} {
		if err := d.takeVMMFile(file.dir, file.from, build.Uid, to, file.to, file.mode); err != nil {
			return fmt.Errorf("template snapshot file %s: %w", file.to, err)
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

// takeVMMFile moves the file name of directory dir, written by a VMM that
// ran as owner and has stopped, into directory to as as, root's with mode.
// No path is resolved: dir is an open directory, name is opened without
// following a symlink, and the move and the change of owner and mode are
// relative to the open directories. The file must be a regular file of
// owner with one link, so no other file on the host is ever taken, and the
// entry moved must be that file.
func (d *FirecrackerDriver) takeVMMFile(dir int, name string, owner uint32, to int, as string, mode uint32) error {
	fd, err := unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var file unix.Stat_t
	if err := unix.Fstat(fd, &file); err != nil {
		return err
	}
	if file.Mode&unix.S_IFMT != unix.S_IFREG || file.Nlink != 1 || file.Uid != owner {
		return fmt.Errorf("not a regular single-link file of the build VM (mode %#o, %d links, owner %d)", file.Mode, file.Nlink, file.Uid)
	}
	if err := unix.Renameat(dir, name, to, as); err != nil {
		return err
	}
	var moved unix.Stat_t
	if err := unix.Fstatat(to, as, &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if moved.Dev != file.Dev || moved.Ino != file.Ino {
		return errors.New("replaced while it was moved")
	}
	return errors.Join(d.host.ChownAt(to, as, 0, 0), unix.Fchmodat(to, as, mode, 0))
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
// interrupted build left. A current snapshot goes too once unused for its
// idle time (unusedSnapshot), when the next collection is due. Anything
// else in the directory is left alone.
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
	now := time.Now()
	var next time.Duration // until the first kept snapshot expires
	for _, entry := range names {
		base, suffix, _ := strings.Cut(entry, ".")
		if !fcSnapshotName.MatchString(base) {
			continue
		}
		var why string
		switch {
		case suffix == "tmp":
			if base != building {
				why = "an interrupted build left it"
			}
		case strings.HasPrefix(suffix, "retired-"):
			if refs[base] == 0 {
				why = "it was retired and no VM uses it"
			}
		case suffix == "" && refs[base] == 0:
			var keep time.Duration
			why, keep = d.unusedSnapshot(base, now)
			if keep > 0 && (next == 0 || keep < next) {
				next = keep
			}
		}
		if why == "" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(d.snapshotsDir(), entry)); err != nil {
			log.Printf("firecracker: remove template snapshot %s: %v", entry, err)
		} else {
			log.Printf("firecracker: template snapshot %s removed: %s", entry, why)
		}
	}
	s.mu.Lock()
	if s.sweep != nil {
		s.sweep.Stop()
		s.sweep = nil
	}
	if next > 0 && !s.stopped {
		s.sweep = time.AfterFunc(next, d.sweepSnapshots)
	}
	s.mu.Unlock()
}

// sweepSnapshots is the collection the sweep timer found due, unless the
// driver is stopped; stopBuilds awaits it (swept).
func (d *FirecrackerDriver) sweepSnapshots() {
	s := &d.snap
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	if s.sweeps == 0 {
		s.swept = make(chan struct{})
	}
	s.sweeps++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.sweeps--; s.sweeps == 0 {
			close(s.swept)
		}
		s.mu.Unlock()
	}()
	d.collectSnapshots()
}

// unusedSnapshot decides about stored snapshot name, which no VM uses: it is
// removed (why says why) when this driver would not restore it now, or when
// it was neither built nor restored from for fcSnapshotIdle (its shape is
// not the one this host serves) or fcSnapshotServedIdle (it is); it is
// otherwise kept, for keep more. A key that cannot be computed for a
// passing reason (the version check failed) keeps the snapshot until the
// next collection.
func (d *FirecrackerDriver) unusedSnapshot(name string, now time.Time) (why string, keep time.Duration) {
	const stale = "no VM uses it and none will"
	if !d.cfg.Snapshots {
		return stale, 0
	}
	dir := d.snapshotDir(name)
	meta, err := readSnapshotMeta(dir)
	if err != nil {
		return stale, 0
	}
	if _, ok := d.images[meta.Key.Image]; !ok {
		return stale, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key, err := d.snapshotKey(ctx, meta.spec())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return stale, 0
		}
		return "", 0
	}
	if key != meta.Key || key.name() != name {
		return stale, 0
	}
	limit, reason := fcSnapshotServedIdle, ""
	if meta.CPUs != d.cfg.CPUs || meta.MemoryMiB != d.cfg.MemoryMiB {
		limit, reason = fcSnapshotIdle, "this host serves another VM shape, and "
	}
	// The directory's time is its last use: the build, or a restore.
	info, err := os.Stat(dir)
	if err != nil {
		return "", 0
	}
	idle := max(now.Sub(info.ModTime()), 0)
	if idle >= limit {
		return fmt.Sprintf("%sno VM used it for %v", reason, limit), 0
	}
	return "", limit - idle
}
