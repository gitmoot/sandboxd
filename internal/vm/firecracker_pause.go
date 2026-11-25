//go:build linux

package vm

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/guestagent"
	"golang.org/x/sys/unix"
)

// A paused Firecracker VM is a full snapshot of its guest (VM state and
// memory, in <chroot>/paused) beside its kept disks, in its kept jail, with
// its record marked Paused. Nothing of it runs: its VMM, network stack and
// namespace are gone, so it holds no host RAM, process or namespace and
// survives a daemon restart (CleanupGuests and Disarm keep it). It keeps its
// slot. Resume starts a VMM in the same jail on a namespace rebuilt with the
// same names, addresses and egress policy, loads the snapshot and
// personalises the guest as a template clone is (fresh entropy, the host
// clock), so it never shares random state with an earlier run of itself.
// The loaded memory file stays mapped by the new VMM; its name is unlinked
// once the guest runs, so the disk it takes is returned when the VMM exits.

const (
	fcPausedJail   = "/paused"
	fcPausedState  = fcPausedJail + "/" + fcSnapshotState
	fcPausedMemory = fcPausedJail + "/" + fcSnapshotMemory
	// fcPauseAPITime bounds each Firecracker API request of a pause, and
	// the undo of a failed one.
	fcPauseAPITime = 30 * time.Second
)

var _ Pauser = (*FirecrackerDriver)(nil)

// paused reports a VM Pause left whole: its record says so and only its jail
// remains on the host.
func (vm fcVM) paused() bool {
	return vm.meta != nil && vm.meta.Paused && vm.jail && !vm.vmm && !vm.network && !vm.netns
}

// Pause flushes running VM id's disks, pauses it, snapshots it into its jail
// and stops its VMM and network stack. Only a VM started with an API socket
// (every VM started since pause support) whose guest agent can be restored
// can be paused. On error before the snapshot is complete the guest is
// resumed and what the snapshot wrote is discarded; after that it is left
// for Destroy. The guest's memory is reserved under Root above the disk
// floor from admission until the snapshot is written or discarded, so
// concurrent pauses never promise the same space.
func (d *FirecrackerDriver) Pause(ctx context.Context, id string) error {
	if err := validAppleID(id); err != nil {
		return err
	}
	vm, found, err := d.lookup(id)
	if err != nil {
		return err
	}
	if !found || !vm.running() {
		return fmt.Errorf("Firecracker VM %q: %w", id, ErrNotRunning)
	}
	meta := *vm.meta
	if err := d.checkPausable(ctx, meta); err != nil {
		return err
	}
	// The running VMM owns its chroot and can replace anything in it: the
	// paused directory is created and handed to it only through the open
	// chroot, never through a path it could turn into a symlink.
	chroot, err := unix.Open(d.chroot(id), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the jail of %q: %w", id, err)
	}
	defer unix.Close(chroot)
	// What an earlier pause left (the emptied directory of a resumed VM, or
	// output a failed discard kept) goes before the free space is measured.
	if err := os.RemoveAll(filepath.Join(d.chroot(id), fcPausedJail)); err != nil {
		return err
	}
	release, err := d.reservePause(meta.MemoryMiB)
	if err != nil {
		return err
	}
	defer release()
	name := filepath.Base(fcPausedJail)
	if err := unix.Mkdirat(chroot, name, 0o700); err != nil {
		return fmt.Errorf("create the paused directory of %q: %w", id, err)
	}
	if err := d.host.ChownAt(chroot, name, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	conn, err := d.dialAgentAs(ctx, id, meta.VMMUID)
	if err != nil {
		return err
	}
	err = guestagent.Sync(ctx, conn)
	_ = conn.Close()
	if err != nil {
		return fmt.Errorf("flush the guest's disks: %w", err)
	}
	if err := d.snapshotPaused(ctx, meta); err != nil {
		return err
	}
	// The VMM must be gone before the files are complete for a resume. If
	// it cannot be stopped, neither can the paused guest run on: its network
	// goes, leaving it for Destroy.
	if err := d.host.KillCgroup(ctx, id); err != nil {
		return errors.Join(err, d.stopNetwork(context.WithoutCancel(ctx), id))
	}
	template, err := d.markPaused(id, true)
	if err != nil {
		return fmt.Errorf("record the pause of %q: %w", id, err)
	}
	if err := d.stopNetwork(ctx, id); err != nil {
		return err
	}
	// The snapshot replaces the template a clone was restored from.
	if template != "" {
		if err := os.RemoveAll(filepath.Join(d.chroot(id), fcSnapshotJail)); err != nil {
			log.Printf("firecracker: remove template snapshot links of paused %s: %v", id, err)
		}
		d.collectSnapshots()
	}
	return nil
}

// checkPausable confirms VM meta has an API socket and a guest agent that
// can be restored from a snapshot.
func (d *FirecrackerDriver) checkPausable(ctx context.Context, meta fcMeta) error {
	api, err := d.host.DialAPI(ctx, d.chroot(meta.ID), meta.VMMUID)
	if err != nil {
		return fmt.Errorf("Firecracker VM %q has no API socket (started before pause support): %w", meta.ID, err)
	}
	_ = api.Close()
	conn, err := d.dialAgentAs(ctx, meta.ID, meta.VMMUID)
	if err != nil {
		return err
	}
	features, err := guestagent.Ping(ctx, conn)
	_ = conn.Close()
	if err != nil {
		return err
	}
	if !slices.Contains(features, guestagent.FeatureRestore) {
		return fmt.Errorf("%w: the guest agent of %s cannot be restored from a snapshot", ErrImageTooOld, meta.Image)
	}
	return nil
}

// reservePause reserves memoryMiB, the memory file of a pause snapshot,
// under Root above the disk floor and the space earlier pauses reserved.
// release returns it once the snapshot is written (and so counted in the
// free space) or discarded.
func (d *FirecrackerDriver) reservePause(memoryMiB int) (release func(), err error) {
	d.pausingMu.Lock()
	defer d.pausingMu.Unlock()
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return nil, err
	}
	need := uint64(memoryMiB) << 20
	if floor := uint64(d.cfg.DiskFloorMiB)<<20 + d.pausing; free < floor+need {
		return nil, fmt.Errorf("%w: %d MiB free, %d MiB floor and %d MiB of pauses in progress plus %d MiB guest memory needed",
			ErrDiskFloor, free>>20, d.cfg.DiskFloorMiB, d.pausing>>20, memoryMiB)
	}
	d.pausing += need
	return sync.OnceFunc(func() {
		d.pausingMu.Lock()
		d.pausing -= need
		d.pausingMu.Unlock()
	}), nil
}

// rootFree is the free space under Root less what pauses in progress have
// reserved (reservePause) but not yet written.
func (d *FirecrackerDriver) rootFree() (uint64, error) {
	d.pausingMu.Lock()
	defer d.pausingMu.Unlock()
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return 0, err
	}
	return free - min(free, d.pausing), nil
}

// snapshotPaused pauses VM meta's guest and writes its full snapshot to the
// jail's paused directory. If the snapshot fails the guest is resumed, or,
// if that fails too, its VMM is stopped; once the VMM can no longer write
// there, what it wrote is discarded.
func (d *FirecrackerDriver) snapshotPaused(ctx context.Context, meta fcMeta) error {
	call := func(ctx context.Context, method, path string, body any) error {
		ctx, cancel := context.WithTimeout(ctx, fcPauseAPITime)
		defer cancel()
		return d.callAPI(ctx, meta.ID, meta.VMMUID, method, path, body)
	}
	err := call(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"})
	if err == nil {
		err = call(ctx, http.MethodPut, "/snapshot/create", map[string]string{
			"snapshot_type": "Full",
			"snapshot_path": fcPausedState,
			"mem_file_path": fcPausedMemory,
		})
	}
	if err == nil {
		return nil
	}
	// The VMM answers one API request at a time: once it has answered the
	// resume, the snapshot request is over.
	undo := context.WithoutCancel(ctx)
	if resumeErr := call(undo, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"}); resumeErr != nil {
		stopErr := d.host.KillCgroup(undo, meta.ID)
		err = errors.Join(err, resumeErr, stopErr)
		if stopErr != nil {
			return fmt.Errorf("snapshot Firecracker VM %q: %w", meta.ID, err)
		}
	}
	if discardErr := os.RemoveAll(filepath.Join(d.chroot(meta.ID), fcPausedJail)); discardErr != nil {
		err = errors.Join(err, fmt.Errorf("discard the failed snapshot: %w", discardErr))
	}
	return fmt.Errorf("snapshot Firecracker VM %q: %w", meta.ID, err)
}

// markPaused rewrites VM id's record as paused or running. Pausing also
// drops the record's template snapshot (returned): the pause snapshot
// replaces it. The record is read again under egressMu, so an egress update
// that finished meanwhile is kept.
func (d *FirecrackerDriver) markPaused(id string, paused bool) (string, error) {
	d.egressMu.Lock()
	defer d.egressMu.Unlock()
	meta, err := d.readMeta(id)
	if err != nil {
		return "", err
	}
	if meta == nil {
		return "", fmt.Errorf("Firecracker VM %q has no valid ownership record", id)
	}
	template := ""
	if paused {
		template, meta.Snapshot = meta.Snapshot, ""
	}
	meta.Paused = paused
	return template, d.rewriteRecord(*meta)
}

// stopNetwork stops VM id's network stack and deletes its namespace (and
// with it the tap).
func (d *FirecrackerDriver) stopNetwork(ctx context.Context, id string) error {
	if err := d.host.KillCgroup(ctx, fcNetCgroup+id); err != nil {
		return err
	}
	return d.host.DeleteNetns(ctx, d.names.netnsPrefix+id)
}

// Resume starts paused VM id from its snapshot, in its jail on a rebuilt
// network, personalises it and confirms it runs behind the armed firewall;
// only then is its record marked running and its snapshot unlinked. On any
// error its VMM and network stack are stopped again and it stays paused,
// snapshot and record intact.
func (d *FirecrackerDriver) Resume(ctx context.Context, id string) error {
	if err := validAppleID(id); err != nil {
		return err
	}
	if err := d.Ready(ctx); err != nil {
		return fmt.Errorf("firewall is not armed before guest resume: %w", err)
	}
	vm, found, err := d.lookup(id)
	if err != nil {
		return err
	}
	if !found || !vm.paused() {
		return fmt.Errorf("Firecracker VM %q: %w", id, ErrNotPaused)
	}
	meta := *vm.meta
	if err := d.checkMemoryFloor(); err != nil {
		return err
	}
	if err := d.clearJailerTraces(id); err != nil {
		return err
	}
	startup := &fcStartup{}
	recording := false
	err = d.launch(ctx, Spec{ID: id, Envd: meta.Envd}, meta, startup, "--api-sock", fcAPIPath)
	if err == nil {
		err = d.loadPaused(ctx, meta)
	}
	if err == nil {
		err = d.confirmStarted(ctx, id)
	}
	if err == nil {
		recording = true
		if _, err = d.markPaused(id, false); err != nil {
			err = fmt.Errorf("record the resume: %w", err)
		}
	}
	if err == nil {
		// Mapped by the VMM: unlinking returns the disk when it exits.
		for _, name := range []string{fcPausedState, fcPausedMemory} {
			if err := fcRemoveMissing(filepath.Join(d.chroot(id), name)); err != nil {
				log.Printf("firecracker: remove the loaded snapshot of resumed %s: %v", id, err)
			}
		}
		return nil
	}
	if d.cfg.ConsoleLog {
		startup.readFile(d.consoleLogPath(id))
	}
	undo, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	stopErr := d.host.KillCgroup(undo, id)
	if stopErr == nil {
		stopErr = d.stopNetwork(undo, id)
	}
	if recording {
		// A record write that failed after its rename left it running.
		if _, markErr := d.markPaused(id, true); markErr != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("record %q paused again: %w", id, markErr))
		}
	}
	return startup.annotate(errors.Join(fmt.Errorf("resume Firecracker VM %q: %w", id, err), stopErr))
}

// loadPaused loads VM meta's pause snapshot into its fresh VMM, resuming
// the guest, and personalises it.
func (d *FirecrackerDriver) loadPaused(ctx context.Context, meta fcMeta) error {
	ctx, cancel := context.WithTimeout(ctx, fcPauseAPITime)
	defer cancel()
	if err := d.waitAPI(ctx, meta.ID, meta.VMMUID); err != nil {
		return err
	}
	if err := d.callAPI(ctx, meta.ID, meta.VMMUID, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": fcPausedState,
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": fcPausedMemory},
		"resume_vm":     true,
	}); err != nil {
		return err
	}
	return d.personalise(ctx, meta.ID, meta.VMMUID)
}

// clearJailerTraces removes what an earlier jailer run and its VMM left in
// VM id's chroot (device nodes, the VMM binary copy and its PID file, the
// sockets), so the jailer can run in it again.
func (d *FirecrackerDriver) clearJailerTraces(id string) error {
	root := d.chroot(id)
	if err := os.RemoveAll(filepath.Join(root, "dev")); err != nil {
		return err
	}
	binary := filepath.Base(d.cfg.Firecracker)
	for _, name := range []string{binary, binary + ".pid", fcVsockPath, fcAPIPath} {
		if err := fcRemoveMissing(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	return nil
}
