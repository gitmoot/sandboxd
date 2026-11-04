//go:build linux

package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func volumeDiskSize(t *testing.T, cfg FirecrackerConfig, id string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(cfg.VolumeDir, id+".ext4"))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestFirecrackerVolumeGrow(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(cfg.VolumeDir, volume.ID+".ext4")

	grown, err := d.ResizeVolume(ctx, volume.ID, 192)
	if err != nil || grown.SizeMiB != 192 || grown.ID != volume.ID || grown.Name != "data" {
		t.Fatalf("grow = %+v %v", grown, err)
	}
	// The host tools saw the already-extended file, and the record agrees.
	if want := fcE2fsck[0] + " " + fcResize2fs[0] + " " + disk + " " + "201326592"; len(host.resized) != 1 || host.resized[0] != want {
		t.Fatalf("resized = %v, want %q", host.resized, want)
	}
	if got := volumeDiskSize(t, cfg, volume.ID); got != 192<<20 {
		t.Fatalf("disk size = %d", got)
	}
	volumes, err := d.Volumes(ctx)
	if err != nil || len(volumes) != 1 || volumes[0].SizeMiB != 192 {
		t.Fatalf("volumes = %+v %v", volumes, err)
	}
	// The grown size counts against the budget (256 MiB): 64 MiB are left.
	if _, err := d.CreateVolume(ctx, "other"); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("create after grow: %v", err)
	}
	// The same size again does nothing.
	if again, err := d.ResizeVolume(ctx, volume.ID, 192); err != nil || again.SizeMiB != 192 || len(host.resized) != 1 {
		t.Fatalf("repeat = %+v %v calls=%v", again, err, host.resized)
	}
	// No stray record temp file is left behind.
	if _, err := os.Stat(filepath.Join(cfg.VolumeDir, volume.ID+".json.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record temp file remains: %v", err)
	}
}

func TestFirecrackerVolumeGrowRefusals(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		id   string
		size int
		want error
	}{
		"shrink":       {volume.ID, 64, ErrVolumeSize},
		"too small":    {volume.ID, 63, ErrVolumeSize},
		"too large":    {volume.ID, 1<<20 + 1, ErrVolumeSize},
		"over budget":  {volume.ID, 300, ErrVolumeBudget},
		"unknown":      {"vol-" + strings.Repeat("e", 32), 192, ErrVolumeNotFound},
		"malformed id": {"../data", 192, ErrVolumeNotFound},
	} {
		if _, err := d.ResizeVolume(ctx, test.id, test.size); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v, want %v", name, err, test.want)
		}
	}
	// The host disk floor counts too.
	host.free = uint64(cfg.DiskFloorMiB+63) << 20
	if _, err := d.ResizeVolume(ctx, volume.ID, 192); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("below floor: %v", err)
	}
	host.free = 100 << 30
	// An untrusted e2fsck or resize2fs stops the grow before the file moves.
	for _, tool := range []string{fcE2fsck[0], fcResize2fs[0]} {
		host.untrusted = map[string]bool{tool: true, fcE2fsck[1]: true, fcResize2fs[1]: true}
		if _, err := d.ResizeVolume(ctx, volume.ID, 192); err == nil || !strings.Contains(err.Error(), "trusted host tool") {
			t.Fatalf("untrusted %s: %v", tool, err)
		}
	}
	host.untrusted = nil
	if len(host.resized) != 0 || volumeDiskSize(t, cfg, volume.ID) != 128<<20 {
		t.Fatalf("a refused grow changed the volume: calls=%v size=%d", host.resized, volumeDiskSize(t, cfg, volume.ID))
	}
	// An attached volume cannot grow.
	if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx1", volume.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ResizeVolume(ctx, volume.ID, 192); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("attached: %v", err)
	}
	if len(host.resized) != 0 || volumeDiskSize(t, cfg, volume.ID) != 128<<20 {
		t.Fatal("an attached volume was changed")
	}
}

// A filesystem that fails its check is not resized, and its file goes back to
// the recorded size, so the volume is exactly as before.
func TestFirecrackerVolumeGrowFsckFailureRestoresDisk(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	host.resizeErr = fmt.Errorf("%w: exit status 4", errVolumeFsck)
	if _, err := d.ResizeVolume(ctx, volume.ID, 192); !errors.Is(err, errVolumeFsck) {
		t.Fatalf("grow of a damaged filesystem: %v", err)
	}
	if got := volumeDiskSize(t, cfg, volume.ID); got != 128<<20 {
		t.Fatalf("disk size after a failed check = %d", got)
	}
	host.resizeErr = nil
	if grown, err := d.ResizeVolume(ctx, volume.ID, 192); err != nil || grown.SizeMiB != 192 {
		t.Fatalf("grow after the failed check = %+v %v", grown, err)
	}
}

// A failed filesystem step leaves the disk file larger than its record. The
// same grow then completes, since each step can be repeated.
func TestFirecrackerVolumeGrowRetryAfterFailure(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	host.resizeErr = errors.New("e2fsck: errors left uncorrected")
	if _, err := d.ResizeVolume(ctx, volume.ID, 192); err == nil {
		t.Fatal("failed resize reported success")
	}
	if volumes, _ := d.Volumes(ctx); len(volumes) != 1 || volumes[0].SizeMiB != 128 {
		t.Fatalf("record changed by a failed grow: %+v", volumes)
	}
	if got := volumeDiskSize(t, cfg, volume.ID); got != 192<<20 {
		t.Fatalf("disk size after failure = %d", got)
	}
	// The failed grow released its reservation: the volume can be deleted or retried.
	host.resizeErr = nil
	grown, err := d.ResizeVolume(ctx, volume.ID, 192)
	if err != nil || grown.SizeMiB != 192 {
		t.Fatalf("retry = %+v %v", grown, err)
	}
	// A disk already larger than the request is not cut down.
	if err := os.Truncate(filepath.Join(cfg.VolumeDir, volume.ID+".ext4"), 250<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ResizeVolume(ctx, volume.ID, 224); !errors.Is(err, ErrVolumeSize) {
		t.Fatalf("oversized disk: %v", err)
	}
}

// While e2fsck and resize2fs run, the volume is held: it cannot be attached,
// deleted or backed up, and the growth counts against the budget.
func TestFirecrackerVolumeGrowHoldsVolume(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	host.resizeGate = gate
	done := make(chan error, 1)
	go func() { _, err := d.ResizeVolume(ctx, volume.ID, 192); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		host.mu.Lock()
		started := len(host.resized) == 1
		host.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resize did not reach the host")
		}
		time.Sleep(time.Millisecond)
	}
	if err := d.DeleteVolume(ctx, volume.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("delete during grow: %v", err)
	}
	if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx1", volume.ID)); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("attach during grow: %v", err)
	}
	if _, err := d.OpenVolumeBackup(ctx, volume.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("backup during grow: %v", err)
	}
	if _, err := d.ResizeVolume(ctx, volume.ID, 224); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("second grow: %v", err)
	}
	if _, err := d.CreateVolume(ctx, "other"); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("create during grow: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); err != nil {
		t.Fatalf("delete after grow: %v", err)
	}
}

// A grow whose record could not be published leaves an enlarged disk. It keeps
// counting against the budget (also after a restart, which re-reads the disk),
// so a create cannot admit more disk than the budget allows.
func TestFirecrackerVolumeGrowFailedRecordKeepsBudget(t *testing.T) {
	d, _, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	// A directory where the record's temp file goes makes publication fail.
	block := filepath.Join(cfg.VolumeDir, volume.ID+".json.tmp")
	if err := os.Mkdir(block, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ResizeVolume(ctx, volume.ID, 192); err == nil {
		t.Fatal("grow reported success although its record was not written")
	}
	if got := volumeDiskSize(t, cfg, volume.ID); got != 192<<20 {
		t.Fatalf("disk size = %d", got)
	}
	// Budget 256 MiB: the 192 MiB disk leaves room for no second 128 MiB volume.
	if _, err := d.CreateVolume(ctx, "other"); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("create next to an unrecorded 192 MiB disk: %v", err)
	}
	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	// The same request finishes the grow, without counting the extension twice.
	if grown, err := d.ResizeVolume(ctx, volume.ID, 192); err != nil || grown.SizeMiB != 192 {
		t.Fatalf("retry = %+v %v", grown, err)
	}
}

func lockedByAnother(t *testing.T, path string) bool {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		return false
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal(err)
	}
	return true
}

// The fence is the disk's flock, not process memory: with the in-memory
// reservation gone (a restarted daemon has none), a disk a tool still holds
// cannot be attached, deleted, backed up or grown.
func TestFirecrackerVolumeGrowFencedByDiskLock(t *testing.T) {
	d, host, cfg := newVolumeFirecracker(t)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(cfg.VolumeDir, volume.ID+".ext4")
	gate := make(chan struct{})
	host.resizeGate = gate
	done := make(chan error, 1)
	go func() { _, err := d.ResizeVolume(ctx, volume.ID, 192); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for !lockedByAnother(t, disk) {
		if time.Now().After(deadline) {
			t.Fatal("the disk was not locked while the tools ran")
		}
		time.Sleep(time.Millisecond)
	}
	d.volumeMu.Lock()
	clear(d.volumeTransfers)
	d.volumeMu.Unlock()
	if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx1", volume.ID)); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("attach with the tools running: %v", err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("delete with the tools running: %v", err)
	}
	if _, err := d.OpenVolumeBackup(ctx, volume.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("backup with the tools running: %v", err)
	}
	if _, err := d.ResizeVolume(ctx, volume.ID, 224); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("second grow with the tools running: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if lockedByAnother(t, disk) {
		t.Fatal("the disk is still locked after the grow")
	}
}

// The real host passes the locked file to e2fsck and resize2fs. The tool keeps
// working after the daemon's own descriptor is closed, which is what a daemon
// killed mid-grow leaves behind: here resize2fs leaves a child that still runs
// after the call returned and the daemon's descriptor was closed.
func TestLinuxHostResizeToolsKeepDiskLocked(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "v.ext4")
	if err := os.WriteFile(disk, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	fsck := script("e2fsck", "exit 0\n")
	resize := script("resize2fs", "sleep 1 </dev/null >/dev/null 2>&1 &\nexit 0\n")

	lock, err := os.OpenFile(disk, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := (&linuxFCHost{}).ResizeVolume(context.Background(), fsck, resize, disk, lock); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if !lockedByAnother(t, disk) {
		t.Fatal("the disk was not locked by the tool after the daemon's descriptor closed")
	}
	deadline := time.Now().Add(10 * time.Second)
	for lockedByAnother(t, disk) {
		if time.Now().After(deadline) {
			t.Fatal("the disk stayed locked after the tool exited")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// While a grow runs, the budget charges the volume's growth once. The extended
// disk file and the reserved growth must not both count: a create that fits
// next to the grown volume is admitted, one that does not is refused.
func TestFirecrackerVolumeGrowInFlightChargedOnce(t *testing.T) {
	d, host, _ := newTestFirecracker(t, func(c *FirecrackerConfig) {
		c.VolumeBudgetMiB, c.VolumeMiB, c.VolumeDir = 320, 128, filepath.Join(c.Root, "volumes")
	})
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	host.resizeGate = gate
	done := make(chan error, 1)
	go func() { _, err := d.ResizeVolume(ctx, volume.ID, 192); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		host.mu.Lock()
		started := len(host.resized) == 1
		host.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resize did not reach the host")
		}
		time.Sleep(time.Millisecond)
	}
	// 192 MiB growing + 128 MiB new = the 320 MiB budget exactly.
	if _, err := d.CreateVolume(ctx, "next"); err != nil {
		t.Fatalf("a volume that fits next to the growing one was refused: %v", err)
	}
	if _, err := d.CreateVolume(ctx, "over"); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("create past the budget during a grow: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Extending the disk file is sparse: the space is only used while the tools
// run. The host disk floor therefore keeps holding the grow's whole growth
// back until the grow ends, also after the file reached its new size.
func TestFirecrackerVolumeGrowKeepsDiskHeadroom(t *testing.T) {
	d, host, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) {
		c.VolumeBudgetMiB, c.VolumeMiB, c.VolumeDir = 1024, 128, filepath.Join(c.Root, "volumes")
	})
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	host.resizeGate = gate
	done := make(chan error, 1)
	go func() { _, err := d.ResizeVolume(ctx, volume.ID, 192); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		host.mu.Lock()
		started := len(host.resized) == 1
		host.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resize did not reach the host")
		}
		time.Sleep(time.Millisecond)
	}
	// The file is already 192 MiB, but 64 MiB of it is still unallocated: free
	// space for the floor plus a new 128 MiB volume is not enough with it.
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+128+63) << 20
	host.mu.Unlock()
	if _, err := d.CreateVolume(ctx, "next"); !errors.Is(err, ErrVolumeBudget) {
		t.Fatalf("a create that would eat the grow's headroom: %v", err)
	}
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+128+64) << 20
	host.mu.Unlock()
	if _, err := d.CreateVolume(ctx, "next"); err != nil {
		t.Fatalf("a create that leaves the grow's headroom: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
