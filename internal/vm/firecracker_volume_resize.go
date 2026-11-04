//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fcE2fsck and fcResize2fs are the host e2fsprogs candidates for a grow. They
// are resolved when a grow runs, not at startup, so a worker that never grows
// a volume needs nothing beyond mke2fs.
var (
	fcE2fsck    = []string{"/usr/sbin/e2fsck", "/sbin/e2fsck"}
	fcResize2fs = []string{"/usr/sbin/resize2fs", "/sbin/resize2fs"}
)

// errVolumeFsck marks a host ResizeVolume that stopped at e2fsck: the
// filesystem was not resized, so the disk file can go back to its old size.
var errVolumeFsck = errors.New("volume filesystem check failed")

func (d *FirecrackerDriver) trustedTool(candidates []string) (string, error) {
	var untrusted error
	for _, tool := range candidates {
		err := d.host.TrustedFile(tool, true)
		if err == nil {
			return tool, nil
		}
		untrusted = errors.Join(untrusted, err)
	}
	return "", fmt.Errorf("Firecracker volume grow needs a trusted host tool: %w", untrusted)
}

// ResizeVolume grows a detached volume to sizeMiB. The volume stays reserved
// (no attach, delete or backup) from the budget check until the new size is
// recorded. Order: extend the disk file, e2fsck -f -p, resize2fs, then replace
// the record. A failed e2fsck puts the file back. A crash, or a failed
// resize2fs, leaves a disk larger than its record; the same grow can be
// retried, because each step is idempotent and a disk larger than the request
// is refused. The host tools read a
// filesystem the guest wrote; nothing is mounted.
func (d *FirecrackerDriver) ResizeVolume(ctx context.Context, id string, sizeMiB int) (Volume, error) {
	if err := d.volumesOn(); err != nil {
		return Volume{}, err
	}
	if sizeMiB < 64 || sizeMiB > 1<<20 {
		return Volume{}, fmt.Errorf("%w: %d MiB is outside 64 MiB to 1 TiB", ErrVolumeSize, sizeMiB)
	}
	ctx, cancel := context.WithTimeout(ctx, VolumeTransferTimeout)
	defer cancel()

	d.volumeMu.Lock()
	volume, err := d.readVolume(id)
	if err == nil {
		err = d.volumeInUse(id)
	}
	switch {
	case err != nil:
	case sizeMiB == volume.SizeMiB:
		d.volumeMu.Unlock()
		return Volume{ID: volume.ID, Name: volume.Name, SizeMiB: volume.SizeMiB}, nil
	case sizeMiB < volume.SizeMiB:
		err = fmt.Errorf("%w: a volume cannot shrink from %d to %d MiB", ErrVolumeSize, volume.SizeMiB, sizeMiB)
	}
	var e2fsck, resize2fs string
	if err == nil {
		if e2fsck, err = d.trustedTool(fcE2fsck); err == nil {
			resize2fs, err = d.trustedTool(fcResize2fs)
		}
	}
	growth := sizeMiB - volume.SizeMiB
	if err == nil {
		err = d.reserveGrowth(volume, growth)
	}
	d.volumeMu.Unlock()
	if err != nil {
		return Volume{}, err
	}
	defer d.releaseVolumeTransfer(id)

	if err := d.growDisk(ctx, id, volume.SizeMiB, sizeMiB, e2fsck, resize2fs); err != nil {
		return Volume{}, err
	}
	volume.SizeMiB = sizeMiB
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	if err := d.replaceVolumeRecord(volume); err != nil {
		return Volume{}, err
	}
	return Volume{ID: volume.ID, Name: volume.Name, SizeMiB: volume.SizeMiB}, nil
}

// reserveGrowth checks the volume budget and the host disk floor for growth
// MiB more, then reserves it like an in-flight restore, so a concurrent create
// counts it. Callers hold volumeMu.
func (d *FirecrackerDriver) reserveGrowth(volume fcVolume, growth int) error {
	volumes, err := d.readVolumes()
	if err != nil {
		return err
	}
	reserved, err := d.reservedVolumeMiB(volume.Name)
	if err != nil {
		return err
	}
	used := reserved
	for _, existing := range volumes {
		used += existing.SizeMiB
	}
	if used+growth > d.cfg.VolumeBudgetMiB {
		return fmt.Errorf("%w: %d of %d MiB used, growing %s takes %d MiB more", ErrVolumeBudget, used, d.cfg.VolumeBudgetMiB, volume.ID, growth)
	}
	free, err := d.host.FreeBytes(d.cfg.VolumeDir)
	if err != nil {
		return err
	}
	if need := uint64(d.cfg.DiskFloorMiB+growth+reserved) << 20; free < need {
		return fmt.Errorf("%w: %d MiB free, %d MiB floor plus %d MiB growth needed", ErrVolumeBudget, free>>20, d.cfg.DiskFloorMiB, growth)
	}
	return d.reserveVolumeTransfer(volume.ID, fcVolumeTransfer{Name: volume.Name, SizeMiB: growth})
}

// growDisk extends the detached disk file and its filesystem. A disk larger
// than the target is not a state this grow made: it is refused, not cut.
func (d *FirecrackerDriver) growDisk(ctx context.Context, id string, oldMiB, newMiB int, e2fsck, resize2fs string) error {
	fd, err := syscall.Open(d.volumeDisk(id), syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "volume-grow")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("volume disk is not a detached native disk")
	}
	size, target := int64(oldMiB)<<20, int64(newMiB)<<20
	if info.Size() < size || info.Size() > target {
		return fmt.Errorf("%w: disk is %d bytes, expected %d to %d", ErrVolumeSize, info.Size(), size, target)
	}
	extended := info.Size() < target
	if extended {
		if err := file.Truncate(target); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	err = d.host.ResizeVolume(ctx, e2fsck, resize2fs, d.volumeDisk(id))
	if errors.Is(err, errVolumeFsck) && extended {
		// Nothing was resized: put the file back, so the volume still matches
		// its record and can be backed up or attached.
		err = errors.Join(err, file.Truncate(info.Size()), file.Sync())
	}
	return err
}

// replaceVolumeRecord swaps the record in with a rename, so a reader or a
// crash sees the old size or the new one, never a partial record. Callers
// hold volumeMu.
func (d *FirecrackerDriver) replaceVolumeRecord(volume fcVolume) error {
	data, err := json.Marshal(volume)
	if err != nil {
		return err
	}
	record := d.volumeRecord(volume.ID)
	tmp := record + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err == nil {
		err = os.Rename(tmp, record)
	}
	if err != nil {
		return errors.Join(err, fcRemoveMissing(tmp))
	}
	return fcSyncPath(d.cfg.VolumeDir)
}
