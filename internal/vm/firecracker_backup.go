//go:build linux

package vm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// volumeTransfers is protected by volumeMu. A zero SizeMiB is a backup of an
// existing volume; a positive size reserves a new name and restore capacity.
// Reservations are process-local: the daemon's instance/ledger claim excludes
// other writers, and restart removes incomplete .ext4.tmp imports.
type fcVolumeTransfer struct {
	Name    string
	SizeMiB int
}

func (d *FirecrackerDriver) reserveVolumeTransfer(id string, transfer fcVolumeTransfer) error {
	if _, exists := d.volumeTransfers[id]; exists {
		return ErrVolumeTransferBusy
	}
	if len(d.volumeTransfers) >= MaxVolumeTransfers {
		return ErrVolumeTransferBusy
	}
	if d.volumeTransfers == nil {
		d.volumeTransfers = make(map[string]fcVolumeTransfer)
	}
	d.volumeTransfers[id] = transfer
	return nil
}

func (d *FirecrackerDriver) releaseVolumeTransfer(id string) {
	d.volumeMu.Lock()
	delete(d.volumeTransfers, id)
	d.volumeMu.Unlock()
}

// reservedVolumeMiB also rejects names reserved by an in-flight restore. Count
// full restore sizes against disk headroom conservatively, even if a stream has
// partially allocated its staging file; a slow import must never overcommit it.
func (d *FirecrackerDriver) reservedVolumeMiB(name string) (int, error) {
	reserved := 0
	for _, transfer := range d.volumeTransfers {
		if transfer.SizeMiB == 0 {
			continue
		}
		if transfer.Name == name {
			return 0, ErrVolumeExists
		}
		reserved += transfer.SizeMiB
	}
	return reserved, nil
}

func (d *FirecrackerDriver) OpenVolumeBackup(ctx context.Context, id string) (VolumeBackup, error) {
	if err := d.volumesOn(); err != nil {
		return VolumeBackup{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, VolumeTransferTimeout)
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	d.volumeMu.Lock()
	volume, err := d.readVolume(id)
	if err == nil {
		err = d.volumeInUse(id)
	}
	if err == nil {
		err = d.reserveVolumeTransfer(id, fcVolumeTransfer{})
	}
	d.volumeMu.Unlock()
	if err != nil {
		return VolumeBackup{}, err
	}
	defer func() {
		if !success {
			d.releaseVolumeTransfer(id)
		}
	}()
	fd, err := syscall.Open(d.volumeDisk(id), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return VolumeBackup{}, err
	}
	file := os.NewFile(uintptr(fd), "volume-backup")
	stop := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer func() {
		if !success {
			stop()
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return VolumeBackup{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	size := int64(volume.SizeMiB) << 20
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Size() != size {
		return VolumeBackup{}, errors.New("volume disk is not a detached native disk")
	}
	digest := sha256.New()
	if err := copyVolumeBytes(ctx, digest, file, size); err != nil {
		return VolumeBackup{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return VolumeBackup{}, err
	}
	manifest := VolumeManifest{SourceVolumeID: id, SizeBytes: size, SHA256: hex.EncodeToString(digest.Sum(nil)), ApplicationConsistency: "not-asserted"}
	if err := manifest.Validate(); err != nil {
		return VolumeBackup{}, err
	}
	if err := ctx.Err(); err != nil {
		return VolumeBackup{}, err
	}
	reader := &fcBackupReader{file: file, ctx: ctx, cancel: cancel, stop: stop, release: func() { d.releaseVolumeTransfer(id) }}
	success = true
	return VolumeBackup{Manifest: manifest, Data: reader}, nil
}

type fcBackupReader struct {
	file    *os.File
	ctx     context.Context
	cancel  context.CancelFunc
	stop    func() bool
	release func()
	once    sync.Once
	err     error
}

func (r *fcBackupReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.file.Read(p)
}
func (r *fcBackupReader) Close() error {
	r.once.Do(func() { r.stop(); r.cancel(); r.err = r.file.Close(); r.release() })
	return r.err
}

func (d *FirecrackerDriver) RestoreVolume(ctx context.Context, name string, m VolumeManifest, source io.Reader) (result Volume, runErr error) {
	if err := d.volumesOn(); err != nil {
		return Volume{}, err
	}
	if !ValidVolumeName(name) {
		return Volume{}, ErrVolumeBackupInvalid
	}
	if err := m.Validate(); err != nil {
		return Volume{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, VolumeTransferTimeout)
	defer cancel()
	d.volumeMu.Lock()
	volume, err := d.reserveRestore(ctx, name, int(m.SizeBytes>>20))
	d.volumeMu.Unlock()
	if err != nil {
		return Volume{}, err
	}
	defer d.releaseVolumeTransfer(volume.ID)
	path := d.volumeDisk(volume.ID)
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Volume{}, err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			runErr = errors.Join(runErr, fcRemoveMissing(tmp), fcSyncPath(d.cfg.VolumeDir))
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer stop()
	if err := file.Chmod(0o600); err != nil {
		return Volume{}, err
	}
	digest := sha256.New()
	sink := &volumeWriteError{Writer: file}
	if err := copyVolumeBytes(ctx, io.MultiWriter(sink, digest), source, m.SizeBytes); err != nil {
		if ctx.Err() != nil {
			return Volume{}, ctx.Err()
		}
		if sink.err != nil {
			return Volume{}, sink.err
		}
		return Volume{}, fmt.Errorf("%w: disk transfer: %v", ErrVolumeBackupInvalid, err)
	}
	// Exact envelope length is mandatory: no appended archive entries or bytes.
	var extra [1]byte
	n, err := io.ReadFull(source, extra[:])
	if ctx.Err() != nil {
		return Volume{}, ctx.Err()
	}
	if n != 0 || err != io.EOF || hex.EncodeToString(digest.Sum(nil)) != m.SHA256 {
		return Volume{}, ErrVolumeBackupInvalid
	}
	if err := file.Sync(); err != nil {
		return Volume{}, err
	}
	if err := file.Close(); err != nil {
		return Volume{}, err
	}
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return Volume{}, err
	}
	record, err := json.Marshal(volume)
	if err != nil {
		return Volume{}, err
	}
	// Record first and durable, disk last. Startup already removes a record with
	// no disk. Once a final disk is visible, its complete synced record exists.
	recordFile, err := os.OpenFile(d.volumeRecord(volume.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Volume{}, err
	}
	published := false
	defer func() {
		if !committed {
			if published {
				runErr = errors.Join(runErr, fcRemoveMissing(path))
			}
			runErr = errors.Join(runErr, fcRemoveMissing(d.volumeRecord(volume.ID)), fcSyncPath(d.cfg.VolumeDir))
		}
	}()
	recordErr := writeVolumeBytes(recordFile, record)
	if recordErr == nil {
		recordErr = recordFile.Sync()
	}
	recordErr = errors.Join(recordErr, recordFile.Close())
	if recordErr != nil {
		return Volume{}, recordErr
	}
	if err := fcSyncPath(d.cfg.VolumeDir); err != nil {
		return Volume{}, err
	}
	if err := ctx.Err(); err != nil {
		return Volume{}, err
	}
	if err := os.Link(tmp, path); err != nil {
		return Volume{}, err
	}
	published = true
	if err := os.Remove(tmp); err != nil {
		return Volume{}, err
	}
	if err := fcSyncPath(d.cfg.VolumeDir); err != nil {
		return Volume{}, err
	}
	committed = true
	return Volume{ID: volume.ID, Name: volume.Name, SizeMiB: volume.SizeMiB}, nil
}

// reserveRestore runs under volumeMu; no disk bytes are accepted until it wins.
func (d *FirecrackerDriver) reserveRestore(ctx context.Context, name string, size int) (fcVolume, error) {
	if err := ctx.Err(); err != nil {
		return fcVolume{}, err
	}
	if len(d.volumeTransfers) >= MaxVolumeTransfers {
		return fcVolume{}, ErrVolumeTransferBusy
	}
	reserved, err := d.reservedVolumeMiB(name)
	if err != nil {
		return fcVolume{}, err
	}
	volumes, err := d.readVolumes()
	if err != nil {
		return fcVolume{}, err
	}
	used := reserved
	for _, volume := range volumes {
		if volume.Name == name {
			return fcVolume{}, ErrVolumeExists
		}
		used += volume.SizeMiB
	}
	if used+size > d.cfg.VolumeBudgetMiB {
		return fcVolume{}, ErrVolumeBudget
	}
	free, err := d.host.FreeBytes(d.cfg.VolumeDir)
	if err != nil {
		return fcVolume{}, err
	}
	if free < uint64(d.cfg.DiskFloorMiB+size+reserved)<<20 {
		return fcVolume{}, ErrVolumeBudget
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fcVolume{}, err
	}
	volume := fcVolume{ID: "vol-" + hex.EncodeToString(random[:]), Name: name, SizeMiB: size}
	if err := d.reserveVolumeTransfer(volume.ID, fcVolumeTransfer{Name: name, SizeMiB: size}); err != nil {
		return fcVolume{}, err
	}
	return volume, nil
}

type volumeWriteError struct {
	io.Writer
	err error
}

func (w *volumeWriteError) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}
