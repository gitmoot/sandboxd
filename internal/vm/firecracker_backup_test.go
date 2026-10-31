//go:build linux

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func backupDriver(t *testing.T) (*FirecrackerDriver, *fakeFCHost, FirecrackerConfig) {
	t.Helper()
	return newTestFirecracker(t, func(c *FirecrackerConfig) {
		c.VolumeBudgetMiB = 256
		c.VolumeMiB = 64
		c.VolumeDir = filepath.Join(c.Root, "volumes")
	})
}

func TestFirecrackerColdBackupRoundTrip(t *testing.T) {
	d, _, cfg := backupDriver(t)
	ctx := context.Background()
	original, err := d.CreateVolume(ctx, "original")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(d.volumeDisk(original.ID), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("preserve raw data, including credential-bearing and deleted blocks\x00\xff")
	if _, err := file.WriteAt(marker, 12345); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	backup, err := d.OpenVolumeBackup(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Data.Close()
	if backup.Manifest.SourceVolumeID != original.ID || backup.Manifest.SizeBytes != 64<<20 || backup.Manifest.ApplicationConsistency != "not-asserted" {
		t.Fatalf("manifest=%+v", backup.Manifest)
	}
	// A held backup excludes actual guest attachment, deletion and another backup.
	if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx1", original.ID)); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("attach during backup: %v", err)
	}
	if err := d.DeleteVolume(ctx, original.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("delete during backup: %v", err)
	}
	if _, err := d.OpenVolumeBackup(ctx, original.ID); !errors.Is(err, ErrVolumeTransferBusy) {
		t.Fatalf("second backup: %v", err)
	}
	restored, err := d.RestoreVolume(ctx, "restored", backup.Manifest, backup.Data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID == original.ID || restored.Name != "restored" || restored.SizeMiB != 64 {
		t.Fatalf("restored identity=%+v", restored)
	}
	if err := backup.Data.Close(); err != nil {
		t.Fatal(err)
	}
	check, err := d.OpenVolumeBackup(ctx, restored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if check.Manifest.SHA256 != backup.Manifest.SHA256 {
		t.Fatalf("restored checksum differs: %s != %s", check.Manifest.SHA256, backup.Manifest.SHA256)
	}
	_ = check.Data.Close()
	restoredFile, err := os.Open(d.volumeDisk(restored.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredFile.Close()
	got := make([]byte, len(marker))
	_, err = restoredFile.ReadAt(got, 12345)
	if err != nil || !bytes.Equal(got, marker) {
		t.Fatalf("restored content: %q %v", got, err)
	}
	// Once the backup closes, the original can attach. Backup then rejects both
	// the running ownership record and, independently, a leftover jail hard link.
	if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx1", original.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenVolumeBackup(ctx, original.ID); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("attached backup: %v", err)
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cfg.Root, "held-disk")
	if err := os.Link(d.volumeDisk(original.ID), link); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenVolumeBackup(ctx, original.ID); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("hard-linked backup: %v", err)
	}
}

func TestFirecrackerRestoreFailureCleanup(t *testing.T) {
	d, _, cfg := backupDriver(t)
	ctx := context.Background()
	source, err := d.CreateVolume(ctx, "source")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := d.OpenVolumeBackup(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := backup.Manifest
	_ = backup.Data.Close()
	for _, kind := range []string{"truncated", "digest", "extra", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			sourceFile, err := os.Open(d.volumeDisk(source.ID))
			if err != nil {
				t.Fatal(err)
			}
			defer sourceFile.Close()
			var reader io.Reader = sourceFile
			m := manifest
			child, cancel := context.WithCancel(ctx)
			defer cancel()
			switch kind {
			case "truncated":
				reader = io.LimitReader(sourceFile, 1024)
			case "digest":
				m.SHA256 = strings.Repeat("f", 64)
			case "extra":
				reader = io.MultiReader(sourceFile, strings.NewReader("extra"))
			case "cancelled":
				reader = &cancelVolumeReader{Reader: sourceFile, cancel: cancel}
			}
			_, err = d.RestoreVolume(child, "failure", m, reader)
			if kind == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
			} else if !errors.Is(err, ErrVolumeBackupInvalid) {
				t.Fatalf("%s: %v", kind, err)
			}
			volumes, err := d.Volumes(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(volumes) != 1 || volumes[0].ID != source.ID {
				t.Fatalf("failed restore published volume: %+v", volumes)
			}
			names, err := os.ReadDir(cfg.VolumeDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				if name.Name() != source.ID+".json" && name.Name() != source.ID+".ext4" {
					t.Fatalf("failed restore left %s", name.Name())
				}
			}
		})
	}
	// Failed imports release the name and budget, and a subsequent valid import succeeds.
	sourceFile, err := os.Open(d.volumeDisk(source.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFile.Close()
	if _, err := d.RestoreVolume(ctx, "failure", manifest, sourceFile); err != nil {
		t.Fatal(err)
	}
}

type cancelVolumeReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *cancelVolumeReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}

type pausedVolumeReader struct {
	io.Reader
	entered chan struct{}
	resume  chan struct{}
	once    bool
}

func (r *pausedVolumeReader) Read(p []byte) (int, error) {
	if !r.once {
		r.once = true
		close(r.entered)
		<-r.resume
	}
	return r.Reader.Read(p)
}

func TestFirecrackerRestoreReservesQuotaAndName(t *testing.T) {
	d, _, _ := backupDriver(t)
	d.cfg.VolumeBudgetMiB = 128
	ctx := context.Background()
	source, err := d.CreateVolume(ctx, "source")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := d.OpenVolumeBackup(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := backup.Manifest
	_ = backup.Data.Close()
	sourceFile, err := os.Open(d.volumeDisk(source.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFile.Close()
	reader := &pausedVolumeReader{Reader: sourceFile, entered: make(chan struct{}), resume: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := d.RestoreVolume(ctx, "incoming", manifest, reader); result <- err }()
	<-reader.entered
	// The full reservation counts even while the transfer is paused outside volumeMu.
	_, sameName := d.CreateVolume(ctx, "incoming")
	_, overBudget := d.CreateVolume(ctx, "other")
	_, secondImport := d.RestoreVolume(ctx, "second", manifest, strings.NewReader(""))
	// A different existing volume can still be read/listed/removed without waiting.
	volumes, listErr := d.Volumes(ctx)
	deleteErr := d.DeleteVolume(ctx, source.ID)
	close(reader.resume)
	restoreErr := <-result
	if !errors.Is(sameName, ErrVolumeExists) || !errors.Is(overBudget, ErrVolumeBudget) || !errors.Is(secondImport, ErrVolumeBudget) {
		t.Fatalf("reservations: name=%v create=%v restore=%v", sameName, overBudget, secondImport)
	}
	if listErr != nil || len(volumes) != 1 || deleteErr != nil || restoreErr != nil {
		t.Fatalf("independent progress: list=%v delete=%v restore=%v", listErr, deleteErr, restoreErr)
	}
}

func TestVolumeBackupEnvelopeBounds(t *testing.T) {
	digest := sha256.Sum256([]byte("manifest only"))
	m := VolumeManifest{SourceVolumeID: "vol-" + strings.Repeat("a", 32), SizeBytes: 64 << 20, SHA256: hex.EncodeToString(digest[:]), ApplicationConsistency: "not-asserted"}
	var valid bytes.Buffer
	if err := WriteVolumeManifest(&valid, m); err != nil {
		t.Fatal(err)
	}
	raw := valid.Bytes()
	for _, kind := range []string{"version", "oversize", "truncated", "metadata", "size"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte(nil), raw...)
			switch kind {
			case "version":
				data[7] = '2'
			case "oversize":
				data[8] = 1
			case "truncated":
				data = data[:len(data)-1]
			case "metadata":
				data = bytes.Replace(data, []byte("not-asserted"), []byte("app-verified"), 1)
			case "size":
				data = bytes.Replace(data, []byte("67108864"), []byte("67108865"), 1)
			}
			if _, err := ReadVolumeManifest(bytes.NewReader(data)); !errors.Is(err, ErrVolumeBackupInvalid) {
				t.Fatalf("%s accepted: %v", kind, err)
			}
		})
	}
}
