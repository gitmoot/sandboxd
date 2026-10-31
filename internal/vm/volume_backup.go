package vm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	VolumeBackupMediaType = "application/vnd.sandboxd.volume-backup"
	VolumeTransferTimeout = 10 * time.Minute
	MaxVolumeTransfers    = 2
	volumeBackupMagic     = "SBXVOL01"
	maxVolumeManifest     = 4096
	volumeTransferBuffer  = 64 << 10
)

var (
	ErrVolumeTransferBusy  = errors.New("volume storage operation in progress")
	ErrVolumeBackupInvalid = errors.New("invalid volume backup")
)

// VolumeManifest describes raw, credential-bearing block data, including deleted
// blocks. Its hash detects corruption, not authenticity. No application-consistency
// guarantee follows from a detached disk or the guest's best-effort flush.
type VolumeManifest struct {
	SourceVolumeID         string `json:"sourceVolumeID"`
	SizeBytes              int64  `json:"sizeBytes"`
	SHA256                 string `json:"sha256"`
	ApplicationConsistency string `json:"applicationConsistency"`
}

func (m VolumeManifest) Validate() error {
	digest, err := hex.DecodeString(m.SHA256)
	if !ValidVolumeID(m.SourceVolumeID) || m.SizeBytes < 64<<20 || m.SizeBytes > 1<<40 || m.SizeBytes%(1<<20) != 0 || err != nil || len(digest) != 32 || m.SHA256 != strings.ToLower(m.SHA256) || m.ApplicationConsistency != "not-asserted" {
		return ErrVolumeBackupInvalid
	}
	return nil
}

// VolumeBackup holds an exclusive reservation until Data.Close, even after EOF.
// Consumers must close it on every success/error path. Data is exactly SizeBytes.
type VolumeBackup struct {
	Manifest VolumeManifest
	Data     io.ReadCloser
}

// VolumeBackups is the local native block-storage capability. It deliberately
// does not grant a caller arbitrary filesystem paths or an in-place restore.
type VolumeBackups interface {
	OpenVolumeBackup(context.Context, string) (VolumeBackup, error)
	RestoreVolume(context.Context, string, VolumeManifest, io.Reader) (Volume, error)
}

func ReadVolumeManifest(r io.Reader) (VolumeManifest, error) {
	var m VolumeManifest
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return m, fmt.Errorf("%w: header: %v", ErrVolumeBackupInvalid, err)
	}
	length := binary.BigEndian.Uint32(header[8:])
	if string(header[:8]) != volumeBackupMagic || length == 0 || length > maxVolumeManifest {
		return m, ErrVolumeBackupInvalid
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(r, data); err != nil {
		return m, fmt.Errorf("%w: manifest: %v", ErrVolumeBackupInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, ErrVolumeBackupInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return m, ErrVolumeBackupInvalid
	}
	return m, m.Validate()
}

func WriteVolumeManifest(w io.Writer, m VolumeManifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var header [12]byte
	copy(header[:8], volumeBackupMagic)
	binary.BigEndian.PutUint32(header[8:], uint32(len(data)))
	if err := writeVolumeBytes(w, header[:]); err != nil {
		return err
	}
	return writeVolumeBytes(w, data)
}

func writeVolumeBytes(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// copyVolumeBytes never allocates in proportion to the disk, bypasses no context
// checks through WriterTo/ReaderFrom, and distinguishes truncation from success.
func copyVolumeBytes(ctx context.Context, dst io.Writer, src io.Reader, size int64) error {
	buffer := make([]byte, volumeTransferBuffer)
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(src, buffer[:min(int64(len(buffer)), size)])
		if err != nil {
			return err
		}
		if err := writeVolumeBytes(dst, buffer[:n]); err != nil {
			return err
		}
		size -= int64(n)
	}
	return ctx.Err()
}
