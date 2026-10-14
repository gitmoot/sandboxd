//go:build linux

package vm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

// A volume is two files in VolumeDir: <id>.json, its record, and <id>.ext4,
// the disk, written in that order and removed in the reverse one. A record
// without a disk is a crash leftover. The disk is root-owned and 0600 while
// detached; attached, it is hard-linked into the VM's jail as fcVolumeFile
// and owned by the VMM UID. A disk with more than one link is held by a jail.
const (
	fcVolumeFile     = "/volume.ext4"
	fcVolumeDrive    = "volume"
	fcVolumeSyncTime = 5 * time.Second
)

// fcMkfs are the host mke2fs candidates; the first trusted one is used.
// mkfs.ext4 is usually a symlink to mke2fs, which TrustedFile refuses, and
// /sbin a symlink to /usr/sbin on merged-/usr systems.
var fcMkfs = []string{"/usr/sbin/mke2fs", "/sbin/mke2fs"}

type fcVolume struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	SizeMiB int    `json:"sizeMiB"`
}

func (d *FirecrackerDriver) volumeRecord(id string) string {
	return filepath.Join(d.cfg.VolumeDir, id+".json")
}
func (d *FirecrackerDriver) volumeDisk(id string) string {
	return filepath.Join(d.cfg.VolumeDir, id+".ext4")
}

// initVolumes validates the volume configuration, creates VolumeDir and
// removes what a crash during CreateVolume left behind.
func (d *FirecrackerDriver) initVolumes() error {
	cfg := d.cfg
	if !cleanAbs(cfg.VolumeDir) {
		return fmt.Errorf("Firecracker volume directory must be absolute and clean: %q", cfg.VolumeDir)
	}
	if cfg.VolumeMiB < 64 || cfg.VolumeMiB > 1<<20 {
		return errors.New("Firecracker volume size must be between 64 MiB and 1 TiB")
	}
	if cfg.VolumeBudgetMiB < cfg.VolumeMiB {
		return errors.New("Firecracker volume budget must hold at least one volume")
	}
	var untrusted error
	for _, mkfs := range fcMkfs {
		err := d.host.TrustedFile(mkfs, true)
		if err == nil {
			d.mkfs = mkfs
			break
		}
		untrusted = errors.Join(untrusted, err)
	}
	if d.mkfs == "" {
		return fmt.Errorf("Firecracker volumes need a trusted mke2fs: %w", untrusted)
	}
	if err := mkdirExact(cfg.VolumeDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	dir, err := os.Lstat(cfg.VolumeDir)
	if err != nil {
		return err
	}
	if !dir.IsDir() {
		return fmt.Errorf("Firecracker volume directory %s is not a directory", cfg.VolumeDir)
	}
	// Only this daemon may reach detached disks: a directory made by hand
	// with a wider mode is narrowed, one owned by another user refused.
	if owner := dir.Sys().(*syscall.Stat_t).Uid; int(owner) != os.Geteuid() {
		return fmt.Errorf("Firecracker volume directory %s is owned by uid %d, not this daemon", cfg.VolumeDir, owner)
	}
	if dir.Mode().Perm() != 0o700 {
		if err := os.Chmod(cfg.VolumeDir, 0o700); err != nil {
			return err
		}
	}
	root, err := os.Stat(cfg.Root)
	if err != nil {
		return err
	}
	// Attaching hard-links the disk into the jail under Root.
	if dir.Sys().(*syscall.Stat_t).Dev != root.Sys().(*syscall.Stat_t).Dev {
		return fmt.Errorf("Firecracker volume directory %s must be on the filesystem of %s", cfg.VolumeDir, cfg.Root)
	}
	names, err := readDirNames(cfg.VolumeDir)
	if err != nil {
		return err
	}
	for _, name := range names {
		path := filepath.Join(cfg.VolumeDir, name)
		if strings.HasSuffix(name, ".ext4.tmp") {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		if id, ok := strings.CutSuffix(name, ".ext4"); ok && ValidVolumeID(id) {
			if err := d.settleDisk(id); err != nil {
				return err
			}
			continue
		}
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || !ValidVolumeID(id) {
			continue
		}
		if _, err := os.Lstat(d.volumeDisk(id)); errors.Is(err, fs.ErrNotExist) {
			if err := os.Remove(path); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return fcSyncPath(cfg.VolumeDir)
}

// settleDisk handles one disk at startup. A disk without its record cannot
// come from the driver's write order (record first on create, disk first on
// delete), so it is someone else's file: it is reported, never removed. A
// detached disk (one link) still owned by a former VMM UID, left by a crash
// between jail removal and the release chown, goes back to root; a disk still
// linked into a jail belongs to a VM that outlived the daemon and keeps its
// owner.
func (d *FirecrackerDriver) settleDisk(id string) error {
	path := d.volumeDisk(id)
	if _, err := os.Lstat(d.volumeRecord(id)); errors.Is(err, fs.ErrNotExist) {
		log.Printf("firecracker: volume disk %s has no record; it is not used, remove it by hand if it is not needed", path)
		return nil
	} else if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid == 0 && stat.Gid == 0 {
		return nil
	}
	return d.host.Chown(path, 0, 0)
}

func (d *FirecrackerDriver) volumesOn() error {
	if d.cfg.VolumeBudgetMiB == 0 {
		return errors.New("volumes are not configured on this Firecracker worker")
	}
	return nil
}

// readVolumes lists every complete volume. Callers hold volumeMu.
func (d *FirecrackerDriver) readVolumes() ([]fcVolume, error) {
	names, err := readDirNames(d.cfg.VolumeDir)
	if err != nil {
		return nil, err
	}
	var volumes []fcVolume
	for _, name := range names {
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || !ValidVolumeID(id) {
			continue
		}
		volume, err := d.readVolume(id)
		if errors.Is(err, ErrVolumeNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

// readVolume reads one complete volume's record. Callers hold volumeMu.
func (d *FirecrackerDriver) readVolume(id string) (fcVolume, error) {
	if !ValidVolumeID(id) {
		return fcVolume{}, fmt.Errorf("%w: %q", ErrVolumeNotFound, id)
	}
	data, err := os.ReadFile(d.volumeRecord(id))
	if errors.Is(err, fs.ErrNotExist) {
		return fcVolume{}, fmt.Errorf("%w: %q", ErrVolumeNotFound, id)
	}
	if err != nil {
		return fcVolume{}, err
	}
	if _, err := os.Lstat(d.volumeDisk(id)); errors.Is(err, fs.ErrNotExist) {
		return fcVolume{}, fmt.Errorf("%w: %q", ErrVolumeNotFound, id)
	} else if err != nil {
		return fcVolume{}, err
	}
	var volume fcVolume
	if json.Unmarshal(data, &volume) != nil || volume.ID != id || !ValidVolumeName(volume.Name) || volume.SizeMiB < 1 {
		return fcVolume{}, fmt.Errorf("malformed Firecracker volume record %s", d.volumeRecord(id))
	}
	return volume, nil
}

// volumeHolders maps each volume ID to the VM whose record holds it.
func volumeHolders(vms []fcVM) map[string]string {
	holders := map[string]string{}
	for _, vm := range vms {
		if vm.meta != nil && vm.meta.Volume != "" {
			holders[vm.meta.Volume] = vm.id
		}
	}
	return holders
}

// volumeInUse reports whether a VM record or a jail's hard link holds the
// volume. Callers hold volumeMu.
func (d *FirecrackerDriver) volumeInUse(id string) error {
	vms, err := d.inventory()
	if err != nil {
		return err
	}
	if holder := volumeHolders(vms)[id]; holder != "" {
		return fmt.Errorf("%w: %s holds %s", ErrVolumeInUse, holder, id)
	}
	info, err := os.Lstat(d.volumeDisk(id))
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return fmt.Errorf("%w: a jail still links %s", ErrVolumeInUse, id)
	}
	return nil
}

// CreateVolume makes a VolumeMiB ext4 disk named name.
func (d *FirecrackerDriver) CreateVolume(ctx context.Context, name string) (Volume, error) {
	if err := d.volumesOn(); err != nil {
		return Volume{}, err
	}
	if !ValidVolumeName(name) {
		return Volume{}, fmt.Errorf("invalid volume name %q", name)
	}
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	volumes, err := d.readVolumes()
	if err != nil {
		return Volume{}, err
	}
	used := 0
	for _, volume := range volumes {
		if volume.Name == name {
			return Volume{}, fmt.Errorf("%w: %q", ErrVolumeExists, name)
		}
		used += volume.SizeMiB
	}
	size := d.cfg.VolumeMiB
	if used+size > d.cfg.VolumeBudgetMiB {
		return Volume{}, fmt.Errorf("%w: %d of %d MiB used, a volume takes %d MiB", ErrVolumeBudget, used, d.cfg.VolumeBudgetMiB, size)
	}
	free, err := d.host.FreeBytes(d.cfg.VolumeDir)
	if err != nil {
		return Volume{}, err
	}
	if need := uint64(d.cfg.DiskFloorMiB+size) << 20; free < need {
		return Volume{}, fmt.Errorf("%w: %d MiB free, %d MiB floor plus %d MiB volume needed",
			ErrVolumeBudget, free>>20, d.cfg.DiskFloorMiB, size)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Volume{}, err
	}
	volume := fcVolume{ID: "vol-" + hex.EncodeToString(random[:]), Name: name, SizeMiB: size}
	record, err := json.Marshal(volume)
	if err != nil {
		return Volume{}, err
	}
	if err := writeFileExcl(d.volumeRecord(volume.ID), record, 0o600); err != nil {
		return Volume{}, err
	}
	if err := d.formatVolume(ctx, volume); err != nil {
		return Volume{}, errors.Join(err, os.Remove(d.volumeRecord(volume.ID)))
	}
	return Volume{ID: volume.ID, Name: volume.Name, SizeMiB: volume.SizeMiB}, nil
}

// formatVolume writes the disk under a temporary name and renames it into
// place, so a disk at its final name is always complete.
func (d *FirecrackerDriver) formatVolume(ctx context.Context, volume fcVolume) error {
	disk := d.volumeDisk(volume.ID)
	tmp := disk + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = errors.Join(file.Truncate(int64(volume.SizeMiB)<<20), file.Chmod(0o600), file.Close())
	if err == nil {
		err = d.host.FormatVolume(ctx, d.mkfs, tmp)
	}
	if err == nil {
		err = fcSyncPath(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, disk)
	}
	if err != nil {
		return errors.Join(err, fcRemoveMissing(tmp))
	}
	return fcSyncPath(d.cfg.VolumeDir)
}

// Volumes lists every volume, sorted by name.
func (d *FirecrackerDriver) Volumes(ctx context.Context) ([]Volume, error) {
	if err := d.volumesOn(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	volumes, err := d.readVolumes()
	if err != nil {
		return nil, err
	}
	vms, err := d.inventory()
	if err != nil {
		return nil, err
	}
	holders := volumeHolders(vms)
	out := make([]Volume, 0, len(volumes))
	for _, volume := range volumes {
		out = append(out, Volume{ID: volume.ID, Name: volume.Name, SizeMiB: volume.SizeMiB, AttachedTo: holders[volume.ID]})
	}
	slices.SortFunc(out, func(a, b Volume) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// DeleteVolume removes a detached volume's disk, then its record.
func (d *FirecrackerDriver) DeleteVolume(ctx context.Context, id string) error {
	if err := d.volumesOn(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	if _, err := d.readVolume(id); err != nil {
		return err
	}
	if err := d.volumeInUse(id); err != nil {
		return err
	}
	if err := os.Remove(d.volumeDisk(id)); err != nil {
		return err
	}
	if err := os.Remove(d.volumeRecord(id)); err != nil {
		return err
	}
	return fcSyncPath(d.cfg.VolumeDir)
}

// writeRecord writes the VM's ownership record. With a volume, the in-use
// check and the record that then holds the volume are one step under
// volumeMu, so two creates can never both attach it.
func (d *FirecrackerDriver) writeRecord(spec Spec, meta *fcMeta) error {
	if err := os.MkdirAll(d.runDir(), 0o700); err != nil {
		return err
	}
	if spec.Volume != nil {
		d.volumeMu.Lock()
		defer d.volumeMu.Unlock()
		volume, err := d.readVolume(spec.Volume.ID)
		if err != nil {
			return err
		}
		if err := d.volumeInUse(volume.ID); err != nil {
			return err
		}
		meta.Volume, meta.VolumePath, meta.VolumeMiB = volume.ID, d.volumeDisk(volume.ID), volume.SizeMiB
	}
	record, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return writeFileExcl(d.metaPath(spec.ID), record, 0o600)
}

// checkVolumeSpec refuses a volume this driver cannot attach.
func (d *FirecrackerDriver) checkVolumeSpec(spec Spec) error {
	if spec.Volume == nil {
		return nil
	}
	if err := d.volumesOn(); err != nil {
		return err
	}
	if !spec.Envd {
		return errors.New("only e2b guests take a volume")
	}
	if !ValidVolumeID(spec.Volume.ID) {
		return fmt.Errorf("%w: %q", ErrVolumeNotFound, spec.Volume.ID)
	}
	if !ValidMountPath(spec.Volume.Path) {
		return fmt.Errorf("%w: invalid volume mount path %q", ErrVolumeMountPath, spec.Volume.Path)
	}
	return nil
}

// linkVolume hard-links the attached disk into the jail and gives it to the
// VMM UID, the only one that opens it.
func (d *FirecrackerDriver) linkVolume(root string, meta fcMeta) error {
	link := filepath.Join(root, fcVolumeFile)
	if err := os.Link(meta.VolumePath, link); err != nil {
		return fmt.Errorf("link volume into jail (same filesystem required): %w", err)
	}
	return d.host.Chown(link, meta.VMMUID, meta.VMMUID)
}

// releaseVolume returns a detached disk to root once the jail's link is gone.
func (d *FirecrackerDriver) releaseVolume(meta *fcMeta) error {
	if meta == nil || meta.Volume == "" {
		return nil
	}
	d.volumeMu.Lock()
	defer d.volumeMu.Unlock()
	if err := d.host.Chown(meta.VolumePath, 0, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// syncGuest asks the guest to flush and remount its volume read-only before
// the VMM is killed. It is best effort: a failure is logged, never fatal.
func (d *FirecrackerDriver) syncGuest(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(ctx, fcVolumeSyncTime)
	defer cancel()
	conn, err := d.dialAgent(ctx, id)
	if err == nil {
		err = guestagent.Sync(ctx, conn)
		_ = conn.Close()
	}
	if err != nil {
		log.Printf("firecracker: volume sync of %s before destroy: %v", id, err)
	}
}

func fcSyncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func fcRemoveMissing(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
