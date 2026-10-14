//go:build sandboxd_devdriver && linux

package devvm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// VolumeConfig turns on volumes (vm.Volumes) for envd guests. Its zero value
// leaves them off.
//
// A dev volume is a plain directory <state>/volumes/<id> beside a record
// <id>.json; SizeMiB is recorded and counted against BudgetMiB but NOT
// enforced, since nothing in the dev driver is isolated. An envd guest gets
// its volume bind-mounted at a path below GuestHome, the only guest directory
// the dev driver maps. Volumes outlive guests and the driver process: a
// restarted driver accepts a state directory that holds only volumes.
type VolumeConfig struct {
	// BudgetMiB caps the summed size of all volumes; 0 turns volumes off.
	BudgetMiB int
	// SizeMiB is the size recorded for every new volume.
	SizeMiB int
}

// VolumeRemoveCommand is the root helper's argument for removing a volume
// directory a guest filled with files the driver's user cannot remove;
// programs used as the helper pass os.Args[2:] to RunVolumeRemove when they
// see it.
const VolumeRemoveCommand = "devvm-volume-remove"

const volumesDir = "volumes"

type volumeRecord struct {
	Name    string `json:"name"`
	SizeMiB int    `json:"sizeMiB"`
}

var _ vm.Volumes = (*Driver)(nil)

func (c VolumeConfig) validate() error {
	if c.BudgetMiB == 0 {
		return nil
	}
	if c.BudgetMiB < 0 || c.SizeMiB < 1 || c.SizeMiB > c.BudgetMiB {
		return errors.New("dev driver volume size must be positive and fit the volume budget")
	}
	return nil
}

func (d *Driver) volumesOn() bool { return d.volumeConfig.BudgetMiB > 0 }

func (d *Driver) volumePath(id string) string { return filepath.Join(d.root, volumesDir, id) }

// loadVolumes reads the volume records under root, finishing creates and
// deletes an earlier process left half done: a directory without a record is
// an unfinished create, a record without a directory an unfinished delete.
func loadVolumes(root string) (map[string]volumeRecord, error) {
	dir := filepath.Join(root, volumesDir)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	records := map[string]volumeRecord{}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case entry.IsDir() && vm.ValidVolumeID(name):
			present[name] = true
		case strings.HasSuffix(name, ".json.tmp"):
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		case strings.HasSuffix(name, ".json") && vm.ValidVolumeID(strings.TrimSuffix(name, ".json")):
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			var record volumeRecord
			if err := json.Unmarshal(raw, &record); err != nil || !vm.ValidVolumeName(record.Name) || record.SizeMiB < 1 {
				return nil, fmt.Errorf("dev driver volume record %s is invalid", name)
			}
			records[strings.TrimSuffix(name, ".json")] = record
		default:
			return nil, fmt.Errorf("dev driver volume directory %s holds unexpected entry %q", dir, name)
		}
	}
	for id := range records {
		if !present[id] {
			if err := os.Remove(filepath.Join(dir, id+".json")); err != nil {
				return nil, err
			}
			delete(records, id)
		}
	}
	for id := range present {
		if _, ok := records[id]; !ok {
			if err := removeTree(filepath.Join(dir, id)); err != nil {
				return nil, fmt.Errorf("remove unfinished dev volume %s: %w", id, err)
			}
		}
	}
	return records, nil
}

// CreateVolume makes the volume's directory, then commits its record.
func (d *Driver) CreateVolume(ctx context.Context, name string) (vm.Volume, error) {
	if !d.volumesOn() {
		return vm.Volume{}, errors.New("dev driver volumes are off (start sandboxd-dev with -volume-budget-mib)")
	}
	if !vm.ValidVolumeName(name) {
		return vm.Volume{}, fmt.Errorf("invalid volume name %q", name)
	}
	if err := ctx.Err(); err != nil {
		return vm.Volume{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	used := 0
	for _, record := range d.volumes {
		if record.Name == name {
			return vm.Volume{}, fmt.Errorf("volume %q: %w", name, vm.ErrVolumeExists)
		}
		used += record.SizeMiB
	}
	size := d.volumeConfig.SizeMiB
	if used+size > d.volumeConfig.BudgetMiB {
		return vm.Volume{}, fmt.Errorf("%w: %d of %d MiB in use, a volume needs %d MiB", vm.ErrVolumeBudget, used, d.volumeConfig.BudgetMiB, size)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return vm.Volume{}, err
	}
	id := "vol-" + hex.EncodeToString(raw[:])
	dir := d.volumePath(id)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return vm.Volume{}, err
	}
	record := volumeRecord{Name: name, SizeMiB: size}
	if err := writeRecord(dir+".json", record); err != nil {
		return vm.Volume{}, errors.Join(err, os.Remove(dir))
	}
	d.volumes[id] = record
	return vm.Volume{ID: id, Name: name, SizeMiB: size}, nil
}

func writeRecord(path string, record volumeRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return errors.Join(err, os.Remove(path+".tmp"))
	}
	return nil
}

// Volumes reports every volume and the guest holding it.
func (d *Driver) Volumes(ctx context.Context) ([]vm.Volume, error) {
	if !d.volumesOn() {
		return nil, errors.New("dev driver volumes are off")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	volumes := make([]vm.Volume, 0, len(d.volumes))
	for id, record := range d.volumes {
		volumes = append(volumes, vm.Volume{ID: id, Name: record.Name, SizeMiB: record.SizeMiB, AttachedTo: d.holderLocked(id)})
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	return volumes, ctx.Err()
}

// holderLocked names the guest holding volume id; callers hold d.mu. Every
// guest still in d.vms holds its volume, running or not: only a finished
// Destroy releases it.
func (d *Driver) holderLocked(id string) string {
	for guestID, g := range d.vms {
		if g.volume == id {
			return guestID
		}
	}
	return ""
}

// DeleteVolume removes the volume's data, then its record. Data a guest
// wrote (as its user or as root through sudo) may not be removable by the
// driver's user; the root helper removes it then.
func (d *Driver) DeleteVolume(ctx context.Context, id string) error {
	if !d.volumesOn() {
		return errors.New("dev driver volumes are off")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.volumes[id]; !ok {
		return fmt.Errorf("volume %q: %w", id, vm.ErrVolumeNotFound)
	}
	if holder := d.holderLocked(id); holder != "" {
		return fmt.Errorf("volume %q is attached to guest %q: %w", id, holder, vm.ErrVolumeInUse)
	}
	dir := d.volumePath(id)
	if err := removeTree(dir); err != nil {
		if len(d.envd.Helper) == 0 {
			return fmt.Errorf("remove volume %q: %w", id, err)
		}
		args := append(append([]string{}, d.envd.Helper[1:]...), VolumeRemoveCommand, dir)
		helper := exec.CommandContext(ctx, d.envd.Helper[0], args...)
		helper.Dir = "/"
		helper.Env = []string{"PATH=" + guestPath}
		if out, helperErr := helper.CombinedOutput(); helperErr != nil {
			return fmt.Errorf("remove volume %q: %w (root helper: %v: %s)", id, err, helperErr, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(dir + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove volume %q record: %w", id, err)
	}
	delete(d.volumes, id)
	return nil
}

// attachLocked checks that spec may mount its volume and returns the host
// directory to bind; callers hold d.mu.
func (d *Driver) attachLocked(spec vm.Spec) (string, error) {
	mount := spec.Volume
	if !d.volumesOn() {
		return "", errors.New("dev driver volumes are off (start sandboxd-dev with -volume-budget-mib)")
	}
	if !spec.Envd {
		return "", errors.New("the dev driver mounts volumes only in envd guests")
	}
	if !validGuestMount(mount.Path) {
		return "", fmt.Errorf("%w: the dev driver maps only %s, so it mounts volumes only below it, not at %q", vm.ErrVolumeMountPath, GuestHome, mount.Path)
	}
	if _, ok := d.volumes[mount.ID]; !ok {
		return "", fmt.Errorf("volume %q: %w", mount.ID, vm.ErrVolumeNotFound)
	}
	if holder := d.holderLocked(mount.ID); holder != "" {
		return "", fmt.Errorf("volume %q is attached to guest %q: %w", mount.ID, holder, vm.ErrVolumeInUse)
	}
	return d.volumePath(mount.ID), nil
}

func validGuestMount(p string) bool {
	return vm.ValidMountPath(p) && strings.HasPrefix(p, GuestHome+"/")
}

// closeVolumes removes the volume directory when no volume is left, so a
// driver that ends with no volumes leaves its state directory removable.
func (d *Driver) closeVolumes() error {
	if !d.volumesOn() {
		return nil
	}
	err := os.Remove(filepath.Join(d.root, volumesDir))
	if err == nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
		return nil
	}
	return err
}

// RunVolumeRemove is the root helper that removes one volume directory (the
// argument after VolumeRemoveCommand): <state>/volumes/vol-<hex>.
func RunVolumeRemove(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: " + VolumeRemoveCommand + " <volume directory>")
	}
	if os.Geteuid() != 0 {
		return errors.New("the volume removal helper must run as root")
	}
	dir := args[0]
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !vm.ValidVolumeID(filepath.Base(dir)) || filepath.Base(filepath.Dir(dir)) != volumesDir {
		return fmt.Errorf("%q is not a dev driver volume directory", dir)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return os.RemoveAll(dir)
}
