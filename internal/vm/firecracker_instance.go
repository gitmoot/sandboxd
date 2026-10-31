//go:build linux

package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// fcNames are an instance's host-global names: its host nftables table, its
// cgroup v2 parent (which holds the VMM and net- cgroups) and the prefix of
// its network namespaces under /run/netns. Names inside a VM's own
// namespace (the sbx_vm table, the taps) need none.
type fcNames struct {
	table, cgroupParent, netnsPrefix string
}

// fcInstanceNames keeps the default instance's names exactly as they were.
// A named instance's namespaces start "sbi-", never "sbx-": the default
// instance's inventory owns every sbx-* namespace and fails on foreign
// ones. Its prefix ends in '-', and names contain none, so "sbi-pho-" never
// matches another instance's "sbi-phobos-".
func fcInstanceNames(instance string) fcNames {
	if instance == "" {
		return fcNames{table: fcHostTable, cgroupParent: fcCgroupParent, netnsPrefix: fcNetnsPrefix}
	}
	return fcNames{
		table:        fcHostTable + "_" + instance,
		cgroupParent: fcCgroupParent + "-" + instance,
		netnsPrefix:  "sbi-" + instance + "-",
	}
}

// fcClaim is an instance's claim file, ClaimDir/<name>.json: the Root, UID
// range and volume directory its guests use. A running daemon holds an
// exclusive flock on its own; a killed daemon's file stays, since its guests
// may still run.
type fcClaim struct {
	Instance string `json:"instance"`
	Root     string `json:"root"`
	UIDLow   int    `json:"uidLow"`
	UIDHigh  int    `json:"uidHigh"`
	// VolumeDir is "" when the instance keeps no volumes. Two instances
	// sharing one would each attach a volume the other has attached: the
	// in-use check sees only its own VMs.
	VolumeDir string `json:"volumeDir,omitempty"`
}

func fcInstanceLabel(instance string) string {
	if instance == "" {
		return "default"
	}
	return instance
}

func fcSameRoot(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// clash names what c and other share, or returns "".
func (c fcClaim) clash(other fcClaim) string {
	if fcSameRoot(c.Root, other.Root) {
		return "root " + other.Root
	}
	if c.UIDLow <= other.UIDHigh && other.UIDLow <= c.UIDHigh {
		return fmt.Sprintf("UIDs %d-%d", other.UIDLow, other.UIDHigh)
	}
	if c.VolumeDir != "" && other.VolumeDir != "" && fcSameRoot(c.VolumeDir, other.VolumeDir) {
		return "volume directory " + other.VolumeDir
	}
	return ""
}

// Claim takes this instance's claim; call it before Arm. It locks
// ClaimDir/<instance>.json (default.json for the default instance) for the
// process's life and refuses to start beside a claim, live or stale, that
// shares its Root or UIDs. A named instance also refuses the default Root
// and UIDs while no default claim exists: a default daemon built before
// claims writes none. A Disarm that succeeds removes the claim.
func (d *FirecrackerDriver) Claim() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.claim != nil {
		return errors.New("Firecracker instance already claimed")
	}
	dir := d.cfg.ClaimDir
	if !cleanAbs(dir) {
		return fmt.Errorf("Firecracker claim directory must be absolute and clean: %q", dir)
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	dirFile, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	// Anyone else who can write here could plant or remove claims.
	info, err := dirFile.Stat()
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("Firecracker claim directory %s must be owned by this user and not group or world writable", dir)
	}
	// Instances starting together check and write their claims one at a
	// time, so none reads another's claim before it is written.
	if err := unix.Flock(int(dirFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock Firecracker claim directory %s: %w", dir, err)
	}
	low, high := d.uidRange()
	own := fcClaim{Instance: d.cfg.Instance, Root: d.cfg.Root, UIDLow: low, UIDHigh: high}
	if d.cfg.VolumeBudgetMiB > 0 {
		own.VolumeDir = d.cfg.VolumeDir
	}
	label := fcInstanceLabel(own.Instance)
	name := label + ".json"
	path := filepath.Join(dir, name)
	file, previous, err := lockClaim(path, label)
	if err != nil {
		return err
	}
	if err := checkClaims(dir, name, own, previous); err != nil {
		// A file this call created would read as an unreadable claim to
		// every other instance.
		if len(previous) == 0 {
			_ = os.Remove(path)
		}
		_ = file.Close()
		return err
	}
	data, err := json.Marshal(own)
	if err == nil {
		err = file.Truncate(0)
	}
	if err == nil {
		_, err = file.WriteAt(append(data, '\n'), 0)
	}
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("write Firecracker claim %s: %w", path, err)
	}
	if d.cfg.VolumeBudgetMiB > 0 {
		if err := d.recoverVolumes(); err != nil {
			_ = file.Close()
			return fmt.Errorf("recover claimed volume storage: %w", err)
		}
	}
	d.claim = file
	return nil
}

// lockClaim opens and locks path, returning the claim's previous contents.
// A lock taken on a file that a cleanly stopping instance has just removed
// is retried on the new one.
func lockClaim(path, label string) (*os.File, []byte, error) {
	for {
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, nil, err
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = file.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, nil, fmt.Errorf("Firecracker instance %q is already running (it holds %s)", label, path)
			}
			return nil, nil, fmt.Errorf("lock Firecracker claim %s: %w", path, err)
		}
		held, errA := file.Stat()
		current, errB := os.Lstat(path)
		if errA != nil || errB != nil || !os.SameFile(held, current) {
			_ = file.Close()
			continue
		}
		previous, err := io.ReadAll(file)
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return file, previous, nil
	}
}

// checkClaims refuses every other claim in dir that shares own's Root or
// UIDs, and this instance's own stale claim if its last run used another
// Root or UIDs: those guests may still run, and Arm would replace their
// host table with one that no longer confines them.
func checkClaims(dir, name string, own fcClaim, previous []byte) error {
	label := fcInstanceLabel(own.Instance)
	howToClear := func(other, path string) string {
		return fmt.Sprintf("a killed daemon's claim still counts, as its guests may still run: start instance %q again as it was and stop it cleanly, "+
			"or remove %s after confirming none of its guests remain", other, path)
	}
	if len(previous) != 0 {
		var last fcClaim
		if err := json.Unmarshal(previous, &last); err != nil {
			// What the last run's guests use is unknown: never assume it
			// matches.
			path := filepath.Join(dir, name)
			return fmt.Errorf("Firecracker claim %s of this instance is unreadable (%v); %s", path, err, howToClear(label, path))
		}
		if !fcSameRoot(last.Root, own.Root) || last.UIDLow != own.UIDLow || last.UIDHigh != own.UIDHigh {
			return fmt.Errorf("Firecracker instance %q last ran with root %s and UIDs %d-%d, not root %s and UIDs %d-%d; %s",
				label, last.Root, last.UIDLow, last.UIDHigh, own.Root, own.UIDLow, own.UIDHigh, howToClear(label, filepath.Join(dir, name)))
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	defaultClaimed := false
	for _, entry := range entries {
		other, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.Name() == name {
			continue
		}
		defaultClaimed = defaultClaimed || other == "default"
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // released by a clean stop since the listing
		}
		if err != nil {
			return fmt.Errorf("read Firecracker claim %s: %w", path, err)
		}
		var claim fcClaim
		if err := json.Unmarshal(data, &claim); err != nil {
			return fmt.Errorf("Firecracker claim %s is unreadable (%v); %s", path, err, howToClear(other, path))
		}
		if what := own.clash(claim); what != "" {
			return fmt.Errorf("Firecracker instance %q would share %s with instance %q (claim %s); %s",
				label, what, other, path, howToClear(other, path))
		}
	}
	if own.Instance != "" && !defaultClaimed {
		def := fcClaim{Root: FirecrackerDefaultRoot, UIDLow: FirecrackerDefaultUIDBase, UIDHigh: FirecrackerDefaultUIDBase + 2*fcUIDStride - 1,
			VolumeDir: filepath.Join(FirecrackerDefaultRoot, "volumes")}
		if what := own.clash(def); what != "" {
			return fmt.Errorf("Firecracker instance %q would share %s with the default instance, which has no claim in %s "+
				"(a binary without claims writes none): give this instance its own -fc-root and -fc-uid-base, "+
				"or run the default instance with a binary that claims", label, what, dir)
		}
	}
	return nil
}

// releaseClaim removes the claim file, then unlocks it: the instance has
// stopped cleanly and left no guests.
func (d *FirecrackerDriver) releaseClaim() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.claim == nil {
		return nil
	}
	// Under the directory lock, like Claim, so a starting instance never
	// lists this claim and then finds it gone.
	var err error
	if dirFile, openErr := os.OpenFile(d.cfg.ClaimDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0); openErr != nil {
		err = openErr
	} else {
		err = unix.Flock(int(dirFile.Fd()), unix.LOCK_EX)
		if err == nil {
			err = os.Remove(d.claim.Name())
		}
		_ = dirFile.Close()
	}
	err = errors.Join(err, d.claim.Close())
	d.claim = nil
	if err != nil {
		return fmt.Errorf("remove Firecracker claim: %w", err)
	}
	return nil
}
