package vm

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
)

// Volume errors. Drivers wrap them so callers can map them with errors.Is.
var (
	// ErrVolumeNotFound: no volume has that ID.
	ErrVolumeNotFound = errors.New("volume not found")
	// ErrVolumeExists: a volume of that name already exists.
	ErrVolumeExists = errors.New("volume name already exists")
	// ErrVolumeInUse: the volume is attached to a VM (any trace of one: a
	// running, stopped or half-destroyed VM still holds it).
	ErrVolumeInUse = errors.New("volume is attached to a sandbox")
	// ErrVolumeBudget: creating the volume would exceed the total volume
	// budget or the host disk floor.
	ErrVolumeBudget = errors.New("volume budget exhausted")
)

// Volume is one durable named disk. It outlives every VM it is attached to:
// destroying a VM, restarting or killing the daemon, and a firewall loss
// that destroys guests all keep it; only DeleteVolume removes it.
type Volume struct {
	ID   string
	Name string
	// SizeMiB is the hard size of the volume's block device.
	SizeMiB int
	// AttachedTo is the VM holding the volume, "" when none does.
	AttachedTo string
}

// VolumeMount attaches volume ID to a VM at an absolute guest path.
type VolumeMount struct {
	ID   string
	Path string
}

// Volumes is implemented by drivers that keep durable volumes (the Linux
// Firecracker driver, and devvm for CI). A volume is attached to at most one
// VM at a time; Create of a Spec whose Volume is attached anywhere fails with
// ErrVolumeInUse, and DeleteVolume of an attached volume does too.
type Volumes interface {
	CreateVolume(ctx context.Context, name string) (Volume, error)
	// Volumes lists every volume, sorted by name.
	Volumes(ctx context.Context) ([]Volume, error)
	DeleteVolume(ctx context.Context, id string) error
}

var (
	volumeName     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)
	volumeID       = regexp.MustCompile(`^vol-[0-9a-f]{32}$`)
	mountPathChars = regexp.MustCompile(`^[a-zA-Z0-9._/-]{2,255}$`)
)

// ValidVolumeName reports whether name is an acceptable volume name.
func ValidVolumeName(name string) bool { return volumeName.MatchString(name) }

// ValidVolumeID reports whether id has the form drivers assign.
func ValidVolumeID(id string) bool { return volumeID.MatchString(id) }

// ValidMountPath reports whether p may be a guest mount path: absolute,
// clean, not "/", and limited to characters that are safe in a kernel
// command line and need no quoting.
func ValidMountPath(p string) bool {
	return mountPathChars.MatchString(p) && strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "/"
}
