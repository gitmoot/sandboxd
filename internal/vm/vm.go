// Package vm defines the isolated execution boundary used by sandboxd.
package vm

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

// Spec describes one disposable Linux VM. ID is an opaque, service-owned name;
// the driver must never interpret an arbitrary client-provided path as an ID.
// Network is the guest's exclusive slot network, assigned by the ledger; the
// guest is attached to it and nothing else.
type Spec struct {
	ID        string
	Image     string
	Network   string
	CPUs      int
	MemoryMiB int
	// Envd boots an e2b-profile guest: a writable root and upstream envd as
	// its entrypoint, reached only through PortDialer. Unset, the guest is
	// the gitmoot-strict guest the driver has always started.
	Envd bool
	// Hardened boots an Envd guest whose system disk stays read-only and
	// nosuid (no writable overlay root): only its home, a volume below it
	// and bounded tmpfs mounts are writable. Only Envd specs take it, and a
	// driver that cannot honour it refuses it.
	Hardened bool
	// Volume, when set, attaches a durable volume (Volumes) at a guest path;
	// only Envd guests of a driver implementing Volumes accept it.
	Volume *VolumeMount
	// Egress, when set, is the sandbox's own public egress policy; only a
	// driver implementing EgressPolicies enforces one, every other refuses
	// it with ErrEgressUnsupported. Nil keeps the driver's default egress.
	Egress *EgressPolicy
}

// EnvdPort is the port upstream envd listens on inside an e2b guest.
const EnvdPort = guestagent.EnvdPort

// PortDialer is implemented by drivers that can start Envd guests. DialPort
// opens a fresh host-initiated byte stream to a TCP port on the guest's
// loopback (envd's, or one the sandbox's template exposes) over the driver's
// private host-to-guest channel (never the guest network). The guest never
// initiates it, and everything read from it is guest-controlled. Callers
// choose the port; drivers only check it is 1-65535.
type PortDialer interface {
	DialPort(ctx context.Context, id string, port int) (net.Conn, error)
}

// TunnelDialer opens a guest-loopback stream with directional EOF support.
// The returned net.Conn must implement CloseWrite; unsupported guests fail.
type TunnelDialer interface {
	DialTunnel(ctx context.Context, id string, port int) (net.Conn, error)
}

// ValidPort reports whether port is a TCP port number DialPort accepts.
func ValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// ErrNoEnvd reports a driver or worker that cannot run envd guests.
var ErrNoEnvd = errors.New("this VM driver does not run envd (e2b-profile) guests")

// ErrHardenedUnsupported refuses a Spec.Hardened on a driver or worker that
// cannot boot a hardened guest: hardening is never silently dropped.
var ErrHardenedUnsupported = errors.New("hardened guests are not supported by this worker")

// ErrImageTooOld: the guest image's agent did not apply a feature the VM
// was created with (hardening, a volume), so the VM is not what was asked
// for and is not kept.
var ErrImageTooOld = errors.New("guest image does not support a requested feature; rebuild it with this sandboxd version")

// ErrMemoryPressure refuses a new VM while the worker host's available
// memory is below its configured floor; retrying later can succeed.
var ErrMemoryPressure = errors.New("host memory is below the configured floor")

// HostMemory is one sample of a worker host's memory: what the kernel has
// (MemTotal), what new work can still use without swapping (MemAvailable),
// and the floor below which the driver refuses new VMs (0: none).
// PressureSome10 is the share of the last 10 seconds in which some task
// stalled on memory (/proc/pressure/memory "some avg10"), in percent, or -1
// when the kernel does not report it.
type HostMemory struct {
	TotalBytes, AvailableBytes, FloorBytes uint64
	PressureSome10                         float64
}

// HostMemoryReporter is implemented by drivers whose capacity follows the
// host's real memory use rather than a fixed reservation per VM.
type HostMemoryReporter interface {
	HostMemory(context.Context) (HostMemory, error)
}

// HardenedBooter is implemented by drivers whose guest init boots hardened
// guests (Spec.Hardened). A gateway serves a hardened template only through
// such a driver: support is declared, never assumed from a driver's name.
type HardenedBooter interface {
	BootsHardened()
}

// Instance is a positive observation of a VM owned by this driver. Network is
// its only attached network, or "" when it is not attached to exactly one.
// Paused marks a VM a Pauser paused: not running, but kept whole for Resume.
// A paused VM's Network is the slot it keeps (and resumes on).
type Instance struct {
	ID      string
	Running bool
	Paused  bool
	Network string
}

// Pauser is implemented by drivers that can pause a running VM and resume it
// later where it stopped: its memory, processes, disks and network slot are
// kept, while a paused VM runs no guest code and takes no CPU or guest RAM.
// Callers serialize Pause, Resume and Destroy of one VM.
type Pauser interface {
	// Pause stops running VM id, keeping everything Resume needs; List then
	// reports it Paused until Resume or Destroy. On error the VM is either
	// still running (Pause undid what it started) or neither running nor
	// paused, left for Destroy.
	Pause(ctx context.Context, id string) error
	// Resume starts paused VM id again where it was paused; List then
	// reports it Running. On error the VM is either still paused or neither
	// running nor paused, left for Destroy.
	Resume(ctx context.Context, id string) error
}

// ErrNotPaused refuses a Resume of a VM that is not paused, and
// ErrNotRunning a Pause of one that is not running.
var (
	ErrNotPaused  = errors.New("VM is not paused")
	ErrNotRunning = errors.New("VM is not running")
)

// Command is executed inside a running VM without a host shell.
type Command struct {
	Args []string
	Dir  string
	Env  map[string]string
	User string
	// OnStart receives the host-side execution process ID after a successful
	// start. It is a correlation ID, not the Linux guest PID.
	OnStart func(int)
}

// Driver provides one VM per job attempt. List must return a complete inventory
// or an error; callers must not infer absence from an incomplete observation.
type Driver interface {
	Create(context.Context, Spec) (Instance, error)
	List(context.Context) ([]Instance, error)
	CopyIn(context.Context, string, string, string) error
	Run(context.Context, string, Command, io.Writer, io.Writer) (int, error)
	Destroy(context.Context, string) error
}

// Usage is a measured VM resource sample. Disk allocation and I/O counters
// are not interchangeable with filesystem consumption.
type Usage struct {
	CPUUsedPct       float64
	MemoryUsedBytes  uint64
	MemoryLimitBytes uint64
	// Detailed marks a driver that also measured the fields below; drivers
	// that cannot leave it false rather than report invented values.
	Detailed bool
	// MemoryCacheBytes is resident file-backed (page cache) memory.
	MemoryCacheBytes uint64
	// DiskUsedBytes and DiskTotalBytes describe the guest's writable
	// filesystem: allocated bytes and the filesystem's size.
	DiskUsedBytes, DiskTotalBytes uint64
}

// ResourceMeter is optional for drivers that can report measured usage.
type ResourceMeter interface {
	Usage(context.Context, string) (Usage, error)
}
