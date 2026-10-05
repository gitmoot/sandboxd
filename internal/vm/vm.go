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

// ValidPort reports whether port is a TCP port number DialPort accepts.
func ValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// ErrNoEnvd reports a driver or worker that cannot run envd guests.
var ErrNoEnvd = errors.New("this VM driver does not run envd (e2b-profile) guests")

// Instance is a positive observation of a VM owned by this driver. Network is
// its only attached network, or "" when it is not attached to exactly one.
type Instance struct {
	ID      string
	Running bool
	Network string
}

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
