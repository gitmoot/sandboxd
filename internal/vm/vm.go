// Package vm defines the isolated execution boundary used by sandboxd.
package vm

import (
	"context"
	"io"
)

// Spec describes one disposable Linux VM. ID is an opaque, service-owned name;
// the driver must never interpret an arbitrary client-provided path as an ID.
type Spec struct {
	ID        string
	Image     string
	CPUs      int
	MemoryMiB int
}

// Instance is a positive observation of a VM owned by this driver.
type Instance struct {
	ID      string
	Running bool
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
}

// ResourceMeter is optional for drivers that can report measured usage.
type ResourceMeter interface {
	Usage(context.Context, string) (Usage, error)
}
