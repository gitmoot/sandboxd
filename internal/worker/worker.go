// Package worker connects the sandboxd gateway to the workers that host VMs.
//
// One gateway (the control plane) enrolls N workers. Each worker owns one VM
// driver (Apple container on a Mac, Firecracker on Linux, ...) and declares the
// guest architecture, templates, per-VM shape, and the exclusive slot networks
// it can attach VMs to. The gateway schedules every create onto a compatible
// worker with free capacity and merges the workers' inventories.
//
// Trust model for remote workers:
//
//   - Transport: the worker API listens on loopback only and is published to
//     the gateway through a private HTTPS proxy on the tailnet (Tailscale
//     Serve), exactly like the control API. The client refuses plaintext HTTP
//     unless the host is a loopback IP.
//   - Authentication: each worker has its own enrollment key (>= 16 bytes).
//     Every request carries "Authorization: Bearer <key>"; the worker keeps
//     only the key's SHA-256 digest and compares digests in constant time
//     before doing anything else. A leaked key compromises one worker only.
//   - Lease fencing: enrollment presents the gateway's durable, strictly
//     increasing lease generation. A worker accepts a lease only if it is >=
//     every lease it has accepted, and every other request must carry exactly
//     the current lease. Re-enrollment under a newer lease cancels in-flight
//     Run/CopyIn work started under an older one, so a delayed request from a
//     superseded gateway, or a run it started, cannot act after re-enrollment.
//     The accepted-lease floor lives in worker memory: a restarted worker has
//     no in-flight work and accepts the next enrollment.
package worker

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// ErrStaleLease reports that the worker has accepted a newer lease than the
// one presented; the caller has been fenced off and must re-enroll.
var ErrStaleLease = errors.New("stale worker lease")

// ErrNoMetrics reports that the worker's driver cannot measure VM usage.
var ErrNoMetrics = errors.New("VM metrics unavailable")

var (
	workerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	vmIDPattern     = regexp.MustCompile(`^sandboxd-[0-9a-f]{32}$`)
)

// Declaration is what a worker declares when it is enrolled.
type Declaration struct {
	// ID is the worker ID, ^[a-z][a-z0-9-]{0,62}$ (same rule as --worker-id).
	ID string `json:"id"`
	// Arch is the guest architecture: "arm64" or "amd64".
	Arch string `json:"arch"`
	// Driver names the VM driver, e.g. "apple", "firecracker", "fake".
	Driver string `json:"driver"`
	// Templates maps E2B template IDs to worker-local images.
	Templates map[string]string `json:"templates"`
	// CPUs is the vCPU count of every VM on this worker.
	CPUs int `json:"cpus"`
	// MemoryMiB is the memory of every VM on this worker.
	MemoryMiB int `json:"memoryMiB"`
	// MaxVMs is the worker's VM capacity, 1..len(Slots).
	MaxVMs int `json:"maxVMs"`
	// Slots are the exclusive guest networks, one per concurrent VM.
	Slots []string `json:"slots"`
}

// Validate reports whether d is a complete, self-consistent declaration.
func (d Declaration) Validate() error {
	if !workerIDPattern.MatchString(d.ID) {
		return fmt.Errorf("worker id %q must match %s", d.ID, workerIDPattern)
	}
	if d.Arch != "arm64" && d.Arch != "amd64" {
		return fmt.Errorf("worker %s: arch %q must be arm64 or amd64", d.ID, d.Arch)
	}
	if d.Driver == "" {
		return fmt.Errorf("worker %s: driver is required", d.ID)
	}
	if len(d.Templates) == 0 {
		return fmt.Errorf("worker %s: at least one template is required", d.ID)
	}
	for template, image := range d.Templates {
		if template == "" || image == "" {
			return fmt.Errorf("worker %s: template IDs and images must be nonempty", d.ID)
		}
	}
	if d.CPUs < 1 {
		return fmt.Errorf("worker %s: cpus must be >= 1", d.ID)
	}
	if d.MemoryMiB < 128 {
		return fmt.Errorf("worker %s: memoryMiB must be >= 128", d.ID)
	}
	seen := make(map[string]bool, len(d.Slots))
	for _, slot := range d.Slots {
		if slot == "" {
			return fmt.Errorf("worker %s: slot networks must be nonempty", d.ID)
		}
		if seen[slot] {
			return fmt.Errorf("worker %s: duplicate slot network %q", d.ID, slot)
		}
		seen[slot] = true
	}
	if d.MaxVMs < 1 || d.MaxVMs > len(d.Slots) {
		return fmt.Errorf("worker %s: maxVMs %d must be between 1 and the %d slot networks", d.ID, d.MaxVMs, len(d.Slots))
	}
	return nil
}

func (d Declaration) clone() Declaration {
	d.Templates = maps.Clone(d.Templates)
	d.Slots = slices.Clone(d.Slots)
	return d
}

// Member is one enrolled worker as seen by the gateway.
type Member interface {
	vm.Driver
	vm.ResourceMeter
	// Enroll presents a lease generation (strictly the gateway's durable
	// counter, >= 1). A worker accepts it only if it is >= every lease it has
	// accepted, then returns its declaration; every later call is made under
	// that lease.
	Enroll(ctx context.Context, lease int64) (Declaration, error)
}

type local struct {
	vm.Driver
	decl Declaration
}

// Local wraps an in-process driver (today's single Mac). Enroll validates and
// returns a copy of decl; there is no transport, so the member cannot be
// stale. Usage delegates to vm.ResourceMeter when the driver implements it,
// else returns ErrNoMetrics.
func Local(driver vm.Driver, decl Declaration) Member {
	return &local{Driver: driver, decl: decl.clone()}
}

func (l *local) Enroll(_ context.Context, lease int64) (Declaration, error) {
	if lease < 1 {
		return Declaration{}, fmt.Errorf("worker %s: lease must be >= 1", l.decl.ID)
	}
	if err := l.decl.Validate(); err != nil {
		return Declaration{}, err
	}
	return l.decl.clone(), nil
}

func (l *local) Usage(ctx context.Context, id string) (vm.Usage, error) {
	meter, ok := l.Driver.(vm.ResourceMeter)
	if !ok {
		return vm.Usage{}, ErrNoMetrics
	}
	return meter.Usage(ctx, id)
}

// wire types shared by Server and Client.

type enrollRequest struct {
	Lease int64 `json:"lease"`
}

type instanceJSON struct {
	ID      string `json:"id"`
	Running bool   `json:"running"`
	Network string `json:"network"`
}

type createRequest struct {
	ID        string `json:"id"`
	Image     string `json:"image"`
	Network   string `json:"network"`
	CPUs      int    `json:"cpus"`
	MemoryMiB int    `json:"memoryMiB"`
}

type runRequest struct {
	Args []string          `json:"args"`
	Dir  string            `json:"dir"`
	Env  map[string]string `json:"env"`
	User string            `json:"user"`
}

type usageJSON struct {
	CPUUsedPct       float64 `json:"cpuUsedPct"`
	MemoryUsedBytes  uint64  `json:"memoryUsedBytes"`
	MemoryLimitBytes uint64  `json:"memoryLimitBytes"`
}

const (
	apiPrefix    = "/worker/v1/"
	leaseHeader  = "X-Sandboxd-Lease"
	maxJSONBody  = 1 << 20
	maxUpload    = 512 << 20
	maxFrameData = 64 << 10
	minKeyLen    = 16
	staleMessage = "stale worker lease"

	frameStarted = 's'
	frameStdout  = 'o'
	frameStderr  = 'e'
	frameExit    = 'x'
	frameFailure = 'f'
)

// validKey reports whether key is usable as a bearer token: long enough and
// made of visible ASCII so it survives an HTTP header unchanged.
func validKey(key string) error {
	if len(key) < minKeyLen {
		return fmt.Errorf("worker key must be at least %d bytes", minKeyLen)
	}
	for i := range len(key) {
		if key[i] < 0x21 || key[i] > 0x7e {
			return errors.New("worker key must be visible ASCII without whitespace")
		}
	}
	return nil
}
