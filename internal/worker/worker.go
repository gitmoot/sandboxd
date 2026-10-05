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
//   - Lease fencing: a gateway instance claims a worker with a lease from its
//     durable, strictly increasing counter and keeps that lease for its whole
//     lifetime, across reconnects. A worker accepts a lease only if it is >=
//     every lease it has accepted, and every other request must carry exactly
//     the current lease. Only a newer gateway instance presents a higher
//     lease; that cancels in-flight Run/CopyIn work started under the older
//     one, so a superseded gateway, or a run it started, cannot act after it
//     was replaced. A network blip never changes the lease and never cancels
//     work. The accepted-lease floor lives in worker memory: a restarted worker
//     has no in-flight work and accepts the next enrollment.
//   - Expiry: every VM carries an end time on the worker, set from the
//     gateway's sandbox TTL and capped by the worker's own max TTL. The worker
//     destroys expired VMs itself, even while partitioned from the gateway or
//     after the gateway forgot it.
package worker

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// ErrStaleLease reports that the worker has accepted a newer lease than the
// one presented: another gateway instance owns the worker now.
var ErrStaleLease = errors.New("stale worker lease")

// StaleLeaseError is the worker's stale-lease answer. Current is the lease the
// worker holds, or 0 when it was not reported.
type StaleLeaseError struct{ Current int64 }

func (e *StaleLeaseError) Error() string {
	if e.Current == 0 {
		return ErrStaleLease.Error()
	}
	return fmt.Sprintf("%s (worker holds lease %d)", ErrStaleLease, e.Current)
}

func (e *StaleLeaseError) Is(target error) bool { return target == ErrStaleLease }

// ErrUnavailable marks a call that failed in transport or because the worker
// is not (yet) enrolled under the caller's lease, without a verdict from the
// worker's driver. Nothing about the guest is known to have failed; the call
// may be retried.
var ErrUnavailable = errors.New("worker unavailable")

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
	// DialEnvd opens a stream to an e2b guest's envd (vm.EnvdDialer); a
	// driver without envd guests fails with vm.ErrNoEnvd.
	vm.EnvdDialer
	// Enroll presents a lease generation (strictly the gateway's durable
	// counter, >= 1). A worker accepts it only if it is >= every lease it has
	// accepted, then returns its declaration; every later call is made under
	// that lease.
	Enroll(ctx context.Context, lease int64) (Declaration, error)
	// CreateUntil is Create for a VM the worker destroys on its own at ends
	// (capped by the worker's max TTL), whether or not the gateway is reachable.
	CreateUntil(ctx context.Context, spec vm.Spec, ends time.Time) (vm.Instance, error)
	// Expire moves a VM's worker-side end time, for a renewal or after the
	// gateway re-adopts it.
	Expire(ctx context.Context, id string, ends time.Time) error
}

type local struct {
	vm.Driver
	decl Declaration
}

// Local wraps an in-process driver (today's single Mac). Enroll validates and
// returns a copy of decl; there is no transport, so the member cannot be
// stale. Usage delegates to vm.ResourceMeter when the driver implements it,
// else returns ErrNoMetrics. Expiry is enforced by the gateway's own sweep in
// the same process, so CreateUntil and Expire record no end time.
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

func (l *local) DialEnvd(ctx context.Context, id string) (net.Conn, error) {
	dialer, ok := l.Driver.(vm.EnvdDialer)
	if !ok {
		return nil, vm.ErrNoEnvd
	}
	return dialer.DialEnvd(ctx, id)
}

func (l *local) CreateUntil(ctx context.Context, spec vm.Spec, _ time.Time) (vm.Instance, error) {
	return l.Driver.Create(ctx, spec)
}

func (l *local) Expire(context.Context, string, time.Time) error { return nil }

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
	// Envd boots an e2b guest (vm.Spec.Envd).
	Envd bool `json:"envd,omitempty"`
	// Ends is when the worker destroys the VM on its own; zero means the
	// worker's max TTL from now.
	Ends time.Time `json:"ends,omitzero"`
}

type expiryRequest struct {
	Ends time.Time `json:"ends"`
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
	// The detailed fields are absent from older workers, which then report
	// detailed=false: the gateway never fills them in.
	Detailed         bool   `json:"detailed,omitempty"`
	MemoryCacheBytes uint64 `json:"memoryCacheBytes,omitempty"`
	DiskUsedBytes    uint64 `json:"diskUsedBytes,omitempty"`
	DiskTotalBytes   uint64 `json:"diskTotalBytes,omitempty"`
}

const (
	apiPrefix   = "/worker/v1/"
	leaseHeader = "X-Sandboxd-Lease"
	// leaseStateHeader qualifies a 409: "stale" (a newer lease was accepted;
	// currentLeaseHeader carries it) or "unenrolled" (the worker holds no lease
	// or an older one, e.g. after a worker restart; the caller re-enrolls).
	leaseStateHeader   = "X-Sandboxd-Lease-State"
	currentLeaseHeader = "X-Sandboxd-Current-Lease"
	// driverErrorHeader marks a failure reported by the worker's VM driver, as
	// opposed to a proxy or transport failure in front of the worker.
	driverErrorHeader = "X-Sandboxd-Worker-Error"
	maxJSONBody       = 1 << 20
	maxUpload         = 512 << 20
	maxFrameData      = 64 << 10
	minKeyLen         = 16
	staleMessage      = "stale worker lease"

	// envdUpgrade is the Upgrade token of a worker envd stream: after "101
	// Switching Protocols" the connection carries raw envd bytes.
	envdUpgrade = "sandboxd-envd"

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
