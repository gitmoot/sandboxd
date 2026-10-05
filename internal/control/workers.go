package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/envd"
	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
	"github.com/gitmoot/sandboxd/internal/worker"
)

// Every worker call has a deadline, so a partitioned worker turns offline
// instead of stalling requests, the sweep, or other workers. workerTimeout
// bounds one enrollment-plus-reconciliation pass and each short call (List,
// Expire, Usage); workerSlowTimeout bounds a Create, which boots a VM, and a
// requested Destroy. Guest Run and CopyIn are bounded by their caller, since a
// job's process may run for its whole TTL. Variables only so tests can shorten
// them.
var (
	workerTimeout     = 10 * time.Second
	workerSlowTimeout = 3 * time.Minute
)

// turn is a mutex whose Lock gives up when its context ends.
type turn chan struct{}

func newTurn() turn { return make(turn, 1) }

func (t turn) lock(ctx context.Context) error {
	select {
	case t <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t turn) unlock() { <-t }

func newMember(id string, api worker.Member, local bool) *member {
	return &member{id: id, api: api, local: local, pass: newTurn(), expiry: newTurn()}
}

var workerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func validWorkerID(id string) bool { return workerIDPattern.MatchString(id) }

func validArch(arch string) bool { return arch == "arm64" || arch == "amd64" }

// member is the gateway's state for one enrolled worker.
//
// Ownership of a sandbox is the pair (worker, lease). A gateway instance
// claims each worker once, with a fresh durable lease, and keeps that lease
// across reconnects: a worker that blips or restarts is re-enrolled under the
// same lease, so nothing it runs for this gateway is cancelled. Only a newer
// gateway instance presents a higher lease; the worker then fences this one,
// which stays superseded (offline) until it restarts. The gateway refuses any
// answer or guest access that does not carry its current lease.
type member struct {
	id  string
	api worker.Member
	// local is the gateway's own driver, whose slots are this host's networks.
	local bool
	// pass serializes enrollment, reconciliation and forgetting for this
	// worker only. Waiting for it honours the caller's context.
	pass turn
	// expiry orders end-time updates sent to the worker, so a reconciliation
	// never overwrites a renewal with the older end time. It is held only for
	// one bounded Expire call.
	expiry turn

	// The fields below are guarded by Service.mu.
	decl    worker.Declaration
	serves  map[string]string // template ID -> image, arch-compatible and registered
	refused map[string]string // template ID -> reason the gateway refused it
	// lease is this gateway instance's claim; 0 until first allocated, then
	// fixed for the life of the process.
	lease int64
	// enrolled: the worker accepted lease since it was last unobservable.
	enrolled bool
	// claimed: the worker has accepted lease at least once.
	claimed bool
	// superseded: the worker accepted a newer gateway's lease.
	superseded bool
	online     bool
	lastSeen   time.Time
	err        string
}

// refusal is a create that provably allocated nothing.
type refusal struct {
	status  int
	message string
}

func (r *refusal) Error() string { return r.message }

var errNoWorker = errors.New("no compatible worker is online")

func (s *Service) reconcileAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, m := range s.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.reconcile(ctx, m)
		}()
	}
	wg.Wait()
}

// offline records that m could not be observed. Its lease is kept: the next
// pass re-enrolls under the same lease, which cancels nothing on the worker.
// A stale-lease answer means a newer gateway owns the worker; this gateway
// then stops using it for good.
func (s *Service) offline(m *member, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.online = false
	m.enrolled = false
	if errors.Is(err, worker.ErrStaleLease) && m.claimed {
		m.superseded = true
		err = fmt.Errorf("superseded by a newer gateway instance; restart this gateway to reclaim the worker: %w", err)
	}
	m.err = err.Error()
	return err
}

func (s *Service) enroll(ctx context.Context, m *member) error {
	s.mu.Lock()
	lease, claimed, superseded := m.lease, m.claimed, m.superseded
	s.mu.Unlock()
	if superseded {
		return errors.New("superseded by a newer gateway instance; restart this gateway to reclaim the worker")
	}
	var err error
	if lease == 0 {
		if lease, err = s.ledger.NextLease(ctx, m.id, m.local, 0); err != nil {
			return err
		}
		s.mu.Lock()
		m.lease = lease
		s.mu.Unlock()
	}
	decl, err := m.api.Enroll(ctx, lease)
	var stale *worker.StaleLeaseError
	if !claimed && errors.As(err, &stale) && stale.Current > 0 {
		// This gateway instance never held the worker, which still holds a
		// lease from a gateway whose ledger is gone. Starting up is what
		// claims a worker, so take a lease above it once.
		if lease, err = s.ledger.NextLease(ctx, m.id, m.local, stale.Current); err != nil {
			return err
		}
		s.mu.Lock()
		m.lease = lease
		s.mu.Unlock()
		decl, err = m.api.Enroll(ctx, lease)
	}
	if err != nil {
		return fmt.Errorf("enroll worker %s: %w", m.id, err)
	}
	if err := decl.Validate(); err != nil {
		return err
	}
	if decl.ID != m.id {
		return fmt.Errorf("worker %s declared identity %q", m.id, decl.ID)
	}
	serves := make(map[string]string, len(decl.Templates))
	refused := make(map[string]string)
	for template, image := range decl.Templates {
		registered, known := s.templates.byID[template]
		switch {
		case !known:
			refused[template] = "template is not registered at the gateway"
		case registered.Arch != decl.Arch:
			refused[template] = fmt.Sprintf("architecture mismatch: template requires %s, worker runs %s", registered.Arch, decl.Arch)
		default:
			serves[template] = image
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.decl, m.serves, m.refused = decl, serves, refused
	m.enrolled, m.claimed = true, true
	return nil
}

// reconcile uses only m's complete successful inventory under its current
// lease. Unknown or failed observations never release a reservation; they take
// the worker offline. Only rows that were settled when the inventory was
// requested are judged by it. Owned VMs with no live ledger row are destroyed;
// VMs recorded for another worker are left to that worker's ledger rows.
func (s *Service) reconcile(ctx context.Context, m *member) error {
	ctx, cancel := context.WithTimeout(ctx, workerTimeout)
	defer cancel()
	if err := m.pass.lock(ctx); err != nil {
		return fmt.Errorf("worker %s: reconciliation already in progress: %w", m.id, err)
	}
	defer m.pass.unlock()
	s.mu.Lock()
	enrolled := m.enrolled
	s.mu.Unlock()
	// fresh: this pass (re-)enrolled the worker, which may have restarted and
	// lost the end times of the VMs it runs.
	fresh := !enrolled
	if fresh {
		if err := s.enroll(ctx, m); err != nil {
			return s.offline(m, err)
		}
	}
	s.mu.Lock()
	lease := m.lease
	rows, err := s.ledger.Active(ctx)
	settled := make(map[string]bool)
	for _, row := range rows {
		if row.WorkerID == m.id && s.busy[row.ID] == nil {
			settled[row.ID] = true
		}
	}
	s.mu.Unlock()
	if err != nil {
		return s.offline(m, err)
	}
	instances, err := m.api.List(ctx)
	if err != nil {
		return s.offline(m, fmt.Errorf("list worker %s: %w", m.id, err))
	}
	inventory := make(map[string]vm.Instance, len(instances))
	for _, instance := range instances {
		if instance.ID == "" {
			return s.offline(m, errors.New("VM inventory contains empty ID"))
		}
		if _, duplicate := inventory[instance.ID]; duplicate {
			return s.offline(m, errors.New("VM inventory contains duplicate ID"))
		}
		inventory[instance.ID] = instance
	}

	s.mu.Lock()
	if m.superseded {
		s.mu.Unlock()
		return errors.New("superseded by a newer gateway instance")
	}
	rows, err = s.ledger.Active(ctx)
	if err != nil {
		s.mu.Unlock()
		return s.offline(m, err)
	}
	var rowsToDestroy, orphans []string
	// expiries are sandboxes whose end time the worker must (re-)learn: rows
	// adopted from an earlier gateway instance, and every kept row after a
	// (re-)enrollment, since a restarted worker forgets them.
	var expiries []string
	now := time.Now()
	for _, row := range rows {
		instance, observed := inventory[row.ID]
		delete(inventory, row.ID)
		if row.WorkerID != m.id || !settled[row.ID] || s.busy[row.ID] != nil {
			continue
		}
		current, err := s.ledger.Current(ctx, row)
		if err != nil {
			s.mu.Unlock()
			return s.offline(m, err)
		}
		// A guest observed off its recorded slot may share a network with
		// another guest; never keep it. Legacy rows have no recorded slot.
		onSlot := row.Slot == "" || instance.Network == row.Slot
		if observed && row.State == "running" && instance.Running && onSlot && current && now.Before(row.Ends) &&
			m.serves[row.TemplateID] == row.Image {
			if row.Lease != lease {
				if err := s.ledger.Adopt(ctx, row.ID, lease); err != nil {
					s.mu.Unlock()
					return s.offline(m, err)
				}
			}
			if fresh || row.Lease != lease {
				expiries = append(expiries, row.ID)
			}
			continue
		}
		// A failed Create can complete late; even a formerly running VM can
		// leave a job-owned volume after its container disappears. Confirm
		// allocation cleanup before marking absence.
		if err := s.setState(ctx, row.ID, "unknown"); err != nil {
			s.mu.Unlock()
			return s.offline(m, err)
		}
		s.markBusy(row.ID)
		rowsToDestroy = append(rowsToDestroy, row.ID)
	}
	for id := range inventory {
		if s.busy[id] == nil {
			orphans = append(orphans, id)
		}
	}
	s.mu.Unlock()

	release := func(ids []string) {
		s.mu.Lock()
		for _, id := range ids {
			s.clearBusy(id)
		}
		s.mu.Unlock()
	}
	for i, id := range rowsToDestroy {
		if err := m.api.Destroy(ctx, id); err != nil {
			release(rowsToDestroy[i:])
			return s.offline(m, fmt.Errorf("destroy on worker %s: %w", m.id, err))
		}
		s.mu.Lock()
		err := s.setState(ctx, id, "gone")
		s.clearBusy(id)
		s.mu.Unlock()
		if err != nil {
			release(rowsToDestroy[i+1:])
			return s.offline(m, err)
		}
	}
	for _, id := range orphans {
		if err := m.api.Destroy(ctx, id); err != nil {
			return s.offline(m, fmt.Errorf("destroy orphan on worker %s: %w", m.id, err))
		}
	}
	// Rows an operator forgot (forget-worker) are proven gone now: a complete
	// inventory was taken and every VM without a live row was destroyed. A
	// targeted destroy also removes any leftover per-VM storage.
	unverified, err := s.ledger.Unverified(ctx, m.id)
	if err != nil {
		return s.offline(m, err)
	}
	for _, id := range unverified {
		if err := m.api.Destroy(ctx, id); err != nil {
			return s.offline(m, fmt.Errorf("destroy forgotten sandbox on worker %s: %w", m.id, err))
		}
		if err := s.ledger.ResolveUnverified(ctx, id); err != nil {
			return s.offline(m, err)
		}
	}
	for _, id := range expiries {
		if err := s.pushExpiry(ctx, m, id); err != nil {
			return s.offline(m, fmt.Errorf("send end time of %s to worker %s: %w", id, m.id, err))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.superseded {
		m.online = false
		return errors.New("superseded by a newer gateway instance")
	}
	m.online, m.lastSeen, m.err = true, time.Now().UTC(), ""
	return nil
}

// pushExpiry sends a sandbox's current ledger end time to its worker. The
// ledger is read under m.expiry, which renewals also hold while they update
// the worker and then the ledger, so the last value sent is never older than
// the ledger's.
func (s *Service) pushExpiry(ctx context.Context, m *member, id string) error {
	if err := m.expiry.lock(ctx); err != nil {
		return err
	}
	defer m.expiry.unlock()
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if row.State != "running" {
		return nil
	}
	return m.api.Expire(ctx, id, row.Ends)
}

// admit schedules row onto the online worker serving its template with the
// most free capacity, and reserves a slot there under the worker's current
// lease. Callers hold s.mu.
func (s *Service) admit(ctx context.Context, row *store.Row) (*member, vm.Spec, error) {
	rows, err := s.ledger.Active(ctx)
	if err != nil {
		return nil, vm.Spec{}, err
	}
	sharing, err := s.sharing(ctx, rows)
	if err != nil {
		return nil, vm.Spec{}, err
	}
	// A worker that is not enrolled is treated like an offline one: its live
	// rows hold its own capacity only. An unenrolled identity that ran on this
	// host also holds the local worker's physical slots.
	used := make(map[string]int)
	for _, active := range rows {
		used[active.WorkerID]++
	}
	if s.localMember != nil {
		for _, id := range sharing {
			used[s.localMember.id] += used[id]
		}
	}
	type candidate struct {
		m    *member
		free int
	}
	var candidates []candidate
	// known: some worker declared it serves the template. A worker that never
	// enrolled has declared nothing, so it may yet serve the template.
	known, mismatch := false, ""
	for _, m := range s.workers {
		_, serves := m.serves[row.TemplateID]
		known = known || serves || m.decl.ID == ""
		if serves {
			if m.online && m.lease != 0 {
				candidates = append(candidates, candidate{m, m.decl.MaxVMs - used[m.id]})
			}
		} else if reason, ok := m.refused[row.TemplateID]; ok && mismatch == "" {
			mismatch = fmt.Sprintf("worker %s refused template %s: %s", m.id, row.TemplateID, reason)
		}
	}
	if len(candidates) == 0 {
		if !known && mismatch != "" {
			return nil, vm.Spec{}, &refusal{http.StatusBadRequest, "no worker can run template " + row.TemplateID + "; " + mismatch}
		}
		return nil, vm.Spec{}, errNoWorker
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].free > candidates[j].free })
	for _, c := range candidates {
		if c.free <= 0 {
			break
		}
		row.WorkerID, row.Image, row.Lease = c.m.id, c.m.serves[row.TemplateID], c.m.lease
		row.CPUs, row.MemoryMiB = c.m.decl.CPUs, c.m.decl.MemoryMiB
		var shared []string
		if c.m.local {
			shared = sharing
		}
		slot, err := s.ledger.Reserve(ctx, *row, c.m.decl.MaxVMs, c.m.decl.Slots, shared...)
		switch {
		case errors.Is(err, store.ErrCapacity):
			continue
		case errors.Is(err, store.ErrStale):
			return nil, vm.Spec{}, &refusal{http.StatusConflict, "sandbox owner conflict: stale or duplicate job attempt"}
		case err != nil:
			return nil, vm.Spec{}, err
		}
		row.Slot = slot
		return c.m, vm.Spec{ID: row.ID, Image: row.Image, Network: slot, CPUs: row.CPUs, MemoryMiB: row.MemoryMiB,
			Envd: rowProfile(row.Profile) == ProfileE2B}, nil
	}
	return nil, vm.Spec{}, &refusal{http.StatusConflict, "sandbox capacity exhausted: every compatible worker is full"}
}

type templateCapacity struct {
	TemplateID string `json:"templateID"`
	Arch       string `json:"arch"`
	TotalSlots int    `json:"totalSlots"`
	FreeSlots  int    `json:"freeSlots"`
}

type workerCapacity struct {
	WorkerID         string            `json:"workerID"`
	Arch             string            `json:"arch"`
	Driver           string            `json:"driver"`
	Templates        []string          `json:"templates"`
	RefusedTemplates map[string]string `json:"refusedTemplates"`
	// Enrolled is false for an identity that still owns live sandboxes but is
	// no longer configured; it is reported offline until forgotten.
	Enrolled  bool       `json:"enrolled"`
	Online    bool       `json:"online"`
	Lease     int64      `json:"lease"`
	MaxVMs    int        `json:"maxVMs"`
	UsedSlots int        `json:"usedSlots"`
	CPUs      int        `json:"cpus"`
	MemoryMiB int        `json:"memoryMiB"`
	LastSeen  *time.Time `json:"lastSeen"`
	Error     string     `json:"error"`
}

type capacityReport struct {
	TotalSlots int                `json:"totalSlots"`
	UsedSlots  int                `json:"usedSlots"`
	FreeSlots  int                `json:"freeSlots"`
	Templates  []templateCapacity `json:"templates"`
	Workers    []workerCapacity   `json:"workers"`
}

// capacity reports the cluster as of the latest reconciliation. Totals count
// only online workers; an offline worker stays listed with its last error.
// Reserved and unresolved rows hold their slot until proven gone.
func (s *Service) capacity(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.ledger.Active(r.Context())
	if err != nil {
		unavailable(w)
		return
	}
	sharing, err := s.sharing(r.Context(), rows)
	if err != nil {
		unavailable(w)
		return
	}
	used := make(map[string]int)
	for _, row := range rows {
		used[row.WorkerID]++
	}
	if s.localMember != nil {
		for _, id := range sharing {
			used[s.localMember.id] += used[id]
		}
	}
	report := capacityReport{Templates: []templateCapacity{}, Workers: []workerCapacity{}}
	for _, m := range s.workers {
		entry := workerCapacity{WorkerID: m.id, Arch: m.decl.Arch, Driver: m.decl.Driver, Templates: []string{},
			RefusedTemplates: map[string]string{}, Enrolled: true, Online: m.online, Lease: m.lease, MaxVMs: m.decl.MaxVMs,
			UsedSlots: used[m.id], CPUs: m.decl.CPUs, MemoryMiB: m.decl.MemoryMiB, Error: m.err}
		for template := range m.serves {
			entry.Templates = append(entry.Templates, template)
		}
		sort.Strings(entry.Templates)
		for template, reason := range m.refused {
			entry.RefusedTemplates[template] = reason
		}
		if !m.lastSeen.IsZero() {
			seen := m.lastSeen
			entry.LastSeen = &seen
		}
		if m.online {
			report.TotalSlots += m.decl.MaxVMs
			report.UsedSlots += used[m.id]
			report.FreeSlots += max(0, m.decl.MaxVMs-used[m.id])
		}
		report.Workers = append(report.Workers, entry)
	}
	for _, id := range s.unenrolled(rows) {
		report.Workers = append(report.Workers, workerCapacity{WorkerID: id, Templates: []string{}, RefusedTemplates: map[string]string{},
			UsedSlots: used[id], Error: "worker is not enrolled; its sandboxes are unconfirmed until it is enrolled again or forgotten"})
	}
	for template, registered := range s.templates.byID {
		entry := templateCapacity{TemplateID: template, Arch: registered.Arch}
		for _, m := range s.workers {
			if _, ok := m.serves[template]; ok && m.online {
				entry.TotalSlots += m.decl.MaxVMs
				entry.FreeSlots += max(0, m.decl.MaxVMs-used[m.id])
			}
		}
		report.Templates = append(report.Templates, entry)
	}
	sort.Slice(report.Templates, func(i, j int) bool { return report.Templates[i].TemplateID < report.Templates[j].TemplateID })
	jsonResponse(w, http.StatusOK, report)
}

// unenrolled returns, sorted, the identities that own live rows but are not
// enrolled in this gateway. Callers hold s.mu.
func (s *Service) unenrolled(rows []store.Row) []string {
	var ids []string
	for _, row := range rows {
		if s.byID[row.WorkerID] == nil && !slices.Contains(ids, row.WorkerID) {
			ids = append(ids, row.WorkerID)
		}
	}
	sort.Strings(ids)
	return ids
}

// sharing returns the unenrolled identities whose live VMs may sit on this
// host's slot networks: identities recorded as local, and identities with no
// enrollment record at all (ledgers written before workers were recorded), so
// renaming the local worker never double-books a physical slot. Callers hold
// s.mu.
func (s *Service) sharing(ctx context.Context, rows []store.Row) ([]string, error) {
	if s.localMember == nil {
		return nil, nil
	}
	ids := s.unenrolled(rows)
	if len(ids) == 0 {
		return nil, nil
	}
	identities, err := s.ledger.Identities(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ids, func(id string) bool {
		local, recorded := identities[id]
		return recorded && !local
	}), nil
}

type forgetRequest struct {
	Confirm bool `json:"confirm"`
}

// forgetResponse names every sandbox released without proof of teardown.
type forgetResponse struct {
	WorkerID   string   `json:"workerID"`
	Unverified []string `json:"unverified"`
}

func (s *Service) forget(w http.ResponseWriter, r *http.Request, id string) {
	var request forgetRequest
	if !readJSON(w, r, &request) || !request.Confirm || !validWorkerID(id) {
		apiError(w, http.StatusBadRequest, "forget-worker needs a valid worker ID and {\"confirm\":true}")
		return
	}
	ids, err := s.ForgetWorker(r.Context(), id)
	switch {
	case errors.Is(err, ErrWorkerOnline):
		apiError(w, http.StatusConflict, err.Error())
	case err != nil:
		unavailable(w)
	default:
		jsonResponse(w, http.StatusOK, forgetResponse{WorkerID: id, Unverified: append([]string{}, ids...)})
	}
}

// ErrWorkerOnline refuses to forget a worker the gateway can still observe.
var ErrWorkerOnline = errors.New("worker is enrolled and online; remove its -enroll and restart, or wait until it is offline")

// ForgetWorker releases every live reservation of a worker that is not
// online, without proof that its VMs are gone. The rows become
// "unverified" (never "gone") and stop holding capacity. If the worker is
// observed again, its VMs without live rows are destroyed and those rows are
// then resolved to gone.
func (s *Service) ForgetWorker(ctx context.Context, id string) ([]string, error) {
	if !validWorkerID(id) {
		return nil, fmt.Errorf("invalid worker ID %q", id)
	}
	m := s.byID[id]
	if m != nil {
		if err := m.pass.lock(ctx); err != nil { // No reconciliation of this worker runs concurrently.
			return nil, err
		}
		defer m.pass.unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m != nil && m.online {
		return nil, ErrWorkerOnline
	}
	ids, err := s.ledger.Forget(ctx, id)
	s.signersMu.Lock()
	for _, sandbox := range ids {
		delete(s.signers, sandbox)
	}
	s.signersMu.Unlock()
	for _, sandbox := range ids {
		log.Printf("forget-worker %s: sandbox %s released as destroyed-unverified; its VM was NOT proven gone", id, sandbox)
	}
	if err != nil {
		return ids, err
	}
	log.Printf("forget-worker %s: released %d reservation(s) without proof of teardown", id, len(ids))
	return ids, nil
}

// Guests routes guest file and process calls to the worker that owns each
// sandbox, under that worker's current lease.
//
// A call that fails before reaching a verdict on the guest (worker offline or
// unreachable, stream lost, worker owned by a newer gateway) wraps
// envd.ErrRetryable: the guest itself did not fail, so the data plane must
// keep the VM rather than abort it.
type Guests struct{ s *Service }

func (s *Service) Guests() *Guests { return &Guests{s: s} }

func (g *Guests) owner(ctx context.Context, id string) (*member, error) {
	g.s.mu.Lock()
	defer g.s.mu.Unlock()
	row, m, err := g.s.owned(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", envd.ErrRetryable, err)
	}
	if row.State != "running" || g.s.busy[id] != nil {
		return nil, fmt.Errorf("%w: sandbox not running", envd.ErrRetryable)
	}
	return m, nil
}

// classify marks transport and fencing failures retryable. A stale lease
// also takes the worker offline: a newer gateway owns it.
func (g *Guests) classify(m *member, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, worker.ErrStaleLease):
		_ = g.s.offline(m, err)
		return fmt.Errorf("%w: %w", envd.ErrRetryable, err)
	case errors.Is(err, worker.ErrUnavailable):
		return fmt.Errorf("%w: %w", envd.ErrRetryable, err)
	}
	return err
}

func (g *Guests) CopyIn(ctx context.Context, id, hostPath, guestPath string) error {
	m, err := g.owner(ctx, id)
	if err != nil {
		return err
	}
	return g.classify(m, m.api.CopyIn(ctx, id, hostPath, guestPath))
}

func (g *Guests) Run(ctx context.Context, id string, command vm.Command, stdout, stderr io.Writer) (int, error) {
	m, err := g.owner(ctx, id)
	if err != nil {
		return -1, err
	}
	code, err := m.api.Run(ctx, id, command, stdout, stderr)
	return code, g.classify(m, err)
}
