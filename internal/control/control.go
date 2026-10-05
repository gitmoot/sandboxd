// Package control exposes the pinned Gitmoot E2B control-plane subset.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
	"github.com/gitmoot/sandboxd/internal/worker"
)

// Config fixes the permitted VM shapes, templates and public guest domain.
//
// The local fields (TemplateID, Image, WorkerID, CPUs, MemoryMiB, MaxVMs,
// Slots, Arch, DriverName) describe the in-process driver passed to Open, as
// in a single-worker deployment. Slots are that worker's dedicated guest
// networks, each used by at most one VM at a time; MaxVMs may not exceed
// them. Workers adds enrolled remote workers, which declare their own shape.
type Config struct {
	APIKey, TemplateID, Image, Domain, WorkerID string
	CPUs, MemoryMiB, MaxVMs                     int
	MaxTTL                                      time.Duration
	Slots                                       []string
	// Arch is the local worker's guest architecture; "" means runtime.GOARCH.
	Arch string
	// DriverName labels the local driver in capacity reports; "" means "local".
	DriverName string
	// Templates maps each additional servable template ID to the guest
	// architecture it requires. The local TemplateID requires Arch. A worker
	// is never scheduled a template it declares for another architecture.
	Templates map[string]string
	// Workers are enrolled remote workers, in scheduling-preference order
	// after the local worker.
	Workers []Remote
}

// Remote is one enrolled worker reached through its own transport.
type Remote struct {
	ID     string
	Member worker.Member
}

type Service struct {
	// mu guards the ledger, worker state and busy set. It is never held across
	// a worker call, so one slow or partitioned worker cannot stall the rest.
	mu        sync.Mutex
	ledger    *store.Store
	cfg       Config
	templates map[string]string // template ID -> required guest architecture
	workers   []*member
	byID      map[string]*member
	// localMember is the gateway's own driver, nil for a gateway without one.
	localMember *member
	// busy marks rows whose worker call (Create or Destroy) is in flight. They
	// are not judged by reconciliation or listed until the call settles; the
	// channel is closed when it does.
	busy    map[string]chan struct{}
	apiHash [32]byte
	stop    chan struct{}
	done    chan struct{}
}

// Open creates the durable ledger before accepting any VM allocations. The
// background sweep enrolls workers and reaps expired VMs even without incoming
// HTTP requests. driver may be nil for a gateway that runs no local VMs.
func Open(ctx context.Context, path string, driver vm.Driver, cfg Config) (*Service, error) {
	if cfg.APIKey == "" || cfg.Domain == "" || strings.ContainsAny(cfg.Domain, "/:*? #@\t\r\n") ||
		cfg.MaxTTL < time.Second || cfg.MaxTTL/time.Second > math.MaxInt32 {
		return nil, errors.New("invalid sandbox control configuration")
	}
	if driver == nil && len(cfg.Workers) == 0 {
		return nil, errors.New("sandbox control needs a local driver or an enrolled worker")
	}
	templates := make(map[string]string, len(cfg.Templates)+1)
	for template, arch := range cfg.Templates {
		if strings.TrimSpace(template) == "" || !validArch(arch) {
			return nil, fmt.Errorf("template %q must name an arm64 or amd64 architecture", template)
		}
		templates[template] = arch
	}
	var members []*member
	if driver != nil {
		if cfg.Arch == "" {
			cfg.Arch = runtime.GOARCH
		}
		if cfg.DriverName == "" {
			cfg.DriverName = "local"
		}
		if strings.TrimSpace(cfg.TemplateID) == "" || strings.TrimSpace(cfg.Image) == "" ||
			cfg.CPUs > math.MaxInt32 || cfg.MemoryMiB > math.MaxInt32 {
			return nil, errors.New("invalid sandbox control configuration")
		}
		for i, slot := range cfg.Slots {
			if strings.TrimSpace(slot) == "" || slices.Contains(cfg.Slots[:i], slot) {
				return nil, errors.New("sandbox network slots must be distinct and non-empty")
			}
		}
		decl := worker.Declaration{ID: cfg.WorkerID, Arch: cfg.Arch, Driver: cfg.DriverName,
			Templates: map[string]string{cfg.TemplateID: cfg.Image}, CPUs: cfg.CPUs, MemoryMiB: cfg.MemoryMiB,
			MaxVMs: cfg.MaxVMs, Slots: slices.Clone(cfg.Slots)}
		if err := decl.Validate(); err != nil {
			return nil, fmt.Errorf("invalid sandbox control configuration: %w", err)
		}
		if arch, ok := templates[cfg.TemplateID]; ok && arch != cfg.Arch {
			return nil, fmt.Errorf("template %q is registered for %s but the local worker runs %s", cfg.TemplateID, arch, cfg.Arch)
		}
		templates[cfg.TemplateID] = cfg.Arch
		members = append(members, newMember(cfg.WorkerID, worker.Local(driver, decl), true))
	}
	for _, remote := range cfg.Workers {
		if remote.Member == nil || !validWorkerID(remote.ID) {
			return nil, fmt.Errorf("invalid enrolled worker %q", remote.ID)
		}
		for _, existing := range members {
			if existing.id == remote.ID {
				return nil, fmt.Errorf("worker %q is enrolled twice", remote.ID)
			}
		}
		members = append(members, newMember(remote.ID, remote.Member, false))
	}
	ledger, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	s := &Service{ledger: ledger, cfg: cfg, templates: templates, workers: members, byID: make(map[string]*member, len(members)),
		busy: make(map[string]chan struct{}), apiHash: sha256.Sum256([]byte(cfg.APIKey)), stop: make(chan struct{}), done: make(chan struct{})}
	for _, m := range members {
		s.byID[m.id] = m
		if m.local {
			s.localMember = m
		}
	}
	s.cfg.APIKey = "" // never retain a second plaintext copy of the control key
	s.cfg.Workers = nil
	go s.sweep()
	return s, nil
}

// markBusy records that a worker call on row id is in flight. Callers hold
// s.mu and have checked that id is not busy.
func (s *Service) markBusy(id string) {
	if s.busy[id] == nil {
		s.busy[id] = make(chan struct{})
	}
}

// clearBusy records that the call on row id settled and wakes its waiters.
// Callers hold s.mu.
func (s *Service) clearBusy(id string) {
	if settled := s.busy[id]; settled != nil {
		close(settled)
		delete(s.busy, id)
	}
}

func (s *Service) Close() error {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ledger.Close()
}

func (s *Service) sweep() {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), workerTimeout)
		s.reconcileAll(ctx)
		cancel()
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
	}
}

// Authorize demands a current positive VM inventory observation from the
// sandbox's worker under its current lease, a live unexpired ledger row, the
// newest job attempt, and the sandbox-scoped token. Inconclusive inventory, a
// stopped VM or an offline worker never grants guest access.
func (s *Service) Authorize(id, token string) bool {
	if !validID(id) || token == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	row, m, err := s.owned(ctx, id)
	s.mu.Unlock()
	if err != nil || row.State != "running" || !time.Now().Before(row.Ends) {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(row.TokenHash, hash[:]) != 1 {
		return false
	}
	observed, err := m.api.List(ctx)
	if err != nil {
		return false
	}
	matches := 0
	running := false
	for _, instance := range observed {
		if instance.ID == id {
			matches++
			running = instance.Running
		}
	}
	return matches == 1 && running
}

// owned returns a sandbox's row and worker only while the row is the newest
// attempt of its job and was proven present under the worker's current lease.
// Callers hold s.mu.
func (s *Service) owned(ctx context.Context, id string) (store.Row, *member, error) {
	row, err := s.ledger.Get(ctx, id)
	if err != nil {
		return store.Row{}, nil, err
	}
	m := s.byID[row.WorkerID]
	if m == nil || !m.online || m.lease == 0 || row.Lease != m.lease {
		return store.Row{}, nil, errors.New("sandbox owner is not the current worker lease")
	}
	current, err := s.ledger.Current(ctx, row)
	if err != nil || !current {
		return store.Row{}, nil, errors.New("sandbox owner superseded")
	}
	return row, m, nil
}

// Abort revokes a canceled/failed guest execution before tearing down its VM.
// Failure leaves the reservation unknown for the periodic reconciliation sweep.
func (s *Service) Abort(ctx context.Context, id, token string) error {
	if !validID(id) || token == "" {
		return errors.New("invalid sandbox capability")
	}
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	m := s.byID[row.WorkerID]
	hash := sha256.Sum256([]byte(token))
	if row.State != "running" || m == nil || subtle.ConstantTimeCompare(row.TokenHash, hash[:]) != 1 {
		s.mu.Unlock()
		return errors.New("sandbox capability is no longer active")
	}
	stateErr := s.ledger.SetState(ctx, id, "unknown")
	s.markBusy(id)
	s.mu.Unlock()
	destroyCtx, cancel := context.WithTimeout(ctx, workerSlowTimeout)
	destroyErr := m.api.Destroy(destroyCtx, id)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearBusy(id)
	if destroyErr != nil {
		return errors.Join(stateErr, destroyErr)
	}
	return errors.Join(stateErr, s.ledger.SetState(ctx, id, "gone"))
}

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serve) }

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	keys := r.Header.Values("X-API-Key")
	if len(keys) != 1 || subtle.ConstantTimeCompare(s.apiHash[:], hashKey(keys[0])) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	if path == "/sandboxes" && r.Method == http.MethodPost {
		s.create(w, r)
		return
	}
	if path == "/v2/sandboxes" && r.Method == http.MethodGet {
		s.list(w, r)
		return
	}
	if path == "/sandboxd/capacity" && r.Method == http.MethodGet {
		s.capacity(w, r)
		return
	}
	if rest, ok := strings.CutPrefix(path, "/sandboxd/workers/"); ok && r.Method == http.MethodPost {
		if id, ok := strings.CutSuffix(rest, "/forget"); ok {
			s.forget(w, r, id)
			return
		}
	}
	if !strings.HasPrefix(path, "/sandboxes/") {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/sandboxes/"), "/")
	if len(parts) < 1 || !validID(parts[0]) {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.get(w, r, id)
		case http.MethodDelete:
			s.delete(w, r, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "timeout" && r.Method == http.MethodPost {
		s.renew(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "metrics" && r.Method == http.MethodGet {
		s.metrics(w, r, id)
		return
	}
	http.NotFound(w, r)
}

func hashKey(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func validID(id string) bool {
	if len(id) != 41 || !strings.HasPrefix(id, "sandboxd-") {
		return false
	}
	for _, char := range id[9:] {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type createRequest struct {
	TemplateID string            `json:"templateID"`
	Timeout    int64             `json:"timeout"`
	AutoPause  bool              `json:"autoPause"`
	Secure     bool              `json:"secure"`
	Metadata   map[string]string `json:"metadata"`
	EnvVars    map[string]string `json:"envVars"`
}

type timeoutRequest struct {
	Timeout int64 `json:"timeout"`
}

func decode(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return decoder.Decode(new(any)) // must be EOF, not a second JSON value
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	err := decode(w, r, value)
	return errors.Is(err, io.EOF)
}

func (s *Service) ttl(seconds int64) (time.Duration, bool) {
	if seconds <= 0 || seconds > math.MaxInt32 || seconds > int64(s.cfg.MaxTTL/time.Second) {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// sandbox is the complete list schema required by the pinned Gitmoot client.
type sandbox struct {
	ID          string            `json:"sandboxID"`
	TemplateID  string            `json:"templateID"`
	StartedAt   time.Time         `json:"startedAt"`
	EndAt       time.Time         `json:"endAt"`
	CPUCount    int               `json:"cpuCount"`
	MemoryMB    int               `json:"memoryMB"`
	DiskSizeMB  int               `json:"diskSizeMB"`
	State       string            `json:"state"`
	EnvdVersion string            `json:"envdVersion"`
	Metadata    map[string]string `json:"metadata"`
	Domain      string            `json:"domain"`
}

func (s *Service) describe(row store.Row) sandbox {
	var metadata map[string]string
	_ = json.Unmarshal([]byte(row.Metadata), &metadata)
	cpus, memory := row.CPUs, row.MemoryMiB
	if cpus == 0 || memory == 0 { // recorded before rows carried their VM shape
		cpus, memory = s.cfg.CPUs, s.cfg.MemoryMiB
	}
	return sandbox{ID: row.ID, TemplateID: row.TemplateID, StartedAt: row.Started, EndAt: row.Ends,
		CPUCount: cpus, MemoryMB: memory, DiskSizeMB: 10 * 1024,
		State: "running", EnvdVersion: "sandboxd-1", Metadata: metadata, Domain: s.cfg.Domain}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// apiError writes the E2B API error shape {"code","message"}.
func apiError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{status, message})
}

func unavailable(w http.ResponseWriter) {
	http.Error(w, "sandbox state unavailable", http.StatusServiceUnavailable)
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if !readJSON(w, r, &request) || !request.Secure || request.AutoPause || len(request.EnvVars) != 0 {
		http.Error(w, "unsupported sandbox request", http.StatusBadRequest)
		return
	}
	if _, known := s.templates[request.TemplateID]; !known {
		http.Error(w, "unsupported sandbox request", http.StatusBadRequest)
		return
	}
	ttl, ok := s.ttl(request.Timeout)
	if !ok {
		http.Error(w, "invalid sandbox timeout", http.StatusBadRequest)
		return
	}
	job := strings.TrimSpace(request.Metadata["job_id"])
	attempt, attemptErr := strconv.ParseInt(request.Metadata["attempt"], 10, 64)
	generation, generationErr := strconv.ParseInt(request.Metadata["lifecycle_generation"], 10, 64)
	if job == "" || len(job) > 256 || attemptErr != nil || attempt < 1 || generationErr != nil || generation < 0 {
		http.Error(w, "invalid sandbox owner metadata", http.StatusBadRequest)
		return
	}
	metadata, err := json.Marshal(request.Metadata)
	if err != nil {
		http.Error(w, "invalid metadata", http.StatusBadRequest)
		return
	}
	idBytes, err := randomHex(16)
	if err != nil {
		unavailable(w)
		return
	}
	token, err := randomHex(32)
	if err != nil {
		unavailable(w)
		return
	}
	hash := sha256.Sum256([]byte(token))
	started := time.Now().UTC()
	row := store.Row{ID: "sandboxd-" + idBytes, TokenHash: hash[:], Metadata: string(metadata), JobID: job,
		TemplateID: request.TemplateID, Attempt: attempt, Generation: generation, Fence: request.Metadata["daemon_fencing_token"],
		Started: started, Ends: started.Add(ttl)}

	reconcileCtx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	s.reconcileAll(reconcileCtx)
	cancel()
	s.mu.Lock()
	m, spec, err := s.admit(r.Context(), &row)
	if err != nil {
		s.mu.Unlock()
		var refusal *refusal
		switch {
		case errors.As(err, &refusal):
			apiError(w, refusal.status, refusal.message)
		default:
			// Includes store.ErrLegacySlot: a live pre-slot row blocks admission
			// until reconciliation proves it gone.
			unavailable(w)
		}
		return
	}
	s.markBusy(row.ID)
	s.mu.Unlock()

	createCtx, cancel := context.WithTimeout(r.Context(), workerSlowTimeout)
	instance, err := m.api.CreateUntil(createCtx, spec, row.Ends)
	cancel()
	if errors.Is(err, worker.ErrStaleLease) {
		_ = s.offline(m, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearBusy(row.ID)
	// A worker that another gateway instance took over while this Create was
	// in flight answered outside this gateway's lease. Its answer cannot admit
	// the VM. A worker that merely blipped keeps this gateway's lease.
	fenced := m.superseded || m.lease != row.Lease
	if err != nil || fenced || instance.ID != row.ID || !instance.Running {
		// A failed Create can have allocated a VM. Never release this reservation
		// until a complete inventory or a successful targeted destroy proves absence.
		_ = s.ledger.SetState(context.Background(), row.ID, "unknown")
		unavailable(w)
		return
	}
	if err := s.ledger.SetState(context.Background(), row.ID, "running"); err != nil {
		unavailable(w)
		return
	}
	row.State = "running"
	response := struct {
		sandbox
		EnvdAccessToken string `json:"envdAccessToken"`
	}{sandbox: s.describe(row), EnvdAccessToken: token}
	jsonResponse(w, http.StatusCreated, response)
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if values, ok := r.URL.Query()["limit"]; ok {
		if len(values) != 1 {
			http.Error(w, "invalid page limit", http.StatusBadRequest)
			return
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > 100 {
			http.Error(w, "invalid page limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	token := r.URL.Query().Get("nextToken")
	if _, ok := r.URL.Query()["nextToken"]; ok && !validID(token) {
		http.Error(w, "invalid next token", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	s.reconcileAll(ctx)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	var offline []string
	for _, m := range s.workers {
		if !m.online {
			offline = append(offline, m.id)
		}
	}
	// With no worker observed there is no inventory at all, only guesses.
	if len(offline) == len(s.workers) {
		unavailable(w)
		return
	}
	rows, err := s.ledger.Active(r.Context())
	if err != nil {
		unavailable(w)
		return
	}
	// A worker that is no longer enrolled is reported like an offline one.
	offline = append(offline, s.unenrolled(rows)...)
	result := make([]sandbox, 0, len(rows))
	for _, row := range rows {
		if s.busy[row.ID] != nil {
			continue // Create or Destroy in flight: not yet, or no longer, a sandbox.
		}
		m := s.byID[row.WorkerID]
		if m == nil || !m.online {
			// The worker's last known running sandboxes stay listed: an offline
			// or removed worker neither strands nor silently drops them. The
			// header below says this part of the inventory is unconfirmed.
			if row.State == "running" {
				result = append(result, s.describe(row))
			}
			continue
		}
		if row.State != "running" || m.serves[row.TemplateID] != row.Image {
			unavailable(w)
			return
		}
		result = append(result, s.describe(row))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(offline) > 0 {
		w.Header().Set("X-Sandboxd-Offline-Workers", strings.Join(offline, ","))
	}
	w.Header().Set("X-Total-Running", strconv.Itoa(len(result)))
	start := sort.Search(len(result), func(i int) bool { return result[i].ID > token })
	page := result[start:]
	if len(page) > limit {
		page = page[:limit]
		w.Header().Set("X-Next-Token", page[len(page)-1].ID)
	}
	jsonResponse(w, http.StatusOK, page)
}

// live reconciles the sandbox's own worker and returns its row only while it
// is running, current and owned under the worker's current lease.
func (s *Service) live(ctx context.Context, id string) (store.Row, *member, error) {
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	m := s.byID[row.WorkerID]
	s.mu.Unlock()
	if err != nil {
		return store.Row{}, nil, err
	}
	if released(row) {
		return store.Row{}, nil, sql.ErrNoRows
	}
	if m == nil {
		return store.Row{}, nil, errors.New("sandbox worker is not enrolled")
	}
	if err := s.reconcile(ctx, m); err != nil {
		return store.Row{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, err = s.ledger.Get(ctx, id); err != nil {
		return store.Row{}, nil, err
	}
	if released(row) {
		return store.Row{}, nil, sql.ErrNoRows
	}
	if row.State != "running" || s.busy[id] != nil || m.serves[row.TemplateID] != row.Image {
		return store.Row{}, nil, errors.New("sandbox not running")
	}
	if row, m, err = s.owned(ctx, id); err != nil {
		return store.Row{}, nil, err
	}
	return row, m, nil
}

// released reports a row that no longer holds a reservation: proven gone, or
// released by forget-worker without proof (its VM is then no longer managed).
func released(row store.Row) bool { return row.State == "gone" || row.State == "unverified" }

func statusFor(err error) int {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound
	}
	return http.StatusServiceUnavailable
}

func (s *Service) get(w http.ResponseWriter, r *http.Request, id string) {
	row, _, err := s.live(r.Context(), id)
	if err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	jsonResponse(w, http.StatusOK, s.describe(row))
}

func (s *Service) renew(w http.ResponseWriter, r *http.Request, id string) {
	var request timeoutRequest
	if !readJSON(w, r, &request) {
		http.Error(w, "invalid timeout", http.StatusBadRequest)
		return
	}
	ttl, ok := s.ttl(request.Timeout)
	if !ok {
		http.Error(w, "invalid timeout", http.StatusBadRequest)
		return
	}
	_, m, err := s.live(r.Context(), id)
	if err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	ends := time.Now().UTC().Add(ttl)
	// The worker enforces end times on its own; it must learn the new one
	// before the ledger promises it. m.expiry keeps a concurrent
	// reconciliation from re-sending the older end time; it is held only for
	// this one bounded call, never across the worker's reconciliation.
	ctx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	defer cancel()
	if err := m.expiry.lock(ctx); err != nil {
		unavailable(w)
		return
	}
	defer m.expiry.unlock()
	if err := m.api.Expire(ctx, id, ends); err != nil {
		unavailable(w)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ledger.Extend(r.Context(), id, ends); err != nil {
		unavailable(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// delete confirms teardown through the sandbox's own worker. An offline
// worker leaves the reservation in place (503) until teardown is proven.
func (s *Service) delete(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	row, err := s.ledger.Get(r.Context(), id)
	m := s.byID[row.WorkerID]
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	if released(row) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if m == nil {
		unavailable(w)
		return
	}
	if err := s.reconcile(r.Context(), m); err != nil {
		unavailable(w)
		return
	}
	// The busy mark set below, not the worker's reconciliation turn, keeps a
	// concurrent reconciliation from judging this row while Destroy runs. A
	// teardown already in flight (an Abort, a reconciliation, another delete)
	// is waited for, bounded, and decides: deleting stays idempotent.
	waitCtx, cancelWait := context.WithTimeout(r.Context(), workerSlowTimeout)
	defer cancelWait()
	s.mu.Lock()
	for {
		row, err = s.ledger.Get(r.Context(), id)
		if err != nil || released(row) {
			s.mu.Unlock()
			if err != nil {
				unavailable(w)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		settled := s.busy[id]
		if settled == nil {
			break
		}
		s.mu.Unlock()
		select {
		case <-settled:
		case <-waitCtx.Done():
			unavailable(w) // still in flight: the reservation stays held
			return
		}
		s.mu.Lock()
	}
	if err := s.ledger.SetState(r.Context(), id, "unknown"); err != nil {
		s.mu.Unlock()
		unavailable(w)
		return
	}
	s.markBusy(id)
	s.mu.Unlock()
	destroyCtx, cancel := context.WithTimeout(r.Context(), workerSlowTimeout)
	destroyErr := m.api.Destroy(destroyCtx, id)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearBusy(id)
	if destroyErr != nil {
		unavailable(w)
		return
	}
	if err := s.ledger.SetState(r.Context(), id, "gone"); err != nil {
		unavailable(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) metrics(w http.ResponseWriter, r *http.Request, id string) {
	row, m, err := s.live(r.Context(), id)
	if err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	usageCtx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	defer cancel()
	usage, err := m.api.Usage(usageCtx, id)
	if errors.Is(err, worker.ErrNoMetrics) {
		http.Error(w, "VM metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	jsonResponse(w, http.StatusOK, []map[string]any{{
		"timestampUnix": time.Now().Unix(),
		"cpuCount":      s.describe(row).CPUCount,
		"cpuUsedPct":    usage.CPUUsedPct,
		"memUsed":       usage.MemoryUsedBytes,
		"memTotal":      usage.MemoryLimitBytes,
	}})
}
