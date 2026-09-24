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
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// Config fixes the only permitted VM shape, template and public guest domain.
type Config struct {
	APIKey, TemplateID, Image, Domain, WorkerID string
	CPUs, MemoryMiB, MaxVMs                     int
	MaxTTL                                      time.Duration
}

type Service struct {
	mu      sync.Mutex
	ledger  *store.Store
	driver  vm.Driver
	cfg     Config
	apiHash [32]byte
	stop    chan struct{}
	done    chan struct{}
}

// Open creates the durable ledger before accepting any VM allocations. The
// background sweep reaps expired VMs even without incoming HTTP requests.
func Open(ctx context.Context, path string, driver vm.Driver, cfg Config) (*Service, error) {
	if driver == nil || cfg.APIKey == "" || strings.TrimSpace(cfg.TemplateID) == "" || strings.TrimSpace(cfg.Image) == "" || strings.TrimSpace(cfg.WorkerID) == "" ||
		cfg.Domain == "" || strings.ContainsAny(cfg.Domain, "/:*? #@\t\r\n") ||
		cfg.CPUs < 1 || cfg.CPUs > math.MaxInt32 || cfg.MemoryMiB < 128 || cfg.MemoryMiB > math.MaxInt32 ||
		cfg.MaxVMs < 1 || cfg.MaxTTL < time.Second || cfg.MaxTTL/time.Second > math.MaxInt32 {
		return nil, errors.New("invalid sandbox control configuration")
	}
	ledger, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	s := &Service{ledger: ledger, driver: driver, cfg: cfg, apiHash: sha256.Sum256([]byte(cfg.APIKey)), stop: make(chan struct{}), done: make(chan struct{})}
	s.cfg.APIKey = "" // never retain a second plaintext copy of the control key
	go s.sweep()
	return s, nil
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
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.mu.Lock()
			_ = s.reconcile(ctx)
			s.mu.Unlock()
			cancel()
		}
	}
}

// Authorize demands a current positive VM inventory observation, a live
// unexpired ledger row, the newest job attempt, and the sandbox-scoped token.
// Inconclusive inventory or a stopped VM never grants guest access.
func (s *Service) Authorize(id, token string) bool {
	if !validID(id) || token == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := s.ledger.Get(ctx, id)
	if err != nil || row.State != "running" || !time.Now().Before(row.Ends) {
		return false
	}
	current, err := s.ledger.Current(ctx, row)
	if err != nil || !current {
		return false
	}
	observed, err := s.driver.List(ctx)
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
	if matches != 1 || !running {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(row.TokenHash, hash[:]) == 1
}

// Abort revokes a canceled/failed guest execution before tearing down its VM.
// Failure leaves the reservation unknown for the periodic reconciliation sweep.
func (s *Service) Abort(ctx context.Context, id, token string) error {
	if !validID(id) || token == "" {
		return errors.New("invalid sandbox capability")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := s.ledger.Get(ctx, id)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(token))
	if row.State != "running" || row.WorkerID != s.cfg.WorkerID ||
		subtle.ConstantTimeCompare(row.TokenHash, hash[:]) != 1 {
		return errors.New("sandbox capability is no longer active")
	}
	stateErr := s.ledger.SetState(ctx, id, "unknown")
	destroyErr := s.driver.Destroy(ctx, id)
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
	return sandbox{ID: row.ID, TemplateID: row.TemplateID, StartedAt: row.Started, EndAt: row.Ends,
		CPUCount: s.cfg.CPUs, MemoryMB: s.cfg.MemoryMiB, DiskSizeMB: 10 * 1024,
		State: "running", EnvdVersion: "sandboxd-1", Metadata: metadata, Domain: s.cfg.Domain}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func unavailable(w http.ResponseWriter) {
	http.Error(w, "sandbox state unavailable", http.StatusServiceUnavailable)
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if !readJSON(w, r, &request) || request.TemplateID != s.cfg.TemplateID || !request.Secure || request.AutoPause || len(request.EnvVars) != 0 {
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
		TemplateID: s.cfg.TemplateID, Image: s.cfg.Image, WorkerID: s.cfg.WorkerID,
		Attempt: attempt, Generation: generation, Fence: request.Metadata["daemon_fencing_token"],
		Started: started, Ends: started.Add(ttl)}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcile(r.Context()); err != nil {
		unavailable(w)
		return
	}
	err = s.ledger.Reserve(r.Context(), row, s.cfg.MaxVMs)
	if errors.Is(err, store.ErrCapacity) || errors.Is(err, store.ErrStale) {
		http.Error(w, "sandbox capacity or owner conflict", http.StatusConflict)
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	instance, err := s.driver.Create(r.Context(), vm.Spec{ID: row.ID, Image: s.cfg.Image, CPUs: s.cfg.CPUs, MemoryMiB: s.cfg.MemoryMiB})
	if err != nil || instance.ID != row.ID || !instance.Running {
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
	response := struct {
		sandbox
		EnvdAccessToken string `json:"envdAccessToken"`
	}{sandbox: s.describe(row), EnvdAccessToken: token}
	jsonResponse(w, http.StatusCreated, response)
}

// reconcile uses only the driver's complete successful inventory. Unknown or
// failed observations never release a reservation, and only ledger-owned IDs
// may be passed to Destroy. All callers hold s.mu.
func (s *Service) reconcile(ctx context.Context) error {
	instances, err := s.driver.List(ctx)
	if err != nil {
		return err
	}
	rows, err := s.ledger.Active(ctx)
	if err != nil {
		return err
	}
	inventory := make(map[string]vm.Instance, len(instances))
	for _, instance := range instances {
		if instance.ID == "" {
			return errors.New("VM inventory contains empty ID")
		}
		if _, duplicate := inventory[instance.ID]; duplicate {
			return errors.New("VM inventory contains duplicate ID")
		}
		inventory[instance.ID] = instance
	}
	now := time.Now()
	for _, row := range rows {
		instance, exists := inventory[row.ID]
		// A failed Create can complete late; even a formerly running VM can
		// leave a job-owned volume after its container disappears. Confirm
		// allocation cleanup before marking absence.
		if !exists {
			if err := s.driver.Destroy(ctx, row.ID); err != nil {
				return err
			}
		}
		if !exists {
			if err := s.ledger.SetState(ctx, row.ID, "gone"); err != nil {
				return err
			}
			continue
		}
		current, err := s.ledger.Current(ctx, row)
		if err != nil {
			return err
		}
		if row.State == "running" && instance.Running && current && now.Before(row.Ends) {
			continue
		}
		if err := s.ledger.SetState(ctx, row.ID, "unknown"); err != nil {
			return err
		}
		if err := s.driver.Destroy(ctx, row.ID); err != nil {
			return err
		}
		if err := s.ledger.SetState(ctx, row.ID, "gone"); err != nil {
			return err
		}
	}
	return nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcile(r.Context()); err != nil {
		unavailable(w)
		return
	}
	rows, err := s.ledger.Active(r.Context())
	if err != nil {
		unavailable(w)
		return
	}
	result := make([]sandbox, 0, len(rows))
	for _, row := range rows {
		if row.State != "running" || row.TemplateID != s.cfg.TemplateID || row.Image != s.cfg.Image || row.WorkerID != s.cfg.WorkerID {
			unavailable(w)
			return
		}
		result = append(result, s.describe(row))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	w.Header().Set("X-Total-Running", strconv.Itoa(len(result)))
	start := sort.Search(len(result), func(i int) bool { return result[i].ID > token })
	page := result[start:]
	if len(page) > limit {
		page = page[:limit]
		w.Header().Set("X-Next-Token", page[len(page)-1].ID)
	}
	jsonResponse(w, http.StatusOK, page)
}

func (s *Service) live(ctx context.Context, id string) (store.Row, error) {
	if err := s.reconcile(ctx); err != nil {
		return store.Row{}, err
	}
	row, err := s.ledger.Get(ctx, id)
	if err != nil {
		return store.Row{}, err
	}
	if row.State == "gone" {
		return store.Row{}, sql.ErrNoRows
	}
	if row.State != "running" || row.TemplateID != s.cfg.TemplateID || row.Image != s.cfg.Image || row.WorkerID != s.cfg.WorkerID {
		return store.Row{}, errors.New("sandbox not running")
	}
	current, err := s.ledger.Current(ctx, row)
	if err != nil || !current {
		return store.Row{}, errors.New("sandbox owner superseded")
	}
	return row, nil
}

func statusFor(err error) int {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound
	}
	return http.StatusServiceUnavailable
}

func (s *Service) get(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := s.live(r.Context(), id)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.live(r.Context(), id); err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	if err := s.ledger.Extend(r.Context(), id, time.Now().UTC().Add(ttl)); err != nil {
		unavailable(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) delete(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcile(r.Context()); err != nil {
		unavailable(w)
		return
	}
	row, err := s.ledger.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	if row.State != "gone" {
		if err := s.ledger.SetState(r.Context(), id, "unknown"); err != nil {
			unavailable(w)
			return
		}
		if err := s.driver.Destroy(r.Context(), id); err != nil {
			unavailable(w)
			return
		}
		if err := s.ledger.SetState(r.Context(), id, "gone"); err != nil {
			unavailable(w)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) metrics(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.live(r.Context(), id); err != nil {
		http.Error(w, "sandbox unavailable", statusFor(err))
		return
	}
	meter, ok := s.driver.(vm.ResourceMeter)
	if !ok {
		http.Error(w, "VM metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	usage, err := meter.Usage(r.Context(), id)
	if err != nil {
		unavailable(w)
		return
	}
	jsonResponse(w, http.StatusOK, []map[string]any{{
		"timestampUnix": time.Now().Unix(),
		"cpuCount":      s.cfg.CPUs,
		"cpuUsedPct":    usage.CPUUsedPct,
		"memUsed":       usage.MemoryUsedBytes,
		"memTotal":      usage.MemoryLimitBytes,
	}})
}
