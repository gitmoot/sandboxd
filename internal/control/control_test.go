package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

type fakeDriver struct {
	mu          sync.Mutex
	instances   map[string]vm.Instance
	createError error
	listError   error
	destroyed   []string
}

func (d *fakeDriver) Create(_ context.Context, spec vm.Spec) (vm.Instance, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	instance := vm.Instance{ID: spec.ID, Running: true}
	d.instances[spec.ID] = instance
	return instance, d.createError
}
func (d *fakeDriver) List(context.Context) ([]vm.Instance, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.listError != nil {
		return nil, d.listError
	}
	out := make([]vm.Instance, 0, len(d.instances))
	for _, instance := range d.instances {
		out = append(out, instance)
	}
	return out, nil
}
func (d *fakeDriver) CopyIn(context.Context, string, string, string) error { return nil }
func (d *fakeDriver) Run(context.Context, string, vm.Command, io.Writer, io.Writer) (int, error) {
	return 0, nil
}
func (d *fakeDriver) Destroy(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.instances[id]; !ok {
		return errors.New("not owned by driver")
	}
	delete(d.instances, id)
	d.destroyed = append(d.destroyed, id)
	return nil
}

func openService(t *testing.T, driver *fakeDriver) *Service {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver,
		Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64", Domain: "sandbox.example", WorkerID: "mac-local", CPUs: 2, MemoryMiB: 512, MaxVMs: 1, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func request(t *testing.T, s *Service, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, path, input)
	r.Header.Set("X-API-Key", "control-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func createBody(job string, attempt int) map[string]any {
	return map[string]any{"templateID": "review-arm64", "timeout": 3600, "secure": true, "autoPause": false,
		"metadata": map[string]string{"job_id": job, "attempt": strconv.Itoa(attempt), "lifecycle_generation": "1"}}
}

func TestReservationFencingAndGuestAuthorization(t *testing.T) {
	d := &fakeDriver{instances: map[string]vm.Instance{"unrelated-vm": {ID: "unrelated-vm", Running: true}}}
	s := openService(t, d)
	first := request(t, s, http.MethodPost, "/sandboxes", createBody("job-A", 1))
	if first.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", first.Code, first.Body.String())
	}
	var created struct {
		ID    string `json:"sandboxID"`
		Token string `json:"envdAccessToken"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || !s.Authorize(created.ID, created.Token) || s.Authorize(created.ID, "wrong") {
		t.Fatal("guest token must authorize only its running VM")
	}
	row, err := s.ledger.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(created.Token))
	if !bytes.Equal(row.TokenHash, digest[:]) {
		t.Fatal("guest credential not stored as its SHA-256 digest")
	}
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-B", 1)); got.Code != http.StatusConflict {
		t.Fatalf("capacity bypass: %d", got.Code)
	}
	if got := request(t, s, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusOK || got.Header().Get("X-Total-Running") != "1" {
		t.Fatalf("inventory status %d, running %q", got.Code, got.Header().Get("X-Total-Running"))
	}
	d.mu.Lock()
	d.listError = errors.New("worker offline")
	d.mu.Unlock()
	if s.Authorize(created.ID, created.Token) {
		t.Fatal("unknown inventory authorized")
	}
	if got := request(t, s, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown inventory status %d", got.Code)
	}
	d.mu.Lock()
	d.listError = nil
	d.instances[created.ID] = vm.Instance{ID: created.ID, Running: false}
	d.mu.Unlock()
	if s.Authorize(created.ID, created.Token) {
		t.Fatal("stopped VM authorized")
	}
	if got := request(t, s, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusOK {
		t.Fatalf("stopped VM reconciliation status %d", got.Code)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.instances["unrelated-vm"]; !ok {
		t.Fatal("reconciliation destroyed unrelated VM")
	}
	for _, id := range d.destroyed {
		if id == "unrelated-vm" {
			t.Fatal("destroyed unrelated VM")
		}
	}
}

func TestAmbiguousCreateRetainsCapacityUntilInventoryResolves(t *testing.T) {
	d := &fakeDriver{instances: make(map[string]vm.Instance), createError: errors.New("response lost")}
	s := openService(t, d)
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-A", 1)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous create status %d", got.Code)
	}
	d.mu.Lock()
	d.listError = errors.New("worker offline")
	d.mu.Unlock()
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-B", 1)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown allocation must not bypass capacity: %d", got.Code)
	}
	d.mu.Lock()
	d.listError = nil
	d.createError = nil
	d.mu.Unlock()
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-B", 1)); got.Code != http.StatusCreated {
		t.Fatalf("capacity should recover after targeted cleanup: %d", got.Code)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.destroyed) != 1 {
		t.Fatalf("targeted cleanup count %d", len(d.destroyed))
	}
}

func TestInventoryPagesPreserveCompleteRunningSet(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	service, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver,
		Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64", Domain: "sandbox.example", WorkerID: "mac-local",
			CPUs: 2, MemoryMiB: 512, MaxVMs: 2, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	for _, job := range []string{"job-A", "job-B"} {
		if got := request(t, service, http.MethodPost, "/sandboxes", createBody(job, 1)); got.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", job, got.Code, got.Body.String())
		}
	}
	first := request(t, service, http.MethodGet, "/v2/sandboxes?limit=1", nil)
	token := first.Header().Get("X-Next-Token")
	if first.Code != http.StatusOK || token == "" || first.Header().Get("X-Total-Running") != "2" {
		t.Fatalf("incomplete first page: %d headers=%v", first.Code, first.Header())
	}
	second := request(t, service, http.MethodGet, "/v2/sandboxes?limit=1&nextToken="+token, nil)
	if second.Code != http.StatusOK || second.Header().Get("X-Next-Token") != "" || second.Header().Get("X-Total-Running") != "2" {
		t.Fatalf("incomplete terminal page: %d headers=%v", second.Code, second.Header())
	}
	var a, b []struct {
		ID string `json:"sandboxID"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 || a[0].ID == b[0].ID || a[0].ID != token {
		t.Fatalf("inventory lost or repeated a VM: first=%v second=%v", a, b)
	}
	if got := request(t, service, http.MethodGet, "/v2/sandboxes?limit=1&nextToken=bogus", nil); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid continuation accepted: %d", got.Code)
	}
}

func TestRestartDoesNotReassignLiveVMToNewWorker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	cfg := Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64",
		Domain: "sandbox.example", WorkerID: "mac-original", CPUs: 2, MemoryMiB: 512, MaxVMs: 1, MaxTTL: time.Hour}
	first, err := Open(context.Background(), path, driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	created := request(t, first, http.MethodPost, "/sandboxes", createBody("review-job", 1))
	if created.Code != http.StatusCreated {
		t.Fatalf("original allocation failed: %d", created.Code)
	}
	var sandbox struct {
		ID string `json:"sandboxID"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &sandbox); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.WorkerID = "mac-replacement"
	second, err := Open(context.Background(), path, driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := request(t, second, http.MethodGet, "/sandboxes/"+sandbox.ID, nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("reassigned old VM to replacement worker: %d", got.Code)
	}
	if got := request(t, second, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("false complete inventory for unknown worker: %d", got.Code)
	}
	if got := request(t, second, http.MethodPost, "/sandboxes", createBody("new-job", 1)); got.Code != http.StatusConflict {
		t.Fatalf("old worker VM released its capacity: %d", got.Code)
	}
}

func TestCanceledStreamRevokesOnlyItsVMCapability(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	service := openService(t, driver)
	created := request(t, service, http.MethodPost, "/sandboxes", createBody("job-cancel", 1))
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d", created.Code)
	}
	var payload struct {
		ID    string `json:"sandboxID"`
		Token string `json:"envdAccessToken"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if err := service.Abort(context.Background(), payload.ID, "wrong-capability"); err == nil || !service.Authorize(payload.ID, payload.Token) {
		t.Fatal("wrong capability destroyed or revoked another VM")
	}
	if err := service.Abort(context.Background(), payload.ID, payload.Token); err != nil {
		t.Fatal(err)
	}
	if service.Authorize(payload.ID, payload.Token) {
		t.Fatal("canceled VM capability remained live")
	}
	if got := request(t, service, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusOK || got.Body.String() != "[]\n" {
		t.Fatalf("destroyed VM remained in inventory: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, service, http.MethodPost, "/sandboxes", createBody("next-job", 1)); got.Code != http.StatusCreated {
		t.Fatalf("confirmed cancellation did not release capacity: %d", got.Code)
	}
}

func TestNewAttemptFencesOldGuestWithoutDeletingNewVM(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	service, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver,
		Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64",
			Domain: "sandbox.example", WorkerID: "mac-local", CPUs: 2, MemoryMiB: 512, MaxVMs: 2, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var first, second struct {
		ID    string `json:"sandboxID"`
		Token string `json:"envdAccessToken"`
	}
	created := request(t, service, http.MethodPost, "/sandboxes", createBody("same-job", 1))
	if created.Code != http.StatusCreated {
		t.Fatalf("initial attempt: %d", created.Code)
	}
	if err := json.Unmarshal(created.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	created = request(t, service, http.MethodPost, "/sandboxes", createBody("same-job", 2))
	if created.Code != http.StatusCreated {
		t.Fatalf("new attempt: %d", created.Code)
	}
	if err := json.Unmarshal(created.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || service.Authorize(first.ID, first.Token) || !service.Authorize(second.ID, second.Token) {
		t.Fatal("new attempt did not fence the old VM capability")
	}
	if got := request(t, service, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusOK || got.Header().Get("X-Total-Running") != "1" {
		t.Fatalf("stale attempt not reaped: %d %s", got.Code, got.Body.String())
	}
	if !service.Authorize(second.ID, second.Token) {
		t.Fatal("old attempt teardown revoked the new attempt")
	}
}
