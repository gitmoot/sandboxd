package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
	"github.com/gitmoot/sandboxd/internal/worker"
)

// fileDriver is a fake worker driver whose guests have real, separate
// filesystems under one host directory per worker.
type fileDriver struct {
	root string

	mu        sync.Mutex
	instances map[string]vm.Instance
	destroyed []string
	// createGate, when set, holds Create until it is closed; createEntered
	// then reports that a Create reached the driver.
	createGate    chan struct{}
	createEntered chan struct{}
	runStarted    chan struct{}
}

func newFileDriver(t *testing.T) *fileDriver {
	return &fileDriver{root: t.TempDir(), instances: make(map[string]vm.Instance),
		createEntered: make(chan struct{}, 8), runStarted: make(chan struct{}, 8)}
}

func (d *fileDriver) Create(ctx context.Context, spec vm.Spec) (vm.Instance, error) {
	d.mu.Lock()
	gate := d.createGate
	d.mu.Unlock()
	if gate != nil {
		d.createEntered <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return vm.Instance{}, ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Join(d.root, spec.ID), 0o700); err != nil {
		return vm.Instance{}, err
	}
	instance := vm.Instance{ID: spec.ID, Running: true, Network: spec.Network}
	d.instances[spec.ID] = instance
	return instance, nil
}

func (d *fileDriver) List(context.Context) ([]vm.Instance, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]vm.Instance, 0, len(d.instances))
	for _, instance := range d.instances {
		result = append(result, instance)
	}
	return result, nil
}

func (d *fileDriver) guestPath(id, guestPath string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.instances[id]; !ok {
		return "", fmt.Errorf("VM %s is not on this worker", id)
	}
	return filepath.Join(d.root, id, filepath.FromSlash(guestPath)), nil
}

func (d *fileDriver) CopyIn(_ context.Context, id, hostPath, guestPath string) error {
	target, err := d.guestPath(id, guestPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o600)
}

// Run understands "cat <path>" and "block" (wait until canceled).
func (d *fileDriver) Run(ctx context.Context, id string, cmd vm.Command, stdout, stderr io.Writer) (int, error) {
	if _, err := d.guestPath(id, "/"); err != nil {
		return -1, err
	}
	switch {
	case len(cmd.Args) == 2 && cmd.Args[0] == "cat":
		target, err := d.guestPath(id, cmd.Args[1])
		if err != nil {
			return -1, err
		}
		data, err := os.ReadFile(target)
		if err != nil {
			_, _ = io.WriteString(stderr, "cat: no such file\n")
			return 1, nil
		}
		_, err = stdout.Write(data)
		return 0, err
	case len(cmd.Args) == 1 && cmd.Args[0] == "block":
		d.runStarted <- struct{}{}
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return 127, nil
}

func (d *fileDriver) Destroy(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.instances, id)
	d.destroyed = append(d.destroyed, id)
	return os.RemoveAll(filepath.Join(d.root, id))
}

func (d *fileDriver) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.instances)
}

func (d *fileDriver) has(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.instances[id]
	return ok
}

func (d *fileDriver) destroyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.destroyed)
}

// fakeWorker serves a fileDriver through the real authenticated worker API
// over HTTP, and can be partitioned from the gateway.
type fakeWorker struct {
	id     string
	driver *fileDriver
	down   atomic.Bool
	client *worker.Client
}

const fakeWorkerKey = "worker-key-0123456789abcdef"

func newFakeWorker(t *testing.T, id, arch string, templates map[string]string, maxVMs int) *fakeWorker {
	t.Helper()
	w := &fakeWorker{id: id, driver: newFileDriver(t)}
	slots := make([]string, maxVMs)
	for i := range slots {
		// The same names on every worker: slots are worker-local networks.
		slots[i] = fmt.Sprintf("slot-%d", i+1)
	}
	server, err := worker.NewServer(w.driver, worker.Declaration{ID: id, Arch: arch, Driver: "fake", Templates: templates,
		CPUs: 2, MemoryMiB: 512, MaxVMs: maxVMs, Slots: slots}, fakeWorkerKey)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.down.Load() {
			http.Error(rw, "partitioned", http.StatusBadGateway)
			return
		}
		server.ServeHTTP(rw, r)
	}))
	t.Cleanup(httpServer.Close)
	if w.client, err = worker.NewClient(id, httpServer.URL, fakeWorkerKey, httpServer.Client()); err != nil {
		t.Fatal(err)
	}
	return w
}

var (
	arm64Templates = map[string]string{"review-arm64": "linux-arm64"}
	amd64Templates = map[string]string{"review-amd64": "linux-amd64"}
	gatewayArchs   = map[string]string{"review-arm64": "arm64", "review-amd64": "amd64"}
)

// openGateway runs a gateway with no local driver over the given workers.
func openGateway(t *testing.T, path string, workers ...*fakeWorker) *Service {
	t.Helper()
	s := startGateway(t, path, workers...)
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

// startGateway is openGateway for a gateway the test closes itself.
func startGateway(t *testing.T, path string, workers ...*fakeWorker) *Service {
	t.Helper()
	remotes := make([]Remote, len(workers))
	for i, w := range workers {
		remotes[i] = Remote{ID: w.id, Member: w.client}
	}
	s, err := Open(context.Background(), path, nil, Config{APIKey: "control-secret", Domain: "sandbox.example",
		MaxTTL: time.Hour, Templates: gatewayArchs, Workers: remotes})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func createFor(template, job string, attempt int) map[string]any {
	body := createBody(job, attempt)
	body["templateID"] = template
	return body
}

type created struct {
	ID    string `json:"sandboxID"`
	Token string `json:"envdAccessToken"`
}

func mustCreate(t *testing.T, s *Service, body map[string]any) created {
	t.Helper()
	got := request(t, s, http.MethodPost, "/sandboxes", body)
	if got.Code != http.StatusCreated {
		t.Fatalf("create %v: %d %s", body["metadata"], got.Code, got.Body.String())
	}
	var c created
	if err := json.Unmarshal(got.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func readCapacity(t *testing.T, s *Service) capacityReport {
	t.Helper()
	got := request(t, s, http.MethodGet, "/sandboxd/capacity", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("capacity: %d %s", got.Code, got.Body.String())
	}
	var report capacityReport
	if err := json.Unmarshal(got.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func workerReport(t *testing.T, report capacityReport, id string) workerCapacity {
	t.Helper()
	for _, w := range report.Workers {
		if w.WorkerID == id {
			return w
		}
	}
	t.Fatalf("worker %s missing from capacity report %+v", id, report)
	return workerCapacity{}
}

func assertCapacityFull(t *testing.T, got *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if got.Code != http.StatusConflict || json.Unmarshal(got.Body.Bytes(), &body) != nil ||
		body.Code != http.StatusConflict || !strings.Contains(body.Message, "capacity exhausted") {
		t.Fatalf("want E2B-shaped 409 capacity error, got %d %s", got.Code, got.Body.String())
	}
}

func catGuest(t *testing.T, s *Service, id, path string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, err := s.Guests().Run(context.Background(), id, vm.Command{Args: []string{"cat", path}}, &stdout, &stderr)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("exit %d: %s", code, stderr.String())
	}
	return stdout.String(), nil
}

func TestConcurrentCreatesSpreadAcrossWorkersWithoutCrossVisibility(t *testing.T) {
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 2)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 2)
	s := openGateway(t, filepath.Join(t.TempDir(), "ledger.sqlite"), a, b)

	jobs := []string{"job-1", "job-2", "job-3", "job-4"}
	results := make(chan created, len(jobs))
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", job, 1))
			var c created
			if got.Code != http.StatusCreated || json.Unmarshal(got.Body.Bytes(), &c) != nil {
				t.Errorf("concurrent create %s: %d %s", job, got.Code, got.Body.String())
			}
			results <- c
		}()
	}
	wg.Wait()
	close(results)
	if t.Failed() {
		t.FailNow()
	}
	if a.driver.count() != 2 || b.driver.count() != 2 {
		t.Fatalf("4 creates not spread over two 2-slot workers: a=%d b=%d", a.driver.count(), b.driver.count())
	}

	// Every sandbox gets its own secret, uploaded and read back through the
	// gateway's guest router.
	secrets := make(map[string]string)
	for c := range results {
		secret := "secret-of-" + c.ID
		host := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(host, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Guests().CopyIn(context.Background(), c.ID, host, "/home/user/secret"); err != nil {
			t.Fatalf("copy into %s: %v", c.ID, err)
		}
		if !s.Authorize(c.ID, c.Token) {
			t.Fatalf("sandbox %s not authorized on its worker", c.ID)
		}
		secrets[c.ID] = secret
	}
	for id, secret := range secrets {
		got, err := catGuest(t, s, id, "/home/user/secret")
		if err != nil || got != secret {
			t.Fatalf("sandbox %s read %q, %v; want its own secret", id, got, err)
		}
	}
	// No worker's disk holds a secret of a sandbox that runs on another worker.
	for _, w := range []*fakeWorker{a, b} {
		err := filepath.WalkDir(w.driver.root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for id, secret := range secrets {
				if string(data) == secret && !w.driver.has(id) {
					t.Errorf("worker %s holds the secret of %s, which runs elsewhere", w.id, id)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A guest call for a sandbox can only reach the worker that owns it: the
	// other worker does not know the VM even when asked directly.
	for id := range secrets {
		other := b
		if b.driver.has(id) {
			other = a
		}
		if _, err := other.driver.Run(context.Background(), id, vm.Command{Args: []string{"cat", "/home/user/secret"}}, io.Discard, io.Discard); err == nil {
			t.Fatalf("worker %s served sandbox %s it does not own", other.id, id)
		}
	}

	report := readCapacity(t, s)
	if report.TotalSlots != 4 || report.UsedSlots != 4 || report.FreeSlots != 0 || len(report.Workers) != 2 {
		t.Fatalf("capacity after filling the cluster: %+v", report)
	}
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-5", 1)))
	if a.driver.count()+b.driver.count() != 4 {
		t.Fatal("a refused create allocated a VM")
	}
	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Code != http.StatusOK || list.Header().Get("X-Total-Running") != "4" || list.Header().Get("X-Sandboxd-Offline-Workers") != "" {
		t.Fatalf("merged inventory: %d %v %s", list.Code, list.Header(), list.Body.String())
	}
}

func TestFullClusterReturnsCapacityErrorAndFreesOnDelete(t *testing.T) {
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 1)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 1)
	s := openGateway(t, filepath.Join(t.TempDir(), "ledger.sqlite"), a, b)
	first := mustCreate(t, s, createFor("review-arm64", "job-1", 1))
	mustCreate(t, s, createFor("review-arm64", "job-2", 1))
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-3", 1)))
	if report := readCapacity(t, s); report.FreeSlots != 0 || len(report.Templates) != 2 ||
		report.Templates[0].TemplateID != "review-amd64" || report.Templates[0].TotalSlots != 0 ||
		report.Templates[1].TemplateID != "review-arm64" || report.Templates[1].TotalSlots != 2 || report.Templates[1].FreeSlots != 0 {
		t.Fatalf("full cluster capacity: %+v", report)
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+first.ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", got.Code)
	}
	if report := readCapacity(t, s); report.FreeSlots != 1 {
		t.Fatalf("delete did not free a slot: %+v", report)
	}
	mustCreate(t, s, createFor("review-arm64", "job-3", 1))
}

func TestArchMismatchIsRefused(t *testing.T) {
	// An amd64 worker that claims to serve the arm64 template.
	wrong := newFakeWorker(t, "linux-amd64", "amd64", map[string]string{"review-arm64": "linux-arm64", "review-amd64": "linux-amd64"}, 3)
	s := openGateway(t, filepath.Join(t.TempDir(), "ledger.sqlite"), wrong)
	got := request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-1", 1))
	if got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "architecture mismatch") {
		t.Fatalf("arm64 template on amd64 worker: %d %s", got.Code, got.Body.String())
	}
	if wrong.driver.count() != 0 {
		t.Fatal("a refused template allocated a VM")
	}
	report := readCapacity(t, s)
	entry := workerReport(t, report, "linux-amd64")
	if !strings.Contains(entry.RefusedTemplates["review-arm64"], "architecture mismatch") ||
		len(entry.Templates) != 1 || entry.Templates[0] != "review-amd64" || entry.Arch != "amd64" {
		t.Fatalf("mismatch not visible to the operator: %+v", entry)
	}
	// The worker still runs the template that matches its architecture.
	mustCreate(t, s, createFor("review-amd64", "job-2", 1))
	if wrong.driver.count() != 1 {
		t.Fatal("matching template not scheduled")
	}

	// With a compatible worker enrolled too, arm64 work goes only there, even
	// though the mismatched worker has more free slots.
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	mac := newFakeWorker(t, "mac", "arm64", arm64Templates, 1)
	linux := newFakeWorker(t, "linux", "amd64", map[string]string{"review-arm64": "linux-arm64"}, 3)
	s = openGateway(t, path, linux, mac)
	mustCreate(t, s, createFor("review-arm64", "job-3", 1))
	if mac.driver.count() != 1 || linux.driver.count() != 0 {
		t.Fatalf("arm64 job placed by free slots, not architecture: mac=%d linux=%d", mac.driver.count(), linux.driver.count())
	}
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-4", 1)))
	if linux.driver.count() != 0 {
		t.Fatal("full compatible worker spilled onto a mismatched worker")
	}
}

func TestRemovingWorkerNeitherStrandsNorDuplicatesSandboxes(t *testing.T) {
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 3)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 3)
	s := openGateway(t, filepath.Join(t.TempDir(), "ledger.sqlite"), a, b)
	var onA, onB []created
	for i := range 4 {
		c := mustCreate(t, s, createFor("review-arm64", fmt.Sprintf("job-%d", i), 1))
		if a.driver.has(c.ID) {
			onA = append(onA, c)
		} else {
			onB = append(onB, c)
		}
	}
	if len(onA) != 2 || len(onB) != 2 {
		t.Fatalf("placement a=%d b=%d", len(onA), len(onB))
	}

	b.down.Store(true) // worker-b is removed from the network.
	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Code != http.StatusOK || list.Header().Get("X-Sandboxd-Offline-Workers") != "worker-b" || list.Header().Get("X-Total-Running") != "4" {
		t.Fatalf("offline worker hidden or its sandboxes dropped: %d %v %s", list.Code, list.Header(), list.Body.String())
	}
	report := readCapacity(t, s)
	if entry := workerReport(t, report, "worker-b"); entry.Online || entry.Error == "" || entry.UsedSlots != 2 {
		t.Fatalf("offline worker not visible: %+v", entry)
	}
	if report.TotalSlots != 3 || report.FreeSlots != 1 {
		t.Fatalf("offline worker's slots still offered: %+v", report)
	}
	for _, c := range onA {
		if !s.Authorize(c.ID, c.Token) {
			t.Fatalf("worker-a sandbox %s stranded by worker-b's removal", c.ID)
		}
		if got := request(t, s, http.MethodGet, "/sandboxes/"+c.ID, nil); got.Code != http.StatusOK {
			t.Fatalf("worker-a sandbox %s: %d", c.ID, got.Code)
		}
	}
	for _, c := range onB {
		if s.Authorize(c.ID, c.Token) {
			t.Fatalf("unobservable worker-b sandbox %s authorized", c.ID)
		}
		if got := request(t, s, http.MethodGet, "/sandboxes/"+c.ID, nil); got.Code != http.StatusServiceUnavailable {
			t.Fatalf("worker-b sandbox %s reported %d, not unknown", c.ID, got.Code)
		}
	}
	// A retry of one of worker-b's jobs lands on worker-a; the remaining free
	// slot is then the only one, and nothing is placed on worker-b.
	retry := mustCreate(t, s, createFor("review-arm64", jobOf(t, s, onB[0].ID), 2))
	if !a.driver.has(retry.ID) {
		t.Fatal("retry not placed on the remaining worker")
	}
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-new", 1)))
	// Deleting worker-b's sandbox while it is away holds its reservation.
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+onB[1].ID, nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete on offline worker: %d", got.Code)
	}
	if b.driver.destroyCount() != 0 || a.driver.destroyCount() != 0 || b.driver.count() != 2 || a.driver.count() != 3 {
		t.Fatalf("outage destroyed or duplicated VMs: a=%d/%d b=%d/%d", a.driver.count(), a.driver.destroyCount(), b.driver.count(), b.driver.destroyCount())
	}

	b.down.Store(false) // worker-b returns.
	s.reconcileAll(context.Background())
	// The superseded attempt is reaped; the sandbox whose delete failed is
	// still there, neither stranded nor duplicated, and is deleted now.
	if b.driver.has(onB[0].ID) || !b.driver.has(onB[1].ID) || !a.driver.has(retry.ID) {
		t.Fatalf("after return: superseded=%v kept=%v retry=%v", b.driver.has(onB[0].ID), b.driver.has(onB[1].ID), a.driver.has(retry.ID))
	}
	if !s.Authorize(retry.ID, retry.Token) || s.Authorize(onB[0].ID, onB[0].Token) || !s.Authorize(onB[1].ID, onB[1].Token) {
		t.Fatal("old attempt still authorized, new attempt revoked, or returned sandbox not re-adopted")
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+onB[1].ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("retried delete after return: %d", got.Code)
	}
	list = request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Code != http.StatusOK || list.Header().Get("X-Sandboxd-Offline-Workers") != "" || list.Header().Get("X-Total-Running") != "3" {
		t.Fatalf("inventory after return: %d %v %s", list.Code, list.Header(), list.Body.String())
	}
	if a.driver.count()+b.driver.count() != 3 {
		t.Fatalf("live VMs %d+%d, want one per live job", a.driver.count(), b.driver.count())
	}
}

func jobOf(t *testing.T, s *Service, id string) string {
	t.Helper()
	row, err := s.ledger.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return row.JobID
}

func TestStaleLeaseWorkerIsFenced(t *testing.T) {
	// worker-a has the most free slots, then wins ties: everything below
	// lands on it, so worker-b stays a bystander.
	owner := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 2)
	bystander := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 1)
	s := openGateway(t, filepath.Join(t.TempDir(), "ledger.sqlite"), owner, bystander)
	ctx := context.Background()

	mustCreate(t, s, createFor("review-arm64", "filler", 1))
	old := mustCreate(t, s, createFor("review-arm64", "job-x", 1))
	if owner.driver.count() != 2 {
		t.Fatalf("placement: owner=%d bystander=%d", owner.driver.count(), bystander.driver.count())
	}
	row, _ := s.ledger.Get(ctx, old.ID)
	oldLease := row.Lease
	// A command is running on the old attempt when its worker drops out.
	runDone := make(chan error, 1)
	runCtx, cancelRun := context.WithCancel(ctx)
	t.Cleanup(cancelRun) // A failed assertion must not leave the run blocked.
	go func() {
		_, err := s.Guests().Run(runCtx, old.ID, vm.Command{Args: []string{"block"}}, io.Discard, io.Discard)
		runDone <- err
	}()
	receive(t, owner.driver.runStarted)

	owner.down.Store(true)
	s.reconcileAll(ctx)
	if s.Authorize(old.ID, old.Token) {
		t.Fatal("sandbox on an unobservable worker stayed authorized")
	}
	if _, err := catGuest(t, s, old.ID, "/etc/hostname"); err == nil {
		t.Fatal("guest call routed to a worker without a current lease")
	}
	owner.down.Store(false)
	s.reconcileAll(ctx)
	row, _ = s.ledger.Get(ctx, old.ID)
	if row.Lease <= oldLease || !s.Authorize(old.ID, old.Token) {
		t.Fatalf("returned worker not re-enrolled under a newer lease: %d -> %d", oldLease, row.Lease)
	}
	select {
	case err := <-runDone:
		if err == nil || !errors.Is(err, worker.ErrStaleLease) {
			t.Fatalf("run under the superseded lease ended with %v, want a stale-lease error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run under the superseded lease kept going after re-enrollment")
	}

	// A Create answered across a re-enrollment cannot admit its VM.
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+old.ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", got.Code)
	}
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release) // A failed assertion must not leave the worker's handler stuck.
	owner.driver.mu.Lock()
	owner.driver.createGate = gate
	owner.driver.mu.Unlock()
	answer := make(chan *httptest.ResponseRecorder, 1)
	go func() { answer <- request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-y", 1)) }()
	receive(t, owner.driver.createEntered) // The worker accepted the Create under the old lease.
	owner.down.Store(true)
	s.reconcileAll(ctx)
	owner.down.Store(false)
	s.reconcileAll(ctx)
	release()
	if got := receive(t, answer); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("create answered under a superseded lease admitted: %d %s", got.Code, got.Body.String())
	}
	s.reconcileAll(ctx)
	if owner.driver.count() != 1 {
		t.Fatalf("VM from a fenced create survived reconciliation: %d VMs", owner.driver.count())
	}
	if rows, _ := s.ledger.Active(ctx); len(rows) != 1 {
		t.Fatalf("fenced create left %d live rows, want only the filler", len(rows))
	}
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the fake worker")
		panic("unreachable")
	}
}

// Today's single Mac: a local driver and the existing configuration, with no
// workers enrolled, still serves every slot and reports its capacity.
func TestSingleLocalWorkerConfigurationIsUnchanged(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	s := openSlotService(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, slotConfig(3, "slot-1", "slot-2", "slot-3"))
	for _, job := range []string{"a", "b", "c"} {
		id, token := createSandbox(t, s, "job-"+job)
		if !s.Authorize(id, token) {
			t.Fatalf("sandbox %s not authorized", id)
		}
	}
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createBody("job-d", 1)))
	report := readCapacity(t, s)
	entry := workerReport(t, report, "mac-local")
	if report.TotalSlots != 3 || report.UsedSlots != 3 || len(report.Workers) != 1 || !entry.Online ||
		entry.Arch != runtime.GOARCH || entry.Driver != "local" || len(entry.Templates) != 1 || entry.Templates[0] != "review-arm64" {
		t.Fatalf("single-worker capacity: %+v", report)
	}
	if got := request(t, s, http.MethodPost, "/sandboxes", createFor("other-template", "job-e", 1)); got.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured template accepted: %d", got.Code)
	}
	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Code != http.StatusOK || list.Header().Get("X-Total-Running") != "3" || list.Header().Get("X-Sandboxd-Offline-Workers") != "" {
		t.Fatalf("single-worker inventory: %d %v", list.Code, list.Header())
	}
}

func ledgerState(t *testing.T, s *Service, id string) string {
	t.Helper()
	row, err := s.ledger.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return row.State
}

// A worker whose -enroll is removed while it still owns live sandboxes is
// treated like an offline worker: the rest of the cluster keeps admitting.
func TestRemovedWorkerDoesNotBlockRemainingWorkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 2)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 2)
	first := startGateway(t, path, a, b)
	var onB []created
	for i := range 2 {
		c := mustCreate(t, first, createFor("review-arm64", fmt.Sprintf("job-%d", i), 1))
		if b.driver.has(c.ID) {
			onB = append(onB, c)
		}
	}
	if len(onB) != 1 || a.driver.count() != 1 {
		t.Fatalf("placement: a=%d b=%d", a.driver.count(), b.driver.count())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	s := openGateway(t, path, a) // worker-b's -enroll was removed.
	mustCreate(t, s, createFor("review-arm64", "job-new", 1))
	if a.driver.count() != 2 || b.driver.count() != 1 {
		t.Fatalf("create on the remaining worker: a=%d b=%d", a.driver.count(), b.driver.count())
	}
	// worker-b's reservation counts against worker-b only; worker-a is full.
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createFor("review-arm64", "job-full", 1)))

	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Code != http.StatusOK || list.Header().Get("X-Sandboxd-Offline-Workers") != "worker-b" ||
		list.Header().Get("X-Total-Running") != "3" || !strings.Contains(list.Body.String(), onB[0].ID) {
		t.Fatalf("removed worker's sandbox dropped or unflagged: %d %v %s", list.Code, list.Header(), list.Body.String())
	}
	report := readCapacity(t, s)
	entry := workerReport(t, report, "worker-b")
	if entry.Enrolled || entry.Online || entry.UsedSlots != 1 || entry.Error == "" || !workerReport(t, report, "worker-a").Enrolled {
		t.Fatalf("removed worker not visible as unenrolled: %+v", entry)
	}
	if report.TotalSlots != 2 || report.UsedSlots != 2 || report.FreeSlots != 0 {
		t.Fatalf("removed worker counted in cluster capacity: %+v", report)
	}
	if s.Authorize(onB[0].ID, onB[0].Token) {
		t.Fatal("sandbox of an unenrolled worker authorized")
	}
	if got := request(t, s, http.MethodGet, "/sandboxes/"+onB[0].ID, nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("get on unenrolled worker: %d", got.Code)
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+onB[0].ID, nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete on unenrolled worker: %d", got.Code)
	}
	if !b.driver.has(onB[0].ID) || ledgerState(t, s, onB[0].ID) != "running" {
		t.Fatal("removed worker's sandbox was destroyed or released without proof")
	}
}

func TestForgetWorkerReleasesUnverifiedReservations(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 1)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 2)
	s := openGateway(t, path, a, b)
	var onB []created
	for i := range 3 {
		c := mustCreate(t, s, createFor("review-arm64", fmt.Sprintf("job-%d", i), 1))
		if b.driver.has(c.ID) {
			onB = append(onB, c)
		}
	}
	if len(onB) != 2 {
		t.Fatalf("placement: a=%d b=%d", a.driver.count(), b.driver.count())
	}
	forget := func(id string, body any) *httptest.ResponseRecorder {
		return request(t, s, http.MethodPost, "/sandboxd/workers/"+id+"/forget", body)
	}
	if got := forget("worker-b", map[string]bool{"confirm": true}); got.Code != http.StatusConflict {
		t.Fatalf("forgot an enrolled online worker: %d %s", got.Code, got.Body.String())
	}
	b.down.Store(true)
	s.reconcileAll(context.Background())
	if got := forget("worker-b", map[string]bool{}); got.Code != http.StatusBadRequest {
		t.Fatalf("forget without confirmation: %d", got.Code)
	}
	if ledgerState(t, s, onB[0].ID) != "running" {
		t.Fatal("refused forget released a reservation")
	}
	got := forget("worker-b", map[string]bool{"confirm": true})
	var answer forgetResponse
	if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &answer) != nil || len(answer.Unverified) != 2 {
		t.Fatalf("forget: %d %s", got.Code, got.Body.String())
	}
	for _, c := range onB {
		if state := ledgerState(t, s, c.ID); state != "unverified" {
			t.Fatalf("forgotten sandbox state %q, want unverified (not gone)", state)
		}
		if !strings.Contains(logs.String(), c.ID) || !strings.Contains(logs.String(), "NOT proven gone") {
			t.Fatalf("forget did not log that %s was not proven gone: %s", c.ID, logs.String())
		}
		if got := request(t, s, http.MethodGet, "/sandboxes/"+c.ID, nil); got.Code != http.StatusNotFound {
			t.Fatalf("forgotten sandbox get: %d", got.Code)
		}
	}
	if entry := workerReport(t, readCapacity(t, s), "worker-b"); entry.UsedSlots != 0 {
		t.Fatalf("forgotten reservations still held: %+v", entry)
	}
	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Header().Get("X-Total-Running") != "1" || strings.Contains(list.Body.String(), onB[0].ID) {
		t.Fatalf("forgotten sandboxes still listed: %v %s", list.Header(), list.Body.String())
	}
	if b.driver.destroyCount() != 0 {
		t.Fatal("forget claimed to destroy VMs it could not reach")
	}

	// The worker returns: its unowned VMs are destroyed and only then are the
	// forgotten rows resolved to gone. Its freed slots take new work.
	b.down.Store(false)
	s.reconcileAll(context.Background())
	if b.driver.count() != 0 {
		t.Fatalf("returned worker kept %d forgotten VMs", b.driver.count())
	}
	for _, c := range onB {
		if state := ledgerState(t, s, c.ID); state != "gone" {
			t.Fatalf("forgotten sandbox not resolved after proof: %q", state)
		}
	}
	mustCreate(t, s, createFor("review-arm64", "job-after", 1))
	mustCreate(t, s, createFor("review-arm64", "job-after-2", 1))
	if b.driver.count() != 2 {
		t.Fatalf("freed slots not reused: b=%d", b.driver.count())
	}
}

// An operator can also forget a worker that is no longer enrolled at all.
func TestForgetUnenrolledWorkerFreesItsReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	a := newFakeWorker(t, "worker-a", "arm64", arm64Templates, 1)
	b := newFakeWorker(t, "worker-b", "arm64", arm64Templates, 1)
	first := startGateway(t, path, a, b)
	mustCreate(t, first, createFor("review-arm64", "job-1", 1))
	mustCreate(t, first, createFor("review-arm64", "job-2", 1))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	s := openGateway(t, path, a)
	if workerReport(t, readCapacity(t, s), "worker-b").Enrolled {
		t.Fatal("removed worker reported as enrolled")
	}
	if got := request(t, s, http.MethodPost, "/sandboxd/workers/worker-b/forget", map[string]bool{"confirm": true}); got.Code != http.StatusOK {
		t.Fatalf("forget unenrolled worker: %d %s", got.Code, got.Body.String())
	}
	for _, w := range readCapacity(t, s).Workers {
		if w.WorkerID == "worker-b" {
			t.Fatalf("forgotten worker still reported: %+v", w)
		}
	}
	list := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if list.Header().Get("X-Sandboxd-Offline-Workers") != "" || list.Header().Get("X-Total-Running") != "1" {
		t.Fatalf("forgotten worker still in inventory: %v", list.Header())
	}
}

// A renamed local worker shares this host's physical slot networks with the
// VMs its old identity still owns: a new guest never lands on a held slot.
func TestRenamedLocalWorkerNeverDoubleBooksAPhysicalSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	cfg := slotConfig(2, "slot-1", "slot-2")
	cfg.WorkerID = "mac-original"
	first, err := Open(context.Background(), path, driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := createSandbox(t, first, "job-old")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.WorkerID = "mac-replacement"
	s := openSlotService(t, path, driver, cfg)
	id, _ := createSandbox(t, s, "job-new")
	oldRow, _ := s.ledger.Get(context.Background(), old)
	newRow, _ := s.ledger.Get(context.Background(), id)
	if oldRow.Slot == newRow.Slot {
		t.Fatalf("new guest placed on slot %s still held by the old identity's VM", newRow.Slot)
	}
	assertCapacityFull(t, request(t, s, http.MethodPost, "/sandboxes", createBody("job-third", 1)))
}
