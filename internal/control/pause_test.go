package control

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// pausingDriver is the fake driver with vm.Pauser: a paused VM is kept,
// neither running nor gone, on its network.
type pausingDriver struct {
	*fakeDriver
	pauseError, resumeError error
	// release, when set, holds every Pause until it is closed; entered
	// then receives once per held Pause.
	entered, release chan struct{}
}

func newPausingDriver() *pausingDriver {
	return &pausingDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
}

func (d *pausingDriver) Pause(_ context.Context, id string) error {
	if d.release != nil {
		d.entered <- struct{}{}
		<-d.release
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pauseError != nil {
		return d.pauseError
	}
	instance, ok := d.instances[id]
	if !ok || !instance.Running {
		return vm.ErrNotRunning
	}
	instance.Running, instance.Paused = false, true
	d.instances[id] = instance
	return nil
}

func (d *pausingDriver) Resume(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.resumeError != nil {
		return d.resumeError
	}
	instance, ok := d.instances[id]
	if !ok || !instance.Paused {
		return vm.ErrNotPaused
	}
	instance.Running, instance.Paused = true, false
	d.instances[id] = instance
	return nil
}

func (d *pausingDriver) instance(id string) (vm.Instance, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	instance, ok := d.instances[id]
	return instance, ok
}

func describedSandbox(t *testing.T, s *Service, id string) listed {
	t.Helper()
	got := request(t, s, http.MethodGet, "/sandboxes/"+id, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get %s: %d %s", id, got.Code, got.Body.String())
	}
	return decodeBody[listed](t, got.Body)
}

func expectStatus(t *testing.T, s *Service, method, path string, body any, status int) {
	t.Helper()
	if got := request(t, s, method, path, body); got.Code != status {
		t.Fatalf("%s %s: %d %s, want %d", method, path, got.Code, got.Body.String(), status)
	}
}

// TestPauseAndResumeKeepTheSandbox: a paused e2b sandbox keeps its VM, slot
// and capacity, is described and listed as paused, refuses running-only
// actions, survives reconciliation, and resumes with the same tokens.
func TestPauseAndResumeKeepTheSandbox(t *testing.T) {
	driver := newPausingDriver()
	cfg := mixedConfig(e2bBase, 1)
	cfg.PauseRetention = 2 * time.Hour
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	created := createE2B(t, s, map[string]any{"templateID": "base"})
	id := created.ID

	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", map[string]any{}, http.StatusNoContent)
	if instance, _ := driver.instance(id); !instance.Paused || instance.Running {
		t.Fatalf("driver VM after pause: %+v", instance)
	}
	described := describedSandbox(t, s, id)
	if described.State != "paused" || described.EndAt.Before(time.Now().Add(110*time.Minute)) {
		t.Fatalf("paused sandbox described as %+v, want paused until its retention", described)
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", map[string]any{}, http.StatusConflict)
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/timeout", map[string]int{"timeout": 60}, http.StatusConflict)
	expectStatus(t, s, http.MethodGet, "/sandboxes/"+id+"/metrics", nil, http.StatusConflict)
	if s.AuthorizeEnvd(id, created.Token) {
		t.Fatal("envd of a paused sandbox authorized")
	}
	// Snapshots and fork stay refused for a paused sandbox, not unknown.
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/fork", map[string]any{}, http.StatusNotImplemented)

	ids, header := listIDs(t, s, "")
	if len(ids) != 1 || ids[0] != id || header.Get("X-Total-Running") != "0" {
		t.Fatalf("default list: %v running %q, want the paused sandbox and 0 running", ids, header.Get("X-Total-Running"))
	}
	if ids, _ := listIDs(t, s, "?state=running"); len(ids) != 0 {
		t.Fatalf("running list: %v", ids)
	}
	if ids, _ := listIDs(t, s, "?state=paused"); len(ids) != 1 {
		t.Fatalf("paused list: %v", ids)
	}
	// The paused sandbox holds the only slot.
	if got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base"}); got.Code != http.StatusConflict {
		t.Fatalf("create beside a paused sandbox at capacity: %d %s", got.Code, got.Body.String())
	}
	s.reconcileAll(context.Background())
	if _, ok := driver.instance(id); !ok {
		t.Fatal("reconciliation destroyed a paused sandbox")
	}

	got := request(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", map[string]any{"timeout": 120})
	if got.Code != http.StatusCreated {
		t.Fatalf("resume: %d %s", got.Code, got.Body.String())
	}
	if resumed := decodeBody[e2bCreated](t, got.Body); resumed.ID != id || resumed.Token != created.Token {
		t.Fatalf("resumed %+v, want the same sandbox and token", resumed)
	}
	described = describedSandbox(t, s, id)
	if described.State != "running" || described.EndAt.After(time.Now().Add(121*time.Second)) {
		t.Fatalf("resumed sandbox described as %+v, want running for its resume timeout", described)
	}
	if !s.AuthorizeEnvd(id, created.Token) {
		t.Fatal("envd of a resumed sandbox refused")
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", map[string]any{}, http.StatusConflict)
}

// TestConnectResumesAPausedSandbox: connect resumes a paused sandbox (201)
// for its timeout, default min(300 s, max TTL); a running one keeps 200.
func TestConnectResumesAPausedSandbox(t *testing.T) {
	driver := newPausingDriver()
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 1))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusNoContent)
	expectStatus(t, s, http.MethodPost, "/v2/sandboxes/"+id+"/connect", map[string]any{}, http.StatusCreated)
	described := describedSandbox(t, s, id)
	if described.State != "running" || described.EndAt.Before(time.Now().Add(290*time.Second)) || described.EndAt.After(time.Now().Add(301*time.Second)) {
		t.Fatalf("connected sandbox %+v, want running for 300 s", described)
	}
	if instance, _ := driver.instance(id); !instance.Running {
		t.Fatalf("driver VM after connect: %+v", instance)
	}
	expectStatus(t, s, http.MethodPost, "/v2/sandboxes/"+id+"/connect", map[string]any{"timeout": 30}, http.StatusOK)
}

// TestPauseRefusals: a filesystem-only pause or resume, a gitmoot-strict
// sandbox and a gone one are refused without touching the VM.
func TestPauseRefusals(t *testing.T) {
	driver := newPausingDriver()
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 3))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	refused := func(method, path string, body any, reason string) {
		t.Helper()
		got := request(t, s, method, path, body)
		failure := decodeBody[e2bError](t, got.Body)
		if got.Code != http.StatusNotImplemented || failure.Message != reason+"; "+notSupportedDoc {
			t.Fatalf("%s %s: %d %s, want 501 %q", method, path, got.Code, got.Body.String(), reason)
		}
	}
	refused(http.MethodPost, "/sandboxes/"+id+"/pause", map[string]any{"memory": false}, refusePauseFilesystem)
	refused(http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","autoPause":true,"autoPauseMemory":false}`), refusePauseFilesystem)
	refused(http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","autoPause":true,"autoResume":{"enabled":true}}`), "autoResume is not supported")
	if instance, _ := driver.instance(id); !instance.Running {
		t.Fatalf("refused pause touched the VM: %+v", instance)
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusNoContent)
	refused(http.MethodPost, "/sandboxes/"+id+"/resume", map[string]any{"memory": false}, refusePauseFilesystem)
	refused(http.MethodPost, "/v2/sandboxes/"+id+"/connect", map[string]any{"memory": false}, refusePauseFilesystem)
	if instance, _ := driver.instance(id); !instance.Paused {
		t.Fatalf("refused resume touched the VM: %+v", instance)
	}

	strict := request(t, s, http.MethodPost, "/sandboxes", createBody("job-1", 1))
	if strict.Code != http.StatusCreated {
		t.Fatalf("strict create: %d %s", strict.Code, strict.Body.String())
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+decodeBody[listed](t, strict.Body).ID+"/pause", nil, http.StatusConflict)

	expectStatus(t, s, http.MethodDelete, "/sandboxes/"+id, nil, http.StatusNoContent)
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", nil, http.StatusNotFound)
	expectStatus(t, s, http.MethodGet, "/sandboxes/"+id+"/pause", nil, http.StatusMethodNotAllowed)
}

// TestFailedPauseKeepsTheSandboxRunning: a pause the driver undid leaves the
// sandbox running and served; a failed resume leaves it paused.
func TestFailedPauseKeepsTheSandboxRunning(t *testing.T) {
	driver := newPausingDriver()
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 1))
	created := createE2B(t, s, map[string]any{"templateID": "base"})
	id := created.ID
	driver.pauseError = vm.ErrImageTooOld
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusInternalServerError)
	if described := describedSandbox(t, s, id); described.State != "running" {
		t.Fatalf("after a failed pause: %+v", described)
	}
	if !s.AuthorizeEnvd(id, created.Token) {
		t.Fatal("envd refused after a failed pause")
	}
	driver.pauseError = nil
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusNoContent)
	driver.resumeError = vm.ErrMemoryPressure
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", nil, http.StatusServiceUnavailable)
	if described := describedSandbox(t, s, id); described.State != "paused" {
		t.Fatalf("after a failed resume: %+v", described)
	}
	driver.resumeError = nil
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", nil, http.StatusCreated)
}

// TestSandboxStaysServedWhilePausing: during a pause the sandbox is still
// described (running until the pause settles), refuses other actions, and a
// kill waits for the pause.
func TestSandboxStaysServedWhilePausing(t *testing.T) {
	driver := newPausingDriver()
	driver.entered, driver.release = make(chan struct{}, 1), make(chan struct{})
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 1))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	paused := make(chan int, 1)
	go func() { paused <- request(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil).Code }()
	receive(t, driver.entered)
	if described := describedSandbox(t, s, id); described.State != "running" {
		t.Fatalf("pausing sandbox described as %+v", described)
	}
	if ids, _ := listIDs(t, s, ""); len(ids) != 1 {
		t.Fatalf("pausing sandbox not listed: %v", ids)
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusConflict)
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", nil, http.StatusConflict)
	expectStatus(t, s, http.MethodPost, "/v2/sandboxes/"+id+"/connect", map[string]any{}, http.StatusConflict)
	killed := make(chan int, 1)
	go func() { killed <- request(t, s, http.MethodDelete, "/sandboxes/"+id, nil).Code }()
	close(driver.release)
	if code := receive(t, paused); code != http.StatusNoContent {
		t.Fatalf("pause: %d", code)
	}
	if code := receive(t, killed); code != http.StatusNoContent {
		t.Fatalf("kill after the pause: %d", code)
	}
	if _, ok := driver.instance(id); ok {
		t.Fatal("killed paused sandbox kept its VM")
	}
}

// waitFor polls condition, reconciling, until it holds or 10 s pass.
func waitFor(t *testing.T, s *Service, what string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		s.reconcileAll(context.Background())
		if condition() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestAutoPauseAtEndTimeAndRetention: a sandbox created with autoPause is
// paused at its end time instead of destroyed, and destroyed once its pause
// retention lapses; one whose auto-pause fails is destroyed.
func TestAutoPauseAtEndTimeAndRetention(t *testing.T) {
	driver := newPausingDriver()
	cfg := mixedConfig(e2bBase, 2)
	cfg.PauseRetention = 2 * time.Second
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	id := createE2B(t, s, map[string]any{"templateID": "base", "autoPause": true, "timeout": 1}).ID
	waitFor(t, s, "the auto-pause", func() bool {
		instance, _ := driver.instance(id)
		return instance.Paused
	})
	if described := describedSandbox(t, s, id); described.State != "paused" {
		t.Fatalf("auto-paused sandbox: %+v", described)
	}
	waitFor(t, s, "the retention to lapse", func() bool {
		_, ok := driver.instance(id)
		return !ok
	})
	expectStatus(t, s, http.MethodGet, "/sandboxes/"+id, nil, http.StatusNotFound)

	driver.pauseError = vm.ErrImageTooOld
	failed := createE2B(t, s, map[string]any{"templateID": "base", "autoPause": true, "timeout": 1}).ID
	waitFor(t, s, "the failed auto-pause's destroy", func() bool {
		_, ok := driver.instance(failed)
		return !ok
	})
}

// TestPausedSandboxSurvivesGatewayRestart: a new gateway instance adopts a
// paused sandbox from the ledger and resumes it.
func TestPausedSandboxSurvivesGatewayRestart(t *testing.T) {
	driver := newPausingDriver()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	first, err := Open(context.Background(), path, driver, mixedConfig(e2bBase, 1))
	if err != nil {
		t.Fatal(err)
	}
	id := createE2B(t, first, map[string]any{"templateID": "base"}).ID
	expectStatus(t, first, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusNoContent)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	s := openAt(t, path, driver, mixedConfig(e2bBase, 1))
	if described := describedSandbox(t, s, id); described.State != "paused" {
		t.Fatalf("after restart: %+v", described)
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/resume", nil, http.StatusCreated)
}

// TestCloseWaitsForAPauseInFlight: Close refuses new pauses and resumes and
// waits for an explicit pause in flight to settle its row before it closes
// the ledger, so the next gateway finds the sandbox paused.
func TestCloseWaitsForAPauseInFlight(t *testing.T) {
	driver := newPausingDriver()
	driver.entered, driver.release = make(chan struct{}, 1), make(chan struct{})
	release := sync.OnceFunc(func() { close(driver.release) })
	t.Cleanup(release)
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	s, err := Open(context.Background(), path, driver, mixedConfig(e2bBase, 2))
	if err != nil {
		t.Fatal(err)
	}
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	other := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	paused := make(chan int, 1)
	go func() { paused <- request(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil).Code }()
	receive(t, driver.entered)
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned with a pause in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close never started refusing pauses")
		}
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+other+"/pause", nil, http.StatusServiceUnavailable)
	release()
	if code := receive(t, paused); code != http.StatusNoContent {
		t.Fatalf("pause in flight at Close: %d", code)
	}
	if err := receive(t, closed); err != nil {
		t.Fatal(err)
	}
	next := openAt(t, path, driver, mixedConfig(e2bBase, 2))
	if described := describedSandbox(t, next, id); described.State != "paused" {
		t.Fatalf("after restart: %+v", described)
	}
}

// TestCloseRefusesPausesWhileTheSweepDrains: Close refuses pauses from its
// start, also while it waits for a sweep held by a worker's inventory.
func TestCloseRefusesPausesWhileTheSweepDrains(t *testing.T) {
	shortenWorkerTimeout(t, 3*time.Second)
	remote := newFakeWorker(t, "worker-a", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 1)
	cfg := mixedConfig(e2bBase, 1)
	cfg.Workers = []Remote{{ID: remote.id, Member: remote.client}}
	driver := newPausingDriver()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	if _, local := driver.instance(id); !local {
		t.Fatal("placement: sandbox not on the local worker")
	}
	inventory := "/vms"
	remote.stall.Store(&inventory)
	receive(t, remote.stalled)
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-s.stop:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop the sweep")
	}
	expectStatus(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil, http.StatusServiceUnavailable)
	remote.stall.Store(nil)
	if err := receive(t, closed); err != nil {
		t.Fatal(err)
	}
}

// TestPauseRefusedOnARemoteWorker: only the local driver pauses.
func TestPauseRefusedOnARemoteWorker(t *testing.T) {
	remote := newFakeWorker(t, "worker-a", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 1)
	cfg := mixedConfig(map[string]Template{"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4"}}, 1)
	cfg.Workers = []Remote{{ID: remote.id, Member: remote.client}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), newPausingDriver(), cfg)
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	got := request(t, s, http.MethodPost, "/sandboxes/"+id+"/pause", nil)
	if failure := decodeBody[e2bError](t, got.Body); got.Code != http.StatusNotImplemented || failure.Message != refusePauseRemote+"; "+notSupportedDoc {
		t.Fatalf("pause on a remote worker: %d %s", got.Code, got.Body.String())
	}
	// autoPause places a sandbox on the local worker only, which does not
	// serve this template.
	if got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base", "autoPause": true}); got.Code != http.StatusConflict {
		t.Fatalf("auto-pausing sandbox with no local template: %d %s", got.Code, got.Body.String())
	}
}
