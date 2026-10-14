package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// fakeVolumes is a driver's volume store; attach marks a volume a VM holds.
type fakeVolumes struct {
	mu       sync.Mutex
	volumes  []vm.Volume
	next     int
	maxCount int // 0 means no budget
	err      error
}

func (f *fakeVolumes) CreateVolume(_ context.Context, name string) (vm.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return vm.Volume{}, f.err
	}
	for _, volume := range f.volumes {
		if volume.Name == name {
			return vm.Volume{}, fmt.Errorf("volume %q: %w", name, vm.ErrVolumeExists)
		}
	}
	if f.maxCount > 0 && len(f.volumes) >= f.maxCount {
		return vm.Volume{}, fmt.Errorf("volume %q: %w", name, vm.ErrVolumeBudget)
	}
	f.next++
	volume := vm.Volume{ID: fmt.Sprintf("vol-%032x", f.next), Name: name, SizeMiB: 512}
	f.volumes = append(f.volumes, volume)
	slices.SortFunc(f.volumes, func(a, b vm.Volume) int { return strings.Compare(a.Name, b.Name) })
	return volume, nil
}

func (f *fakeVolumes) Volumes(context.Context) ([]vm.Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return slices.Clone(f.volumes), nil
}

func (f *fakeVolumes) DeleteVolume(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	for i, volume := range f.volumes {
		if volume.ID != id {
			continue
		}
		if volume.AttachedTo != "" {
			return fmt.Errorf("volume %s: %w", id, vm.ErrVolumeInUse)
		}
		f.volumes = slices.Delete(f.volumes, i, i+1)
		return nil
	}
	return fmt.Errorf("volume %s: %w", id, vm.ErrVolumeNotFound)
}

func (f *fakeVolumes) attach(name, sandbox string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.volumes {
		if f.volumes[i].Name == name {
			f.volumes[i].AttachedTo = sandbox
		}
	}
}

// specDriver records every Create spec the local driver receives.
type specDriver struct {
	*fakeDriver
	specMu sync.Mutex
	specs  []vm.Spec
}

func (d *specDriver) Create(ctx context.Context, spec vm.Spec) (vm.Instance, error) {
	d.specMu.Lock()
	d.specs = append(d.specs, spec)
	d.specMu.Unlock()
	return d.fakeDriver.Create(ctx, spec)
}

func (d *specDriver) recorded() []vm.Spec {
	d.specMu.Lock()
	defer d.specMu.Unlock()
	return slices.Clone(d.specs)
}

type volumeJSON struct {
	ID    string `json:"volumeID"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

func openVolumes(t *testing.T, slots int) (*Service, *specDriver, *fakeVolumes) {
	t.Helper()
	driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
	volumes := &fakeVolumes{}
	cfg := mixedConfig(e2bBase, slots)
	cfg.Volumes = volumes
	return openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg), driver, volumes
}

func createVolume(t *testing.T, s *Service, name string) volumeJSON {
	t.Helper()
	got := request(t, s, http.MethodPost, "/volumes", map[string]any{"name": name})
	if got.Code != http.StatusCreated {
		t.Fatalf("create volume %q: %d %s", name, got.Code, got.Body.String())
	}
	return decodeBody[volumeJSON](t, got.Body)
}

// wantFailure checks an E2B JSON error with status and a message containing
// message.
func wantFailure(t *testing.T, label string, got *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	var failure e2bError
	if err := json.Unmarshal(got.Body.Bytes(), &failure); err != nil || got.Code != status ||
		failure.Code != status || !strings.Contains(failure.Message, message) {
		t.Errorf("%s: %d %s, want %d containing %q", label, got.Code, got.Body.String(), status, message)
	}
}

func mountBody(mounts any) map[string]any {
	return map[string]any{"templateID": "base", "volumeMounts": mounts}
}

// Volumes off: the volume API, its content API and volumeMounts keep their
// 501 refusal, the content API under the original message.
func TestVolumesOffStayRefused(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), &fakeDriver{instances: map[string]vm.Instance{}}, mixedConfig(e2bBase, 1))
	for _, c := range []struct {
		method, path string
		body         any
		reason       string
	}{
		{http.MethodPost, "/volumes", map[string]any{"name": "v"}, refuseVolumes},
		{http.MethodGet, "/volumes", nil, refuseVolumes},
		{http.MethodDelete, "/volumes/vol-00000000000000000000000000000001", nil, refuseVolumes},
		{http.MethodGet, "/volumecontent/vol-1/file", nil, refuseVolumes},
		{http.MethodPost, "/v2/sandboxes", mountBody([]any{}), "volume mounts are not supported"},
	} {
		got := request(t, s, c.method, c.path, c.body)
		wantFailure(t, c.method+" "+c.path, got, http.StatusNotImplemented, c.reason+"; "+notSupportedDoc)
	}
}

func TestVolumeAPI(t *testing.T) {
	s, _, volumes := openVolumes(t, 1)
	created := createVolume(t, s, "data")
	if !vm.ValidVolumeID(created.ID) || created.Name != "data" || created.Token == "" || created.Token != s.volumeToken(created.ID) {
		t.Fatalf("created volume: %+v", created)
	}
	other := createVolume(t, s, "cache")

	got := request(t, s, http.MethodGet, "/volumes", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("list: %d %s", got.Code, got.Body.String())
	}
	// The list item is E2B's Volume: no token.
	want := fmt.Sprintf(`[{"volumeID":%q,"name":"cache"},{"volumeID":%q,"name":"data"}]`+"\n", other.ID, created.ID)
	if got.Body.String() != want {
		t.Fatalf("list: %s, want %s", got.Body.String(), want)
	}
	got = request(t, s, http.MethodGet, "/volumes/"+created.ID, nil)
	if fetched := decodeBody[volumeJSON](t, got.Body); got.Code != http.StatusOK || fetched != created {
		t.Fatalf("get: %d %+v, want %+v", got.Code, fetched, created)
	}

	for _, c := range []struct {
		label, method, path string
		body                any
		status              int
		message             string
	}{
		{"duplicate name", http.MethodPost, "/volumes", map[string]any{"name": "data"}, http.StatusConflict, "already exists"},
		{"invalid name", http.MethodPost, "/volumes", map[string]any{"name": "-bad"}, http.StatusBadRequest, "invalid volume name"},
		{"empty name", http.MethodPost, "/volumes", map[string]any{}, http.StatusBadRequest, "invalid volume name"},
		{"unknown field", http.MethodPost, "/volumes", map[string]any{"name": "x", "size": 1}, http.StatusBadRequest, "invalid volume request body"},
		{"unknown id", http.MethodGet, "/volumes/vol-ffffffffffffffffffffffffffffffff", nil, http.StatusNotFound, "volume not found"},
		{"malformed id", http.MethodGet, "/volumes/data", nil, http.StatusNotFound, "volume not found"},
		{"delete unknown", http.MethodDelete, "/volumes/vol-ffffffffffffffffffffffffffffffff", nil, http.StatusNotFound, "volume not found"},
		{"content API", http.MethodGet, "/volumecontent/" + created.ID + "/dir", nil, http.StatusNotImplemented, refuseVolumeContent},
	} {
		got := request(t, s, c.method, c.path, c.body)
		wantFailure(t, c.label, got, c.status, c.message)
	}

	volumes.attach("data", "sandboxd-00000000000000000000000000000001")
	got = request(t, s, http.MethodDelete, "/volumes/"+created.ID, nil)
	wantFailure(t, "delete attached", got, http.StatusConflict, "attached to a sandbox")
	volumes.attach("data", "")
	if got := request(t, s, http.MethodDelete, "/volumes/"+created.ID, nil); got.Code != http.StatusNoContent || got.Body.Len() != 0 {
		t.Fatalf("delete: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, s, http.MethodGet, "/volumes/"+created.ID, nil); got.Code != http.StatusNotFound {
		t.Fatalf("get deleted: %d", got.Code)
	}

	volumes.maxCount = 1
	got = request(t, s, http.MethodPost, "/volumes", map[string]any{"name": "more"})
	wantFailure(t, "over budget", got, http.StatusBadRequest, "budget")

	// Any other driver failure is unavailability, its detail logged only.
	volumes.err = errors.New("/var/lib/sandboxd-fc/volumes: disk on fire")
	got = request(t, s, http.MethodGet, "/volumes", nil)
	wantFailure(t, "driver failure", got, http.StatusServiceUnavailable, "volume state unavailable")
	if strings.Contains(got.Body.String(), "fire") {
		t.Fatalf("driver detail leaked: %s", got.Body.String())
	}
}

func TestVolumeMountReachesLocalDriver(t *testing.T) {
	s, driver, _ := openVolumes(t, 3)
	created := createVolume(t, s, "data")
	sandbox := createE2B(t, s, mountBody([]map[string]string{{"name": "data", "path": "/mnt/data"}}))
	specs := driver.recorded()
	if len(specs) != 1 || specs[0].ID != sandbox.ID || specs[0].Volume == nil || *specs[0].Volume != (vm.VolumeMount{ID: created.ID, Path: "/mnt/data"}) {
		t.Fatalf("specs: %+v", specs)
	}
	// None, null and [] mount nothing.
	for _, mounts := range []any{nil, []any{}} {
		createE2B(t, s, mountBody(mounts))
		if got := driver.recorded(); got[len(got)-1].Volume != nil {
			t.Fatalf("volumeMounts %v mounted %+v", mounts, got[len(got)-1].Volume)
		}
	}
}

// Strict create never carries a volume, and refuses volumeMounts as the
// unknown field it is in that API.
func TestStrictCreateNeverCarriesAVolume(t *testing.T) {
	s, driver, _ := openVolumes(t, 2)
	createVolume(t, s, "data")
	body := createBody("job-1", 1)
	body["volumeMounts"] = []map[string]string{{"name": "data", "path": "/mnt/data"}}
	if got := request(t, s, http.MethodPost, "/sandboxes", body); got.Code != http.StatusBadRequest {
		t.Fatalf("strict create with volumeMounts: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-1", 1)); got.Code != http.StatusCreated {
		t.Fatalf("strict create: %d %s", got.Code, got.Body.String())
	}
	if specs := driver.recorded(); len(specs) != 1 || specs[0].Volume != nil {
		t.Fatalf("strict specs: %+v", specs)
	}
}

func TestVolumeMountRefusals(t *testing.T) {
	s, driver, volumes := openVolumes(t, 1)
	createVolume(t, s, "data")
	createVolume(t, s, "logs")
	attached := "sandboxd-00000000000000000000000000000001"
	volumes.attach("logs", attached)
	for _, c := range []struct {
		label   string
		mounts  any
		status  int
		message string
	}{
		{"two mounts", []map[string]string{{"name": "data", "path": "/a"}, {"name": "data", "path": "/b"}}, http.StatusBadRequest, "at most one volume mount per sandbox"},
		{"relative path", []map[string]string{{"name": "data", "path": "mnt"}}, http.StatusBadRequest, "invalid volume mount path"},
		{"root path", []map[string]string{{"name": "data", "path": "/"}}, http.StatusBadRequest, "invalid volume mount path"},
		{"unclean path", []map[string]string{{"name": "data", "path": "/mnt/../etc"}}, http.StatusBadRequest, "invalid volume mount path"},
		{"unknown field", []map[string]any{{"name": "data", "path": "/mnt", "readOnly": true}}, http.StatusBadRequest, "invalid volumeMounts"},
		{"not a list", map[string]string{"name": "data", "path": "/mnt"}, http.StatusBadRequest, "invalid volumeMounts"},
		{"unknown name", []map[string]string{{"name": "missing", "path": "/mnt"}}, http.StatusNotFound, `volume "missing" not found`},
		{"in use", []map[string]string{{"name": "logs", "path": "/mnt"}}, http.StatusConflict, `volume "logs" is attached to sandbox ` + attached},
	} {
		got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody(c.mounts))
		wantFailure(t, c.label, got, c.status, c.message)
	}
	// None of them reserved a slot or reached the driver.
	rows, err := s.ledger.Active(context.Background())
	if err != nil || len(rows) != 0 || len(driver.recorded()) != 0 {
		t.Fatalf("refused mounts left rows %+v (%v), specs %+v", rows, err, driver.recorded())
	}
	// The one slot is still free.
	createE2B(t, s, mountBody([]map[string]string{{"name": "data", "path": "/mnt"}}))
}

// The driver is authoritative: a volume it finds in use at Create is the
// client's conflict, while the row is held as for any failed start.
func TestDriverVolumeInUseIsConflict(t *testing.T) {
	s, driver, _ := openVolumes(t, 1)
	createVolume(t, s, "data")
	driver.createError = fmt.Errorf("create: %w", vm.ErrVolumeInUse)
	got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "data", "path": "/mnt"}}))
	wantFailure(t, "driver in use", got, http.StatusConflict, "attached to another sandbox")
	specs := driver.recorded()
	if len(specs) != 1 || specs[0].Volume == nil {
		t.Fatalf("specs: %+v", specs)
	}
	if state := ledgerState(t, s, specs[0].ID); state != "unknown" && state != "gone" {
		t.Fatalf("row after in-use create: %s", state)
	}
	// A path the worker cannot mount is the client's to fix: never a 503.
	driver.createError = fmt.Errorf("create: %w", vm.ErrVolumeMountPath)
	got = request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "data", "path": "/mnt"}}))
	wantFailure(t, "driver mount path", got, http.StatusBadRequest, "mount path not supported")
}

// A template image too old for the requested features is the operator's
// to fix: a plain 500, never the 503 clients retry.
func TestDriverImageTooOldIsNotRetryable(t *testing.T) {
	s, driver, _ := openVolumes(t, 1)
	createVolume(t, s, "data")
	driver.createError = fmt.Errorf("create: %w", vm.ErrImageTooOld)
	got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "data", "path": "/home/user/data"}}))
	wantFailure(t, "old image", got, http.StatusInternalServerError, "must rebuild")
}

// A volume deleted between the name lookup and Create is not found, as if
// it had been gone at the lookup: never a 503.
func TestDriverVolumeGoneIsNotFound(t *testing.T) {
	s, driver, _ := openVolumes(t, 1)
	createVolume(t, s, "data")
	driver.createError = fmt.Errorf("create: %w", vm.ErrVolumeNotFound)
	got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "data", "path": "/mnt"}}))
	wantFailure(t, "driver not found", got, http.StatusNotFound, "volume not found")
}

// A volume sandbox runs on the gateway's local worker or nowhere, however
// much room an enrolled worker has.
func TestVolumeSandboxNeverPlacedOnRemoteWorker(t *testing.T) {
	var remote *fakeWorker
	// Each gateway gets its own worker: two gateways enrolling one worker
	// fence each other, and the loser's sandboxes become unavailable.
	newGateway := func(local map[string]Template) (*Service, *specDriver) {
		remote = newFakeWorker(t, "arm-1", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 4)
		driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
		cfg := mixedConfig(local, 1)
		cfg.Arch = "arm64"
		cfg.Volumes = &fakeVolumes{}
		cfg.Workers = []Remote{{ID: remote.id, Member: remote.client}}
		return openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg), driver
	}
	mount := mountBody([]map[string]string{{"name": "data", "path": "/mnt"}})

	// The local worker serves the template: the volume sandbox lands there
	// though the remote has more free capacity, and the next one is refused
	// once the local worker is full.
	s, driver := newGateway(e2bBase)
	createVolume(t, s, "data")
	createVolume(t, s, "other")
	sandbox := createE2B(t, s, mount)
	if row, err := s.ledger.Get(context.Background(), sandbox.ID); err != nil || row.WorkerID != "mac-local" || len(driver.recorded()) != 1 {
		t.Fatalf("volume sandbox placed on %q (%v)", row.WorkerID, err)
	}
	got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "other", "path": "/mnt"}}))
	wantFailure(t, "local full", got, http.StatusConflict, "capacity exhausted")
	if n := remote.driver.count(); n != 0 {
		t.Fatalf("remote worker ran %d VMs", n)
	}

	// Only the remote serves the template: refused, not placed there; the
	// same request without a volume runs on the remote.
	remoteOnly := map[string]Template{"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4"}}
	s, driver = newGateway(remoteOnly)
	createVolume(t, s, "data")
	got = request(t, s, http.MethodPost, "/v2/sandboxes", mount)
	wantFailure(t, "remote only", got, http.StatusConflict, "local worker")
	if n := remote.driver.count(); n != 0 || len(driver.recorded()) != 0 {
		t.Fatalf("volume sandbox placed: remote %d, local %+v", n, driver.recorded())
	}
	createE2B(t, s, map[string]any{"templateID": "base"})
	if n := remote.driver.count(); n != 1 {
		t.Fatalf("plain sandbox not on the remote: %d", n)
	}
}

func TestVolumesNeedLocalDriver(t *testing.T) {
	remote := newFakeWorker(t, "arm-1", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 1)
	_, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), nil, Config{APIKey: "control-secret", Domain: "sandbox.example",
		MaxTTL: time.Hour, TokenSecret: []byte(testSecret), Volumes: &fakeVolumes{}, Workers: []Remote{{ID: remote.id, Member: remote.client}},
		Templates: map[string]Template{"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, EnvdVersion: "0.2.4"}}})
	if err == nil {
		t.Fatal("volumes accepted without a local driver")
	}
}
