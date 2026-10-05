package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

const (
	testKey = "0123456789abcdef-worker-key"
	vmA     = "sandboxd-0123456789abcdef0123456789abcdef"
	vmB     = "sandboxd-fedcba9876543210fedcba9876543210"
)

func testDecl() Declaration {
	return Declaration{
		ID: "linux-1", Arch: "amd64", Driver: "fake",
		Templates: map[string]string{"review-amd64": "img-review"},
		CPUs:      2, MemoryMiB: 2048, MaxVMs: 2,
		Slots: []string{"slot-1", "slot-2"},
	}
}

// fakeDriver is an in-memory vm.Driver and vm.ResourceMeter.
type fakeDriver struct {
	mu       sync.Mutex
	calls    int
	creates  int
	destroys int
	vms      map[string]vm.Instance
	copied   map[string][]byte // guest path -> bytes read from the staged host file
	staged   []string          // host paths handed to CopyIn
	ran      []vm.Command

	stdout, stderr []byte
	exit           int
	blockRun       bool          // Run writes stdout, then blocks until ctx is done or release closes
	release        chan struct{} // closed at test cleanup so a failing test cannot hang
	runStarted     chan struct{} // closed once Run has started
	runCtxErr      chan error    // receives ctx.Err() from a blocked Run
}

func newFake() *fakeDriver {
	return &fakeDriver{vms: map[string]vm.Instance{}, copied: map[string][]byte{}, release: make(chan struct{}),
		runStarted: make(chan struct{}), runCtxErr: make(chan error, 1)}
}

func (f *fakeDriver) touch() {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
}

func (f *fakeDriver) count() (calls, creates, destroys int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.creates, f.destroys
}

func (f *fakeDriver) Create(_ context.Context, spec vm.Spec) (vm.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.creates++
	instance := vm.Instance{ID: spec.ID, Running: true, Network: spec.Network}
	f.vms[spec.ID] = instance
	return instance, nil
}

func (f *fakeDriver) List(context.Context) ([]vm.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	var out []vm.Instance
	for _, instance := range f.vms {
		out = append(out, instance)
	}
	return out, nil
}

func (f *fakeDriver) CopyIn(_ context.Context, id, hostPath, guestPath string) error {
	f.touch()
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.vms[id]; !ok {
		return errors.New("no such vm " + hostPath)
	}
	f.copied[guestPath] = data
	f.staged = append(f.staged, hostPath)
	return nil
}

func (f *fakeDriver) Run(ctx context.Context, id string, cmd vm.Command, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.calls++
	f.ran = append(f.ran, vm.Command{Args: cmd.Args, Dir: cmd.Dir, Env: cmd.Env, User: cmd.User})
	f.mu.Unlock()
	cmd.OnStart(4242)
	close(f.runStarted)
	if _, err := stdout.Write(f.stdout); err != nil {
		return 0, err
	}
	if f.blockRun {
		select {
		case <-ctx.Done():
		case <-f.release:
		}
		f.runCtxErr <- ctx.Err()
		return 0, ctx.Err()
	}
	if _, err := stderr.Write(f.stderr); err != nil {
		return 0, err
	}
	return f.exit, nil
}

func (f *fakeDriver) Destroy(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.destroys++
	delete(f.vms, id)
	return nil
}

func (f *fakeDriver) Usage(_ context.Context, id string) (vm.Usage, error) {
	f.touch()
	return vm.Usage{CPUUsedPct: 12.5, MemoryUsedBytes: 1 << 20, MemoryLimitBytes: 2 << 30}, nil
}

// plainDriver hides the fake's ResourceMeter.
type plainDriver struct{ vm.Driver }

func serve(t *testing.T, driver vm.Driver) (*Server, *httptest.Server) {
	t.Helper()
	server, err := NewServer(driver, testDecl(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)
	if fake, ok := driver.(*fakeDriver); ok {
		t.Cleanup(func() { close(fake.release) }) // runs before ts.Close
	}
	return server, ts
}

func enrolled(t *testing.T, url string, lease int64) *Client {
	t.Helper()
	client, err := NewClient("linux-1", url, testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	return client
}

func spec(id string) vm.Spec {
	return vm.Spec{ID: id, Image: "img-review", Network: "slot-1", CPUs: 2, MemoryMiB: 2048}
}

func TestRoundTrip(t *testing.T) {
	fake := newFake()
	fake.stdout = []byte("hello stdout")
	fake.stderr = bytes.Repeat([]byte("e"), 3*maxFrameData+17) // exercises chunking
	fake.exit = 7
	_, ts := serve(t, fake)
	ctx := context.Background()
	client, err := NewClient("linux-1", ts.URL, testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	decl, err := client.Enroll(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decl, testDecl()) {
		t.Fatalf("declaration = %+v", decl)
	}

	instance, err := client.Create(ctx, spec(vmA))
	if err != nil {
		t.Fatal(err)
	}
	if instance != (vm.Instance{ID: vmA, Running: true, Network: "slot-1"}) {
		t.Fatalf("instance = %+v", instance)
	}
	listed, err := client.List(ctx)
	if err != nil || len(listed) != 1 || listed[0] != instance {
		t.Fatalf("list = %+v, %v", listed, err)
	}

	payload := make([]byte, 300<<10+3)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(t.TempDir(), "upload.bin")
	if err := os.WriteFile(hostPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.CopyIn(ctx, vmA, hostPath, "/workspace/upload.bin"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.copied["/workspace/upload.bin"], payload) {
		t.Fatal("copied content differs")
	}
	if _, err := os.Stat(fake.staged[0]); !os.IsNotExist(err) {
		t.Fatalf("staged upload %s not removed: %v", fake.staged[0], err)
	}

	var stdout, stderr bytes.Buffer
	var pid int
	command := vm.Command{Args: []string{"git", "status"}, Dir: "/workspace", Env: map[string]string{"A": "b"}, User: "agent",
		OnStart: func(p int) { pid = p }}
	code, err := client.Run(ctx, vmA, command, &stdout, &stderr)
	if err != nil || code != 7 {
		t.Fatalf("run = %d, %v", code, err)
	}
	if pid != 4242 || stdout.String() != "hello stdout" || !bytes.Equal(stderr.Bytes(), fake.stderr) {
		t.Fatalf("pid %d stdout %q stderr %d bytes", pid, stdout.String(), stderr.Len())
	}
	if got := fake.ran[0]; !reflect.DeepEqual(got.Args, command.Args) || got.Dir != "/workspace" || got.Env["A"] != "b" || got.User != "agent" {
		t.Fatalf("driver ran %+v", got)
	}

	usage, err := client.Usage(ctx, vmA)
	if err != nil || usage != (vm.Usage{CPUUsedPct: 12.5, MemoryUsedBytes: 1 << 20, MemoryLimitBytes: 2 << 30}) {
		t.Fatalf("usage = %+v, %v", usage, err)
	}
	if err := client.Destroy(ctx, vmA); err != nil {
		t.Fatal(err)
	}
	if listed, err := client.List(ctx); err != nil || len(listed) != 0 {
		t.Fatalf("list after destroy = %+v, %v", listed, err)
	}
}

func TestCreateRefusesUndeclaredSpec(t *testing.T) {
	fake := newFake()
	_, ts := serve(t, fake)
	client := enrolled(t, ts.URL, 1)
	for name, mutate := range map[string]func(*vm.Spec){
		"image":   func(s *vm.Spec) { s.Image = "img-other" },
		"network": func(s *vm.Spec) { s.Network = "slot-9" },
		"cpus":    func(s *vm.Spec) { s.CPUs = 4 },
		"memory":  func(s *vm.Spec) { s.MemoryMiB = 4096 },
		"id":      func(s *vm.Spec) { s.ID = "../etc" },
	} {
		s := spec(vmA)
		mutate(&s)
		if _, err := client.Create(context.Background(), s); err == nil {
			t.Errorf("%s: create accepted %+v", name, s)
		}
	}
	if _, creates, _ := fake.count(); creates != 0 {
		t.Fatalf("driver saw %d creates", creates)
	}
}

func TestUsageWithoutMeter(t *testing.T) {
	_, ts := serve(t, plainDriver{newFake()})
	client := enrolled(t, ts.URL, 1)
	if _, err := client.Usage(context.Background(), vmA); !errors.Is(err, ErrNoMetrics) {
		t.Fatalf("usage error = %v", err)
	}
}

func TestLocal(t *testing.T) {
	decl := testDecl()
	member := Local(plainDriver{newFake()}, decl)
	got, err := member.Enroll(context.Background(), 1)
	if err != nil || !reflect.DeepEqual(got, decl) {
		t.Fatalf("enroll = %+v, %v", got, err)
	}
	got.Slots[0] = "mutated"
	again, _ := member.Enroll(context.Background(), 2)
	if again.Slots[0] != "slot-1" {
		t.Fatal("Enroll returned shared declaration state")
	}
	if _, err := member.Usage(context.Background(), vmA); !errors.Is(err, ErrNoMetrics) {
		t.Fatalf("usage error = %v", err)
	}
	if _, err := Local(newFake(), decl).Usage(context.Background(), vmA); err != nil {
		t.Fatalf("metered usage error = %v", err)
	}
	bad := testDecl()
	bad.Arch = "riscv64"
	if _, err := Local(newFake(), bad).Enroll(context.Background(), 1); err == nil {
		t.Fatal("Local enrolled an invalid declaration")
	}
}

func rawRequest(t *testing.T, method, url string, header http.Header, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAuthentication(t *testing.T) {
	fake := newFake()
	_, ts := serve(t, fake)
	for name, header := range map[string]http.Header{
		"missing": {},
		"wrong":   {"Authorization": {"Bearer wrong-key-0123456789"}},
		"two":     {"Authorization": {"Bearer " + testKey, "Bearer " + testKey}},
		"scheme":  {"Authorization": {"Basic " + testKey}},
		"bare":    {"Authorization": {testKey}},
	} {
		header.Set(leaseHeader, "5")
		if code := rawRequest(t, http.MethodPost, ts.URL+"/worker/v1/enroll", header, `{"lease":5}`); code != http.StatusUnauthorized {
			t.Errorf("%s enroll: status %d", name, code)
		}
		if code := rawRequest(t, http.MethodGet, ts.URL+"/worker/v1/vms", header, ""); code != http.StatusUnauthorized {
			t.Errorf("%s list: status %d", name, code)
		}
		if code := rawRequest(t, http.MethodGet, ts.URL+"/nope", header, ""); code != http.StatusUnauthorized {
			t.Errorf("%s unknown route: status %d", name, code)
		}
	}
	if calls, _, _ := fake.count(); calls != 0 {
		t.Fatalf("driver saw %d calls", calls)
	}
	// The unauthenticated enrollments must not have raised the lease floor.
	enrolled(t, ts.URL, 1)

	wrong, err := NewClient("linux-1", ts.URL, "another-key-0123456789", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Enroll(context.Background(), 9); err == nil {
		t.Fatal("wrong key enrolled")
	}
}

func TestRoutesAndLeaseHeader(t *testing.T) {
	fake := newFake()
	_, ts := serve(t, fake)
	header := func(lease string) http.Header {
		h := http.Header{"Authorization": {"Bearer " + testKey}}
		if lease != "" {
			h.Set(leaseHeader, lease)
		}
		return h
	}
	if code := rawRequest(t, http.MethodGet, ts.URL+"/worker/v1/vms", header("1"), ""); code != http.StatusConflict {
		t.Fatalf("before enrollment: status %d", code)
	}
	enrolled(t, ts.URL, 3)
	for _, tc := range []struct {
		method, path, lease string
		want                int
	}{
		{http.MethodGet, "/worker/v1/vms", "", http.StatusBadRequest},
		{http.MethodGet, "/worker/v1/vms", "x", http.StatusBadRequest},
		{http.MethodGet, "/worker/v1/vms", "2", http.StatusConflict},
		{http.MethodGet, "/worker/v1/vms", "4", http.StatusConflict},
		{http.MethodGet, "/worker/v1/vms", "3", http.StatusOK},
		{http.MethodGet, "/worker/v1/nope", "3", http.StatusNotFound},
		{http.MethodGet, "/worker/v1/vms/../../etc/usage", "3", http.StatusNotFound},
		{http.MethodGet, "/worker/v1/vms/sandboxd-XYZ/usage", "3", http.StatusNotFound},
		{http.MethodGet, "/worker/v1/vms/" + vmA + "/bogus", "3", http.StatusNotFound},
		{http.MethodPut, "/worker/v1/vms", "3", http.StatusMethodNotAllowed},
		{http.MethodGet, "/worker/v1/enroll", "3", http.StatusMethodNotAllowed},
		{http.MethodGet, "/worker/v1/vms/" + vmA, "3", http.StatusMethodNotAllowed},
		{http.MethodPut, "/worker/v1/vms/" + vmA + "/files?path=relative", "3", http.StatusBadRequest},
		{http.MethodPut, "/worker/v1/vms/" + vmA + "/files", "3", http.StatusBadRequest},
		{http.MethodPost, "/worker/v1/vms", "3", http.StatusBadRequest}, // empty JSON body
	} {
		if code := rawRequest(t, tc.method, ts.URL+tc.path, header(tc.lease), ""); code != tc.want {
			t.Errorf("%s %s lease %q: status %d, want %d", tc.method, tc.path, tc.lease, code, tc.want)
		}
	}
	if code := rawRequest(t, http.MethodPost, ts.URL+"/worker/v1/vms", header("3"),
		`{"id":"`+vmA+`","image":"img-review","network":"slot-1","cpus":2,"memoryMiB":2048,"extra":1}`); code != http.StatusBadRequest {
		t.Errorf("unknown JSON field: status %d", code)
	}
	if _, creates, _ := fake.count(); creates != 0 {
		t.Fatalf("driver saw %d creates", creates)
	}
}

func TestUploadCap(t *testing.T) {
	fake := newFake()
	server, ts := serve(t, fake)
	server.maxUpload = 1024
	client := enrolled(t, ts.URL, 1)
	if _, err := client.Create(context.Background(), spec(vmA)); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(hostPath, make([]byte, 1025), 0o600); err != nil {
		t.Fatal(err)
	}
	err := client.CopyIn(context.Background(), vmA, hostPath, "/big")
	if err == nil || !strings.Contains(err.Error(), "413") {
		t.Fatalf("oversized upload error = %v", err)
	}
	// A chunked body (no Content-Length) is capped while streaming.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/worker/v1/vms/"+vmA+"/files?path=/big", io.MultiReader(bytes.NewReader(make([]byte, 2048))))
	req.Header.Set("Authorization", "Bearer "+testKey)
	req.Header.Set(leaseHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized upload: status %d", resp.StatusCode)
	}
	if len(fake.copied) != 0 {
		t.Fatal("driver received an oversized upload")
	}
}

func TestEnrollRefusesForeignDeclaration(t *testing.T) {
	fake := newFake()
	server, err := NewServer(fake, testDecl(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		server.ServeHTTP(w, r)
	}))
	defer ts.Close()
	client, err := NewClient("mac-1", ts.URL, testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "linux-1") {
		t.Fatalf("enroll error = %v", err)
	}
	before := requests.Load()
	if _, err := client.List(context.Background()); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("list after refused enroll = %v", err)
	}
	if _, err := client.Create(context.Background(), spec(vmA)); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("create after refused enroll = %v", err)
	}
	if requests.Load() != before {
		t.Fatal("unenrolled client made network requests")
	}
}

func TestStaleLease(t *testing.T) {
	fake := newFake()
	_, ts := serve(t, fake)
	ctx := context.Background()
	a := enrolled(t, ts.URL, 1)
	if _, err := a.Create(ctx, spec(vmA)); err != nil {
		t.Fatal(err)
	}
	enrolled(t, ts.URL, 2)
	_, creates, destroys := fake.count()
	if _, err := a.List(ctx); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale list = %v", err)
	}
	if _, err := a.Create(ctx, spec(vmB)); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale create = %v", err)
	}
	if err := a.Destroy(ctx, vmA); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale destroy = %v", err)
	}
	if _, nowCreates, nowDestroys := fake.count(); nowCreates != creates || nowDestroys != destroys {
		t.Fatalf("stale client reached the driver: creates %d->%d destroys %d->%d", creates, nowCreates, destroys, nowDestroys)
	}
	if _, err := a.Enroll(ctx, 1); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("re-enroll with old lease = %v", err)
	}
	if _, err := a.List(ctx); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("list after refused re-enroll = %v", err)
	}
}

func TestReenrollmentCancelsRun(t *testing.T) {
	fake := newFake()
	fake.stdout = []byte("partial")
	fake.blockRun = true
	_, ts := serve(t, fake)
	ctx := context.Background()
	a := enrolled(t, ts.URL, 1)
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	var stdout bytes.Buffer
	go func() {
		code, err := a.Run(ctx, vmA, vm.Command{Args: []string{"sleep", "infinity"}}, &stdout, io.Discard)
		done <- result{code, err}
	}()
	<-fake.runStarted
	enrolled(t, ts.URL, 2)
	select {
	case err := <-fake.runCtxErr:
		if err == nil {
			t.Fatal("run context not cancelled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("re-enrollment did not cancel the in-flight run")
	}
	select {
	case got := <-done:
		if !errors.Is(got.err, ErrStaleLease) {
			t.Fatalf("stale run = %d, %v", got.code, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale run did not return")
	}
	if stdout.String() != "partial" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

func TestRunWriterErrorAborts(t *testing.T) {
	fake := newFake()
	fake.stdout = []byte("data")
	fake.blockRun = true
	_, ts := serve(t, fake)
	client := enrolled(t, ts.URL, 1)
	sentinel := errors.New("disk full")
	_, err := client.Run(context.Background(), vmA, vm.Command{Args: []string{"cat"}}, failingWriter{sentinel}, io.Discard)
	if !errors.Is(err, sentinel) {
		t.Fatalf("run error = %v", err)
	}
	select {
	case <-fake.runCtxErr:
	case <-time.After(5 * time.Second):
		t.Fatal("remote run was not cancelled after the writer failed")
	}
}

func frame(kind byte, data string) []byte {
	out := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(data)))
	return append(out, data...)
}

func TestTruncatedRunStream(t *testing.T) {
	for name, stream := range map[string][]byte{
		"no terminal frame": frame('o', "partial"),
		"short payload":     append(frame('o', "ok"), frame('x', "0")[:5]...),
		"short header":      append(frame('o', "ok"), 'x', 0),
		"empty":             nil,
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/worker/v1/enroll" {
					_ = json.NewEncoder(w).Encode(testDecl())
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(stream)
			}))
			defer ts.Close()
			client := enrolled(t, ts.URL, 1)
			code, err := client.Run(context.Background(), vmA, vm.Command{Args: []string{"true"}}, io.Discard, io.Discard)
			if err == nil {
				t.Fatalf("truncated stream returned exit code %d", code)
			}
		})
	}
}

func TestNewClientURL(t *testing.T) {
	for _, url := range []string{"https://worker-1.tailnet.ts.net", "https://worker-1.tailnet.ts.net:8443/base/", "http://127.0.0.1:8080", "http://[::1]:9"} {
		if _, err := NewClient("linux-1", url, testKey, nil); err != nil {
			t.Errorf("%s rejected: %v", url, err)
		}
	}
	for _, url := range []string{"http://worker-1.tailnet.ts.net", "http://10.0.0.1:8080", "http://localhost:8080", "ftp://127.0.0.1",
		"https://user:pw@worker", "https://worker?x=1", "https://", "worker:8080"} {
		if _, err := NewClient("linux-1", url, testKey, nil); err == nil {
			t.Errorf("%s accepted", url)
		}
	}
	if _, err := NewClient("linux-1", "https://w", "short", nil); err == nil {
		t.Error("short key accepted")
	}
	if _, err := NewClient("Linux_1", "https://w", testKey, nil); err == nil {
		t.Error("bad worker id accepted")
	}
}

func TestDeclarationValidate(t *testing.T) {
	if err := testDecl().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Declaration){
		"bad id":          func(d *Declaration) { d.ID = "Linux-1" },
		"empty id":        func(d *Declaration) { d.ID = "" },
		"long id":         func(d *Declaration) { d.ID = "a" + strings.Repeat("b", 63) },
		"bad arch":        func(d *Declaration) { d.Arch = "x86_64" },
		"no driver":       func(d *Declaration) { d.Driver = "" },
		"no templates":    func(d *Declaration) { d.Templates = nil },
		"empty image":     func(d *Declaration) { d.Templates = map[string]string{"t": ""} },
		"empty template":  func(d *Declaration) { d.Templates = map[string]string{"": "img"} },
		"zero cpus":       func(d *Declaration) { d.CPUs = 0 },
		"small memory":    func(d *Declaration) { d.MemoryMiB = 64 },
		"zero max":        func(d *Declaration) { d.MaxVMs = 0 },
		"max over slots":  func(d *Declaration) { d.MaxVMs = 3 },
		"duplicate slots": func(d *Declaration) { d.Slots = []string{"slot-1", "slot-1"} },
		"empty slot":      func(d *Declaration) { d.Slots = []string{"slot-1", ""} },
	} {
		d := testDecl()
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, d)
		}
	}
}
