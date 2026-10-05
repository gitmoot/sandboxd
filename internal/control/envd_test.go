package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// testEnvd stands in for every test guest's envd: it accepts /init and
// records each body by access token.
var testEnvd = struct {
	once   sync.Once
	server *httptest.Server
	mu     sync.Mutex
	inits  map[string]envdInit
	// runs records Process/Start commands by access token; readyAfter
	// makes the ready command fail that many times first.
	runs       map[string][]string
	readyFails int
}{inits: map[string]envdInit{}, runs: map[string][]string{}}

func dialTestEnvd(ctx context.Context) (net.Conn, error) {
	testEnvd.once.Do(func() {
		testEnvd.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/process.Process/Start" {
				serveTestStart(w, r)
				return
			}
			var body envdInit
			if r.URL.Path != "/init" || json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, "bad init", http.StatusBadRequest)
				return
			}
			testEnvd.mu.Lock()
			testEnvd.inits[body.AccessToken] = body
			testEnvd.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
	})
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", testEnvd.server.Listener.Addr().String())
}

// serveTestStart answers a Connect Process/Start stream: start, then the
// end event (exit 0, or 1 while readyFails lasts for "ready" commands).
func serveTestStart(w http.ResponseWriter, r *http.Request) {
	frame, err := io.ReadAll(r.Body)
	var start struct {
		Process struct {
			Args []string `json:"args"`
		} `json:"process"`
	}
	if err != nil || len(frame) < 5 || json.Unmarshal(frame[5:], &start) != nil || len(start.Process.Args) != 3 ||
		r.Header.Get("Authorization") != "Basic cm9vdDo=" {
		http.Error(w, "bad start", http.StatusBadRequest)
		return
	}
	command := start.Process.Args[2]
	exit := 0
	testEnvd.mu.Lock()
	testEnvd.runs[r.Header.Get("X-Access-Token")] = append(testEnvd.runs[r.Header.Get("X-Access-Token")], command)
	if strings.HasPrefix(command, "ready") && testEnvd.readyFails > 0 {
		testEnvd.readyFails--
		exit = 1
	}
	testEnvd.mu.Unlock()
	w.Header().Set("Content-Type", "application/connect+json")
	for _, event := range []string{`{"event":{"start":{"pid":7}}}`, `{"event":{"end":{"exitCode":` + strconv.Itoa(exit) + `,"exited":true,"status":"exit"}}}`} {
		_, _ = w.Write(append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(event))), event...))
	}
	_, _ = w.Write(append(binary.BigEndian.AppendUint32([]byte{2}, 2), "{}"...))
}

func testEnvdInit(token string) (envdInit, bool) {
	testEnvd.mu.Lock()
	defer testEnvd.mu.Unlock()
	init, ok := testEnvd.inits[token]
	return init, ok
}

func (d *fakeDriver) DialPort(ctx context.Context, id string, _ int) (net.Conn, error) {
	d.mu.Lock()
	_, ok := d.instances[id]
	d.mu.Unlock()
	if !ok {
		return nil, vm.ErrNoEnvd
	}
	return dialTestEnvd(ctx)
}

func (d *fileDriver) DialPort(ctx context.Context, _ string, _ int) (net.Conn, error) {
	return dialTestEnvd(ctx)
}

// TestE2BCreateInitializesEnvdWithoutStoringEnvVars: create-time envVars
// reach envd's /init with the sandbox's token and defaults, and never the
// ledger.
func TestE2BCreateInitializesEnvdWithoutStoringEnvVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	s := openAt(t, path, &fakeDriver{instances: map[string]vm.Instance{}}, mixedConfig(e2bBase, 3))
	const secret = "envvar-secret-7d1f0c"
	got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base", "envVars": map[string]string{"API_SECRET": secret}})
	if got.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", got.Code, got.Body)
	}
	var created struct {
		SandboxID       string `json:"sandboxID"`
		EnvdAccessToken string `json:"envdAccessToken"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	init, ok := testEnvdInit(created.EnvdAccessToken)
	if !ok || init.EnvVars["API_SECRET"] != secret || init.DefaultUser != "user" || init.DefaultWorkdir != "/home/user" {
		t.Fatalf("envd /init = %+v, %v", init, ok)
	}
	if !s.AuthorizeEnvd(created.SandboxID, created.EnvdAccessToken) || s.Authorize(created.SandboxID, created.EnvdAccessToken) {
		t.Fatal("an e2b token must open only the e2b data plane")
	}
	if token, ok := s.EnvdToken(created.SandboxID); !ok || token != created.EnvdAccessToken || !s.IsE2B(created.SandboxID) {
		t.Fatal("EnvdToken does not re-derive the sandbox token")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) || strings.Contains(string(data), "API_SECRET") {
			t.Fatalf("%s stores the envVars", entry.Name())
		}
	}
}

// A template's start command runs once, in the background, and its ready
// command until it exits 0, as root, before the create returns; its exposed
// ports open with the issued traffic token and no other port does.
func TestE2BTemplateStartReadyAndPorts(t *testing.T) {
	templates := map[string]Template{"ci": {Image: "linux-arm64", Profile: ProfileE2B, EnvdVersion: "0.9.0",
		Aliases: []string{"code-interpreter-v1"}, Ports: []int{49999}, StartCmd: "start-server", ReadyCmd: "ready-check"}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), &fakeDriver{instances: map[string]vm.Instance{}}, mixedConfig(templates, 3))
	testEnvd.mu.Lock()
	testEnvd.readyFails = 2
	testEnvd.mu.Unlock()
	got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "code-interpreter-v1", "network": map[string]any{"allowPublicTraffic": false}})
	if got.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", got.Code, got.Body)
	}
	var created struct {
		SandboxID          string `json:"sandboxID"`
		EnvdAccessToken    string `json:"envdAccessToken"`
		TrafficAccessToken string `json:"trafficAccessToken"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	testEnvd.mu.Lock()
	runs := slices.Clone(testEnvd.runs[created.EnvdAccessToken])
	testEnvd.mu.Unlock()
	if !slices.Equal(runs, []string{"start-server", "ready-check", "ready-check", "ready-check"}) {
		t.Fatalf("commands run: %q", runs)
	}
	id := created.SandboxID
	if created.TrafficAccessToken == "" || created.TrafficAccessToken == created.EnvdAccessToken ||
		!s.AuthorizeTraffic(id, created.TrafficAccessToken) || s.AuthorizeTraffic(id, created.EnvdAccessToken) ||
		s.AuthorizeEnvd(id, created.TrafficAccessToken) {
		t.Fatal("the traffic token must be distinct and open guest ports only")
	}
	if !s.Exposes(id, 49999) || s.Exposes(id, 8080) || s.Exposes(id, 49983) {
		t.Fatal("only the template's ports are exposed")
	}
	for _, network := range []map[string]any{{"allowPublicTraffic": true}, {}, {"allowPublicTraffic": false, "denyOut": []string{"0.0.0.0/0"}}} {
		if got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "ci", "network": network}); got.Code != http.StatusBadRequest {
			t.Fatalf("network %v: %d %s", network, got.Code, got.Body)
		}
	}
	if found, ok := s.SignedSandbox(func(token string) bool { return token == created.EnvdAccessToken }); !ok || found != id {
		t.Fatalf("SignedSandbox = %q, %v", found, ok)
	}
}

// SignedSandbox answers from the in-memory index of running e2b sandboxes:
// without the ledger or mu (it answers while mu is held), only for a
// running sandbox, and again after a restart.
func TestSignedSandboxIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	driver := &fakeDriver{instances: map[string]vm.Instance{}}
	s, err := Open(context.Background(), path, driver, mixedConfig(e2bBase, 3))
	if err != nil {
		t.Fatal(err)
	}
	create := func() (string, string) {
		got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base"})
		if got.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", got.Code, got.Body)
		}
		var created struct {
			SandboxID       string `json:"sandboxID"`
			EnvdAccessToken string `json:"envdAccessToken"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		return created.SandboxID, created.EnvdAccessToken
	}
	signedBy := func(s *Service, token string) (string, bool) {
		return s.SignedSandbox(func(candidate string) bool { return candidate == token })
	}
	kept, keptToken := create()
	deleted, deletedToken := create()
	s.mu.Lock()
	found := make(chan string, 1)
	go func() {
		id, _ := signedBy(s, keptToken)
		found <- id
	}()
	select {
	case id := <-found:
		if id != kept {
			t.Fatalf("SignedSandbox = %q, want %q", id, kept)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SignedSandbox waited for mu")
	}
	s.mu.Unlock()
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+deleted, nil); got.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", got.Code, got.Body)
	}
	if id, ok := signedBy(s, deletedToken); ok {
		t.Fatalf("a deleted sandbox still matches: %q", id)
	}
	if id, ok := signedBy(s, "not-a-token"); ok {
		t.Fatalf("an unknown token matches %q", id)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openAt(t, path, driver, mixedConfig(e2bBase, 3))
	if id, ok := signedBy(reopened, keptToken); !ok || id != kept {
		t.Fatalf("after a restart SignedSandbox = %q, %v", id, ok)
	}
	if _, ok := signedBy(reopened, deletedToken); ok {
		t.Fatal("after a restart a deleted sandbox matches")
	}
}

// Config.ReadyTimeout (-template-ready-timeout) bounds the ready command
// polling: a template that never becomes ready fails the create with 503 and
// its sandbox is destroyed.
func TestE2BTemplateReadyTimeout(t *testing.T) {
	templates := map[string]Template{"ci": {Image: "linux-arm64", Profile: ProfileE2B, EnvdVersion: "0.9.0",
		Ports: []int{49999}, ReadyCmd: "ready-check"}}
	driver := &fakeDriver{instances: map[string]vm.Instance{}}
	cfg := mixedConfig(templates, 3)
	cfg.ReadyTimeout = 600 * time.Millisecond
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	testEnvd.mu.Lock()
	testEnvd.readyFails = 1 << 20
	testEnvd.mu.Unlock()
	defer func() {
		testEnvd.mu.Lock()
		testEnvd.readyFails = 0
		testEnvd.mu.Unlock()
	}()
	started := time.Now()
	got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "ci"})
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("create: %d %s", got.Code, got.Body)
	}
	if took := time.Since(started); took < cfg.ReadyTimeout || took > 10*time.Second {
		t.Fatalf("create gave up after %s with a %s ready timeout", took, cfg.ReadyTimeout)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.destroyed) != 1 {
		t.Fatalf("destroyed %q, want the one sandbox", driver.destroyed)
	}
}
