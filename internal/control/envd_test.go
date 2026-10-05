package control

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// testEnvd stands in for every test guest's envd: it accepts /init and
// records each body by access token.
var testEnvd = struct {
	once   sync.Once
	server *httptest.Server
	mu     sync.Mutex
	inits  map[string]envdInit
}{inits: map[string]envdInit{}}

func dialTestEnvd(ctx context.Context) (net.Conn, error) {
	testEnvd.once.Do(func() {
		testEnvd.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func testEnvdInit(token string) (envdInit, bool) {
	testEnvd.mu.Lock()
	defer testEnvd.mu.Unlock()
	init, ok := testEnvd.inits[token]
	return init, ok
}

func (d *fakeDriver) DialEnvd(ctx context.Context, id string) (net.Conn, error) {
	d.mu.Lock()
	_, ok := d.instances[id]
	d.mu.Unlock()
	if !ok {
		return nil, vm.ErrNoEnvd
	}
	return dialTestEnvd(ctx)
}

func (d *fileDriver) DialEnvd(ctx context.Context, _ string) (net.Conn, error) {
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
