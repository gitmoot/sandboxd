package envd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	e2bID           = "sandboxd-00000000000000000000000000000e2b"
	strictID        = "sandboxd-0000000000000000000000000000057c"
	e2bToken        = "e2b-token"
	e2bTrafficToken = "e2b-traffic-token"
	exposedPort     = 49999
)

// fakeE2B serves one e2b sandbox whose envd is upstream, an HTTP server
// reached only through DialPort.
type fakeE2B struct {
	upstream *httptest.Server
	dials    int
	ports    []int
}

func (f *fakeE2B) IsE2B(id string) bool { return id == e2bID }
func (f *fakeE2B) AuthorizeEnvd(id, token string) bool {
	return id == e2bID && token == e2bToken
}
func (f *fakeE2B) EnvdToken(id string) (string, bool) { return e2bToken, id == e2bID }
func (f *fakeE2B) AuthorizeTraffic(id, token string) bool {
	return id == e2bID && token == e2bTrafficToken
}
func (f *fakeE2B) SignedSandbox(signed func(string) bool) (string, bool) {
	return e2bID, signed(e2bToken)
}
func (f *fakeE2B) Exposes(id string, port int) bool { return id == e2bID && port == exposedPort }
func (f *fakeE2B) DialPort(ctx context.Context, id string, port int) (net.Conn, error) {
	f.ports = append(f.ports, port)
	f.dials++
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", f.upstream.Listener.Addr().String())
}

func newProxyFixture(t *testing.T) (http.Handler, *fakeE2B, chan *http.Request) {
	t.Helper()
	seen := make(chan *http.Request, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		seen <- r
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"envd":"`+r.URL.Path+`"}`)
	}))
	t.Cleanup(upstream.Close)
	fake := &fakeE2B{upstream: upstream}
	strict := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "strict", http.StatusTeapot) })
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "api", http.StatusNotFound) })
	return Routes(strict, NewProxy(fake, "sandboxd.test", "gateway.test"), api), fake, seen
}

func envdRequest(method, target, id, token string) *http.Request {
	r := httptest.NewRequest(method, "http://gateway.test"+target, strings.NewReader("{}"))
	r.Header.Set("E2b-Sandbox-Id", id)
	r.Header.Set("E2b-Sandbox-Port", "49983")
	if token != "" {
		r.Header.Set("X-Access-Token", token)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestProxyForwardsE2BEnvdTrafficOnly(t *testing.T) {
	routes, fake, seen := newProxyFixture(t)
	for _, path := range []string{"/process.Process/List", "/filesystem.Filesystem/ListDir", "/files?path=/home/user/a", "/health"} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodPost, path, e2bID, e2bToken))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"envd"`) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		forwarded := <-seen
		if forwarded.Header.Get("E2b-Sandbox-Id") != "" || forwarded.Header.Get("X-Access-Token") != e2bToken {
			t.Fatalf("%s: forwarded headers %v", path, forwarded.Header)
		}
	}
	// envd's internal routes never reach the guest from a client.
	for _, path := range []string{"/init", "/freeze", "/metrics", "/process.Process/", "/filesystem.Filesystem/a/b"} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodPost, path, e2bID, e2bToken))
		if strings.Contains(w.Body.String(), `"envd"`) {
			t.Fatalf("%s reached envd", path)
		}
	}
	// A strict sandbox keeps the strict handler.
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, envdRequest(http.MethodPost, "/process.Process/Start", strictID, "strict-token"))
	if w.Code != http.StatusTeapot {
		t.Fatalf("strict sandbox: %d %s", w.Code, w.Body)
	}
	if fake.dials == 0 {
		t.Fatal("proxy never dialed envd")
	}
}

func TestProxyRequiresTokenOrSignature(t *testing.T) {
	routes, _, seen := newProxyFixture(t)
	for _, token := range []string{"", "wrong"} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodPost, "/process.Process/List", e2bID, token))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", token, w.Code)
		}
		w = httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodGet, "/health", e2bID, token))
		if w.Code != http.StatusBadGateway {
			t.Fatalf("health with token %q: %d", token, w.Code)
		}
	}
	sign := func(path, op, user string, expiration string) string {
		raw := path + ":" + op + ":" + user + ":" + e2bToken
		if expiration != "" {
			raw += ":" + expiration
		}
		sum := sha256.Sum256([]byte(raw))
		return url.QueryEscape("v1_" + base64.RawStdEncoding.EncodeToString(sum[:]))
	}
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	cases := []struct {
		method, query string
		ok            bool
	}{
		{http.MethodGet, "path=a.txt&signature=" + sign("a.txt", "read", "", ""), true},
		{http.MethodPost, "path=a.txt&username=root&signature=" + sign("a.txt", "write", "root", future) + "&signature_expiration=" + future, true},
		{http.MethodPost, "path=a.txt&signature=" + sign("a.txt", "read", "", ""), false},
		{http.MethodGet, "path=b.txt&signature=" + sign("a.txt", "read", "", ""), false},
		{http.MethodGet, "path=a.txt&signature=" + sign("a.txt", "read", "", past) + "&signature_expiration=" + past, false},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(c.method, "/files?"+c.query, e2bID, ""))
		if (w.Code == http.StatusOK) != c.ok {
			t.Fatalf("%s %s: %d", c.method, c.query, w.Code)
		}
		if c.ok {
			<-seen
		}
	}
}

type brokenBody struct{ data []byte }

func (b *brokenBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}
func (b *brokenBody) Close() error { return nil }

func TestConnectStreamEndsBrokenStreamsAsUnavailable(t *testing.T) {
	message := append([]byte{0, 0, 0, 0, 2}, "{}"...)
	stream := &connectStream{body: &brokenBody{data: message}}
	got, err := io.ReadAll(stream)
	if err != nil || !strings.HasPrefix(string(got), string(message)) || got[len(message)] != streamEndFlag ||
		!strings.Contains(string(got[len(message)+5:]), `"code":"unavailable"`) {
		t.Fatalf("broken at a boundary: %q, %v", got, err)
	}
	// Mid-message the break stays a transport failure.
	stream = &connectStream{body: &brokenBody{data: message[:6]}}
	if _, err := io.ReadAll(stream); err == nil {
		t.Fatal("a truncated message ended cleanly")
	}
}

// Only identifier method names reach envd, judged on the path as sent:
// dot segments and percent-encoded bytes never do.
func TestProxyRejectsDotAndEncodedRoutes(t *testing.T) {
	routes, fake, _ := newProxyFixture(t)
	for _, path := range []string{
		"/process.Process/..", "/process.Process/.", "/filesystem.Filesystem/..",
		"/process.Process/%2e%2e", "/process.Process/%2E", "/filesystem.Filesystem/%2e%2e",
		"/process.Process/%53tart", "/filesystem.Filesystem/List%44ir", "/process.Process/Start%2f..",
		"/fil%65s", "/h%65alth", "/process.Process/start", "/process.Process/Start_x", "/process.Process/Start.",
	} {
		before := fake.dials
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodPost, path, e2bID, e2bToken))
		if fake.dials != before || strings.Contains(w.Body.String(), `"envd"`) || w.Code == http.StatusOK {
			t.Errorf("%s reached envd: %d %s", path, w.Code, w.Body)
		}
	}
	for _, path := range []string{"/process.Process/SendInput", "/filesystem.Filesystem/CreateWatcher"} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, envdRequest(http.MethodPost, path, e2bID, e2bToken))
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}
