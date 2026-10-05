package envd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func portRequest(host, id string, port int, header, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/execute", nil)
	if id != "" {
		r.Header.Set("E2b-Sandbox-Id", id)
		r.Header.Set("E2b-Sandbox-Port", strconv.Itoa(port))
	}
	if header != "" {
		r.Header.Set(header, token)
	}
	return r
}

func decodeGuestError(t *testing.T, w *httptest.ResponseRecorder) guestError {
	t.Helper()
	var body guestError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %s: %v", w.Code, w.Body, err)
	}
	return body
}

// Exposed guest ports are reached through the gateway with E2B's routing
// headers and either token, never without one, and never beyond the
// template's allowlist.
func TestPortProxyNeedsTokenAndAllowlist(t *testing.T) {
	routes, fake, seen := newProxyFixture(t)
	for _, auth := range [][2]string{{trafficTokenHeader, e2bTrafficToken}, {"X-Access-Token", e2bToken}} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, portRequest("gateway.test", e2bID, exposedPort, auth[0], auth[1]))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", auth[0], w.Code, w.Body)
		}
		forwarded := <-seen
		if forwarded.Header.Get(trafficTokenHeader) != "" || forwarded.Header.Get("E2b-Sandbox-Id") != "" || forwarded.Host != "gateway.test" {
			t.Fatalf("forwarded routing or traffic headers: %v host %q", forwarded.Header, forwarded.Host)
		}
	}
	if len(fake.ports) == 0 || slices.ContainsFunc(fake.ports, func(port int) bool { return port != exposedPort }) {
		t.Fatalf("dialed ports %v", fake.ports)
	}
	refusals := []struct {
		name           string
		request        *http.Request
		status         int
		messageContain string
	}{
		{"no token", portRequest("gateway.test", e2bID, exposedPort, "", ""), http.StatusForbidden, "is missing"},
		{"wrong traffic token", portRequest("gateway.test", e2bID, exposedPort, trafficTokenHeader, e2bToken), http.StatusForbidden, "is invalid"},
		{"wrong access token", portRequest("gateway.test", e2bID, exposedPort, "X-Access-Token", e2bTrafficToken), http.StatusForbidden, "is invalid"},
		{"port not exposed", portRequest("gateway.test", e2bID, 22, trafficTokenHeader, e2bTrafficToken), http.StatusForbidden, "does not expose"},
		{"unknown sandbox", portRequest("gateway.test", "sandboxd-ffffffffffffffffffffffffffffffff", exposedPort, trafficTokenHeader, e2bTrafficToken), http.StatusBadGateway, "not found"},
		{"strict sandbox", portRequest("gateway.test", strictID, exposedPort, trafficTokenHeader, e2bTrafficToken), http.StatusBadGateway, "not found"},
	}
	for _, refusal := range refusals {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, refusal.request)
		body := decodeGuestError(t, w)
		if w.Code != refusal.status || body.Code != refusal.status || !strings.Contains(body.Message, refusal.messageContain) {
			t.Fatalf("%s: %d %+v", refusal.name, w.Code, body)
		}
	}
	select {
	case r := <-seen:
		t.Fatalf("a refused request reached the guest: %v", r.URL)
	default:
	}
}

// "<port>-<id>.<domain>" reaches a guest port only when PortHosts is on;
// envd's own wildcard host is always routed.
func TestPortHostsRoutingIsOptIn(t *testing.T) {
	fake := &fakeE2B{upstream: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))}
	t.Cleanup(fake.upstream.Close)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "api", http.StatusNotFound) })
	proxy := NewProxy(fake, "sandboxd.test", "gateway.test")
	routes := Routes(http.NotFoundHandler(), proxy, api)
	host := strconv.Itoa(exposedPort) + "-" + e2bID + ".sandboxd.test"
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, portRequest(host, "", 0, trafficTokenHeader, e2bTrafficToken))
	if w.Code != http.StatusNotFound || len(fake.ports) != 0 {
		t.Fatalf("host routing without PortHosts: %d, dialed %v", w.Code, fake.ports)
	}
	proxy.PortHosts = true
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, portRequest(host, "", 0, trafficTokenHeader, e2bTrafficToken))
	if w.Code != http.StatusOK || !slices.Equal(fake.ports, []int{exposedPort}) {
		t.Fatalf("host routing with PortHosts: %d %s, dialed %v", w.Code, w.Body, fake.ports)
	}
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, portRequest(host, "", 0, "", ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("host routing without a token: %d", w.Code)
	}
}

// refusingE2B is fakeE2B whose guest ports are closed.
type refusingE2B struct{ fakeE2B }

func (f *refusingE2B) DialPort(context.Context, string, int) (net.Conn, error) {
	return nil, errors.New("guest port unreachable: connection refused")
}

// A full-duplex request (any guest port request, an envd Connect stream)
// whose upstream refuses it gets its 502 and leaves the client's keep-alive
// connection usable: the unread request body used to make net/http panic on
// the connection's next read ("invalid concurrent Body.Read call") and drop
// it, which clients retrying a restarting server saw as broken connections.
func TestRefusedFullDuplexRequestKeepsConnection(t *testing.T) {
	var logged strings.Builder
	var logMu sync.Mutex
	server := httptest.NewUnstartedServer(Routes(http.NotFoundHandler(), NewProxy(&refusingE2B{}, "sandboxd.test", "127.0.0.1"), http.NotFoundHandler()))
	server.Config.ErrorLog = log.New(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logged.Write(p)
	}), "", 0)
	server.Start()
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	requests := []string{
		fmt.Sprintf("E2b-Sandbox-Port: %d\r\nE2b-Traffic-Access-Token: %s\r\nContent-Type: application/json", exposedPort, e2bTrafficToken),
		fmt.Sprintf("E2b-Sandbox-Port: %d\r\nX-Access-Token: %s\r\nContent-Type: application/connect+json", EnvdPort, e2bToken),
	}
	for i := range 6 {
		body := `{"code":"x = 1; x"}`
		path := "/execute"
		if i%2 == 1 {
			path = "/process.Process/Start"
		}
		_, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nE2b-Sandbox-Id: %s\r\n%s\r\nContent-Length: %d\r\n\r\n%s",
			path, e2bID, requests[i%2], len(body), body)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			logMu.Lock()
			defer logMu.Unlock()
			t.Fatalf("request %d on one connection: %v; server log: %s", i, err, logged.String())
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("request %d: %d", i, response.StatusCode)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestSandboxHostPort(t *testing.T) {
	for host, want := range map[string]string{
		"49999-" + e2bID + ".sandboxd.test":      e2bID + " 49999",
		"8000-" + e2bID + ".SANDBOXD.test.:8443": e2bID + " 8000",
		"0-" + e2bID + ".sandboxd.test":          "",
		"08000-" + e2bID + ".sandboxd.test":      "",
		"70000-" + e2bID + ".sandboxd.test":      "",
		"8000-" + e2bID + ".other.test":          "",
		"8000-" + e2bID + ".a.sandboxd.test":     "",
	} {
		id, port, ok := sandboxHostPort(host, "sandboxd.test:8443")
		got := ""
		if ok {
			got = id + " " + strconv.Itoa(port)
		}
		if got != want {
			t.Fatalf("%s: %q, want %q", host, got, want)
		}
	}
}

func signedURL(path, operation, user string, expires int64) string {
	raw := path + ":" + operation + ":" + user + ":" + e2bToken + ":" + strconv.FormatInt(expires, 10)
	sum := sha256.Sum256([]byte(raw))
	return "/files?path=" + path + "&username=" + user + "&signature=" + url.QueryEscape("v1_"+base64.RawStdEncoding.EncodeToString(sum[:])) +
		"&signature_expiration=" + strconv.FormatInt(expires, 10)
}

// A signed file URL built from E2B_SANDBOX_URL carries no routing headers;
// the signature alone selects the sandbox, and an expired one gets envd's
// own refusal.
func TestSignedFileURLWithoutRoutingHeaders(t *testing.T) {
	routes, _, seen := newProxyFixture(t)
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://gateway.test"+signedURL("a.txt", "read", "user", time.Now().Add(time.Minute).Unix()), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("signed download: %d %s", w.Code, w.Body)
	}
	if forwarded := <-seen; forwarded.URL.Query().Get("path") != "a.txt" {
		t.Fatalf("forwarded %v", forwarded.URL)
	}
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://gateway.test"+signedURL("a.txt", "read", "user", time.Now().Add(-time.Minute).Unix()), nil))
	if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"code":401,"message":"signature is already expired"}` {
		t.Fatalf("expired: %d %s", w.Code, w.Body)
	}
	// A signature for another operation, or none of this sandbox's, is
	// left to the strict handler, never routed to an e2b sandbox.
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://gateway.test"+signedURL("a.txt", "read", "user", time.Now().Add(time.Minute).Unix()), nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("mismatched operation was not left to the strict handler: %d %s", w.Code, w.Body)
	}
	select {
	case r := <-seen:
		t.Fatalf("an unsigned request reached envd: %v", r.URL)
	default:
	}
}

// countingE2B is fakeE2B that counts signed-URL lookups.
type countingE2B struct {
	fakeE2B
	lookups int
}

func (f *countingE2B) SignedSandbox(signed func(string) bool) (string, bool) {
	f.lookups++
	return f.fakeE2B.SignedSandbox(signed)
}

// A signed file URL that names no sandbox and cannot be valid (wrong shape,
// unparsable expiration) or has expired is refused before any sandbox is
// looked at; only a well-formed, unexpired one is matched.
func TestUnroutedSignatureRefusedBeforeLookup(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "file") }))
	t.Cleanup(upstream.Close)
	fake := &countingE2B{fakeE2B: fakeE2B{upstream: upstream}}
	strict := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "strict", http.StatusTeapot) })
	routes := Routes(strict, NewProxy(fake, "sandboxd.test", "gateway.test"), http.NotFoundHandler())
	future := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	shaped := "v1_" + strings.Repeat("A", 43)
	for _, refusal := range []struct {
		name, query string
		status      int
	}{
		{"short signature", "signature=v1_abc&signature_expiration=" + future, http.StatusTeapot},
		{"wrong version", "signature=v2_" + strings.Repeat("A", 43) + "&signature_expiration=" + future, http.StatusTeapot},
		{"unparsable expiration", "signature=" + shaped + "&signature_expiration=soon", http.StatusTeapot},
		{"expired", "signature=" + shaped + "&signature_expiration=1", http.StatusUnauthorized},
	} {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://gateway.test/files?path=a.txt&username=user&"+refusal.query, nil))
		if w.Code != refusal.status || fake.lookups != 0 {
			t.Fatalf("%s: %d %s after %d lookups", refusal.name, w.Code, w.Body, fake.lookups)
		}
	}
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://gateway.test"+signedURL("a.txt", "read", "user", time.Now().Add(time.Minute).Unix()), nil))
	if w.Code != http.StatusOK || fake.lookups != 1 {
		t.Fatalf("valid signature: %d %s after %d lookups", w.Code, w.Body, fake.lookups)
	}
}

// The guest port and envd proxies never pass sandboxd's routing headers or
// gateway and client credentials to the guest. A guest port keeps only the
// envd access token (E2B's code-interpreter server reads it); envd keeps its
// token and the Basic user in Authorization.
func TestProxiesStripGatewayCredentials(t *testing.T) {
	routes, _, seen := newProxyFixture(t)
	credentials := map[string]string{"X-Api-Key": "control-secret", "Authorization": "Basic cm9vdDo=", "Cookie": "session=secret",
		"Proxy-Authorization": "Basic cHJveHk6c2VjcmV0"}
	never := []string{"X-Api-Key", "Cookie", "Proxy-Authorization", trafficTokenHeader, "E2b-Sandbox-Id", "E2b-Sandbox-Port"}
	check := func(name string, forwarded *http.Request, absent []string, kept map[string]string) {
		t.Helper()
		for _, header := range absent {
			if value := forwarded.Header.Get(header); value != "" {
				t.Fatalf("%s: the guest saw %s=%q", name, header, value)
			}
		}
		for header, want := range kept {
			if got := forwarded.Header.Get(header); got != want {
				t.Fatalf("%s: the guest saw %s=%q, want %q", name, header, got, want)
			}
		}
	}
	for _, auth := range [][2]string{{trafficTokenHeader, e2bTrafficToken}, {"X-Access-Token", e2bToken}} {
		r := portRequest("gateway.test", e2bID, exposedPort, auth[0], auth[1])
		for header, value := range credentials {
			r.Header.Set(header, value)
		}
		r.Header.Set("X-Custom", "app")
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("port via %s: %d %s", auth[0], w.Code, w.Body)
		}
		kept := map[string]string{"X-Custom": "app"}
		if auth[0] == "X-Access-Token" {
			kept["X-Access-Token"] = e2bToken
		}
		check("port via "+auth[0], <-seen, append(slices.Clone(never), "Authorization"), kept)
	}
	r := envdRequest(http.MethodPost, "/process.Process/List", e2bID, e2bToken)
	for header, value := range credentials {
		r.Header.Set(header, value)
	}
	r.Header.Set(trafficTokenHeader, e2bTrafficToken)
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("envd: %d %s", w.Code, w.Body)
	}
	check("envd", <-seen, never, map[string]string{"X-Access-Token": e2bToken, "Authorization": credentials["Authorization"]})
}

// A WebSocket upgrade through a guest port streams both ways and ends
// cleanly: the hijacked connection is never flushed or written to again (no
// server error or panic is logged) and the sandbox's stream is released.
func TestPortProxyWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString("echo:" + line)
		_ = rw.Flush()
	}))
	t.Cleanup(upstream.Close)
	proxy := NewProxy(&fakeE2B{upstream: upstream}, "sandboxd.test", "127.0.0.1")
	var logged strings.Builder
	var logMu sync.Mutex
	server := httptest.NewUnstartedServer(Routes(http.NotFoundHandler(), proxy, http.NotFoundHandler()))
	server.Config.ErrorLog = log.New(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logged.Write(p)
	}), "", 0)
	server.Start()
	t.Cleanup(server.Close)
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nE2b-Sandbox-Id: %s\r\nE2b-Sandbox-Port: %d\r\n%s: %s\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		e2bID, exposedPort, trafficTokenHeader, e2bTrafficToken)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", response, err)
	}
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "echo:hello\n" {
		t.Fatalf("echo: %q %v", line, err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("the stream did not end with the upstream: %v", err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		proxy.streamsMu.Lock()
		open := len(proxy.streams)
		proxy.streamsMu.Unlock()
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sandbox stream(s) still held after the WebSocket ended", open)
		}
		time.Sleep(10 * time.Millisecond)
	}
	server.Close()
	logMu.Lock()
	defer logMu.Unlock()
	if logged.Len() != 0 {
		t.Fatalf("server logged: %s", logged.String())
	}
}
