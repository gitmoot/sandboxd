package envd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
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
