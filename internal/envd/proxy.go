package envd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

// E2BSandboxes is the control plane as the e2b data plane sees it.
type E2BSandboxes interface {
	// IsE2B reports whether id names an e2b-profile sandbox; its envd
	// traffic goes to Proxy, never to the gitmoot-strict Handler.
	IsE2B(id string) bool
	// AuthorizeEnvd is Authorize for an e2b-profile sandbox.
	AuthorizeEnvd(id, token string) bool
	// EnvdToken re-derives an e2b-profile sandbox's envd access token, to
	// check signed file URLs; ok is false for any other ID.
	EnvdToken(id string) (token string, ok bool)
	// DialEnvd opens a stream to the sandbox's envd over its worker's
	// host-to-guest channel.
	DialEnvd(ctx context.Context, id string) (net.Conn, error)
}

// Proxy forwards an e2b sandbox's envd traffic, after sandboxd has checked
// the sandbox's envd access token (or a file URL signed with it), to the
// upstream envd running in the guest. Only the envd routes the SDKs use are
// forwarded; envd's internal routes (/init, /freeze, upgrades, ...) are
// reachable by sandboxd alone.
type Proxy struct {
	Sandboxes   E2BSandboxes
	Domain      string
	GatewayHost string

	proxy *httputil.ReverseProxy
}

// NewProxy returns a Proxy using one shared upstream transport.
func NewProxy(sandboxes E2BSandboxes, domain, gatewayHost string) *Proxy {
	p := &Proxy{Sandboxes: sandboxes, Domain: domain, GatewayHost: gatewayHost}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(out *httputil.ProxyRequest) {
			out.Out.URL.Scheme = "http"
			out.Out.URL.Host = out.In.Context().Value(proxyTarget{}).(string)
			out.Out.Host = out.Out.URL.Host
			// Routing headers are sandboxd's, not envd's.
			out.Out.Header.Del("E2b-Sandbox-Id")
			out.Out.Header.Del("E2b-Sandbox-Port")
		},
		Transport: Transport(sandboxes.DialEnvd),
		// Connect streams and process output must reach the client as
		// envd writes them.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			jsonError(w, http.StatusBadGateway, "sandbox envd is not reachable")
		},
	}
	return p
}

type proxyTarget struct{}

// envdHostSuffix marks the internal upstream host of a sandbox's envd; it is
// only ever resolved by Transport.
const envdHostSuffix = ".envd.sandboxd.internal"

// EnvdURL is the base URL Transport resolves to sandbox id's envd.
func EnvdURL(id string) string {
	return "http://" + id + envdHostSuffix + ":" + strconv.Itoa(49983)
}

// Transport is an HTTP transport to sandboxes' envd: it resolves EnvdURL
// hosts through dial and nothing else, and keeps a few idle streams per
// sandbox.
func Transport(dial func(ctx context.Context, id string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			id, ok := strings.CutSuffix(host, envdHostSuffix)
			if !ok || !validSandboxID(id) {
				return nil, errors.New("not a sandbox envd address")
			}
			return dial(ctx, id)
		},
		Proxy:                 nil,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// envdRoute reports whether path is an envd route the SDKs use.
func envdRoute(path string) bool {
	switch path {
	case "/health", "/files", "/files/compose", "/envs":
		return true
	}
	for _, service := range []string{"/process.Process/", "/filesystem.Filesystem/"} {
		if method, ok := strings.CutPrefix(path, service); ok && method != "" && !strings.Contains(method, "/") {
			return true
		}
	}
	return false
}

// sandboxID resolves the addressed sandbox as Handler does: the wildcard
// envd host, or E2B's routing headers on the gateway host.
func (p *Proxy) sandboxID(r *http.Request) (string, bool) {
	id, ok := sandboxHostID(r.Host, p.Domain)
	if p.GatewayHost != "" && strings.EqualFold(hostName(r.Host), hostName(p.GatewayHost)) {
		headerID := r.Header.Get("E2b-Sandbox-Id")
		if r.Header.Get("E2b-Sandbox-Port") == "49983" && validSandboxID(headerID) {
			id, ok = headerID, true
		}
	}
	return id, ok
}

// serve handles r if it is envd traffic for an e2b sandbox, and reports
// whether it did.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) bool {
	if p == nil || !envdRoute(r.URL.Path) {
		return false
	}
	id, ok := p.sandboxID(r)
	if !ok || !p.Sandboxes.IsE2B(id) {
		return false
	}
	if !p.authorized(r, id) {
		if r.URL.Path == "/health" {
			// As Handler: E2B's edge answers 502 for a sandbox it cannot
			// reach, which the SDKs' is_running reads as "not running".
			jsonError(w, http.StatusBadGateway, "sandbox not running")
			return true
		}
		jsonError(w, http.StatusUnauthorized, "unauthorized access, please provide a valid access token or method signing if supported")
		return true
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/connect") {
		// Connect client and bidirectional streams read the request while
		// the response streams.
		_ = http.NewResponseController(w).EnableFullDuplex()
	}
	ctx := context.WithValue(r.Context(), proxyTarget{}, strings.TrimPrefix(EnvdURL(id), "http://"))
	p.proxy.ServeHTTP(w, r.WithContext(ctx))
	return true
}

// authorized checks the envd access token, or for a file transfer without
// one, a URL signature made with it (E2B's v1 signing).
func (p *Proxy) authorized(r *http.Request, id string) bool {
	if token := r.Header.Get("X-Access-Token"); token != "" {
		return p.Sandboxes.AuthorizeEnvd(id, token)
	}
	if r.URL.Path != "/files" || r.Method != http.MethodGet && r.Method != http.MethodPost {
		return false
	}
	token, ok := p.Sandboxes.EnvdToken(id)
	if !ok || !validFileSignature(r, token) {
		return false
	}
	return p.Sandboxes.AuthorizeEnvd(id, token)
}

// validFileSignature checks signature=v1_<b64(sha256(path:op:user:token[:exp]))>
// and an unexpired signature_expiration, as envd does.
func validFileSignature(r *http.Request, token string) bool {
	query := r.URL.Query()
	signature := query.Get("signature")
	if signature == "" {
		return false
	}
	operation := "read"
	if r.Method == http.MethodPost {
		operation = "write"
	}
	raw := strings.Join([]string{query.Get("path"), operation, query.Get("username"), token}, ":")
	if expiration := query.Get("signature_expiration"); expiration != "" {
		unix, err := strconv.ParseInt(expiration, 10, 64)
		if err != nil || unix < time.Now().Unix() {
			return false
		}
		raw += ":" + expiration
	}
	sum := sha256.Sum256([]byte(raw))
	expected := "v1_" + base64.RawStdEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// jsonError is envd's error body.
func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{status, message})
}
