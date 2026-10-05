package envd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// E2BSandboxes is the control plane as the e2b data plane sees it.
type E2BSandboxes interface {
	// IsE2B reports whether id names an e2b-profile sandbox; its envd
	// traffic goes to Proxy, never to the gitmoot-strict Handler.
	IsE2B(id string) bool
	// AuthorizeEnvd is Authorize for an e2b-profile sandbox.
	AuthorizeEnvd(id, token string) bool
	// AuthorizeTraffic is AuthorizeEnvd for the sandbox's traffic access
	// token, which grants its exposed guest ports only.
	AuthorizeTraffic(id, token string) bool
	// EnvdToken re-derives an e2b-profile sandbox's envd access token, to
	// check signed file URLs; ok is false for any other ID.
	EnvdToken(id string) (token string, ok bool)
	// SignedSandbox finds the running e2b-profile sandbox whose envd access
	// token signed, a signed file URL that names no sandbox, was made with.
	SignedSandbox(signed func(token string) bool) (id string, ok bool)
	// Exposes reports whether id's template exposes guest port.
	Exposes(id string, port int) bool
	// DialPort opens a stream to a TCP port of the sandbox's guest loopback
	// over its worker's host-to-guest channel.
	DialPort(ctx context.Context, id string, port int) (net.Conn, error)
}

// Proxy forwards an e2b sandbox's envd traffic, after sandboxd has checked
// the sandbox's envd access token (or a file URL signed with it), to the
// upstream envd running in the guest, and traffic to the guest ports its
// template exposes (ports.go). Only the envd routes the SDKs use are
// forwarded; envd's internal routes (/init, /freeze, upgrades, ...) are
// reachable by sandboxd alone.
type Proxy struct {
	Sandboxes   E2BSandboxes
	Domain      string
	GatewayHost string
	// PortHosts routes "<port>-<id>.<domain>" hosts to exposed guest ports;
	// it needs wildcard DNS and TLS for *.<domain> in front of sandboxd.
	// Without it guest ports are reached only through the gateway host and
	// E2B's routing headers. envd's own "49983-<id>.<domain>" is always
	// routed.
	PortHosts bool
	// MaxPortStreams caps one sandbox's concurrent guest port requests
	// (WebSocket and other upgraded streams included); 0 means
	// DefaultMaxPortStreams.
	MaxPortStreams int

	proxy, ports *httputil.ReverseProxy
	streamsMu    sync.Mutex
	streams      map[string]int
}

// NewProxy returns a Proxy using one shared upstream transport.
func NewProxy(sandboxes E2BSandboxes, domain, gatewayHost string) *Proxy {
	p := &Proxy{Sandboxes: sandboxes, Domain: domain, GatewayHost: gatewayHost, streams: make(map[string]int)}
	transport := Transport(sandboxes.DialPort)
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(out *httputil.ProxyRequest) {
			out.Out.URL.Scheme = "http"
			out.Out.URL.Host = out.In.Context().Value(proxyTarget{}).(string)
			out.Out.Host = out.Out.URL.Host
			// Routing headers are sandboxd's, not envd's.
			out.Out.Header.Del("E2b-Sandbox-Id")
			out.Out.Header.Del("E2b-Sandbox-Port")
		},
		Transport:      transport,
		ModifyResponse: endStreams,
		// Connect streams and process output must reach the client as
		// envd writes them.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			jsonError(w, http.StatusBadGateway, "sandbox envd is not reachable")
		},
	}
	p.ports = newPortProxy(transport)
	return p
}

type proxyTarget struct{}

// guestHostSuffix marks the internal upstream host of a sandbox's guest
// loopback; it is only ever resolved by Transport.
const guestHostSuffix = ".guest.sandboxd.internal"

// EnvdURL is the base URL Transport resolves to sandbox id's envd.
func EnvdURL(id string) string {
	return "http://" + guestHost(id, EnvdPort)
}

// guestHost is the internal upstream host of port on sandbox id's guest.
func guestHost(id string, port int) string {
	return id + guestHostSuffix + ":" + strconv.Itoa(port)
}

// Transport is an HTTP transport to sandboxes' guest ports: it resolves
// EnvdURL and guestHost hosts through dial and nothing else, and keeps a few
// idle streams per sandbox port.
func Transport(dial func(ctx context.Context, id string, port int) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			id, ok := strings.CutSuffix(host, guestHostSuffix)
			port, err := strconv.Atoi(portText)
			if !ok || !validSandboxID(id) || err != nil || port < 1 || port > 65535 {
				return nil, errors.New("not a sandbox guest address")
			}
			return dial(ctx, id, port)
		},
		Proxy:                 nil,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// envdMethod is a Connect procedure name of envd's process and filesystem
// services (Start, ListDir, ...).
var envdMethod = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

// envdRoute reports whether u names an envd route the SDKs use. It judges
// the path as sent: any percent-encoded byte disqualifies it, so neither
// "." and ".." segments nor escaped names ever reach envd.
func envdRoute(u *url.URL) bool {
	path := u.EscapedPath()
	if path != u.Path {
		return false
	}
	switch path {
	case "/health", "/files", "/files/compose", "/envs":
		return true
	}
	for _, service := range []string{"/process.Process/", "/filesystem.Filesystem/"} {
		if method, ok := strings.CutPrefix(path, service); ok && envdMethod.MatchString(method) {
			return true
		}
	}
	return false
}

// onGateway reports whether r is addressed to the gateway host.
func (p *Proxy) onGateway(r *http.Request) bool {
	return p.GatewayHost != "" && strings.EqualFold(hostName(r.Host), hostName(p.GatewayHost))
}

// target resolves the addressed sandbox and guest port: a wildcard
// "<port>-<id>.<domain>" host (other ports than envd's only with PortHosts),
// or E2B's routing headers on the gateway host.
func (p *Proxy) target(r *http.Request) (string, int, bool) {
	id, port, ok := sandboxHostPort(r.Host, p.Domain)
	if ok && port != EnvdPort && !p.PortHosts {
		ok = false
	}
	if p.onGateway(r) {
		headerID := r.Header.Get("E2b-Sandbox-Id")
		headerPort, err := strconv.Atoi(r.Header.Get("E2b-Sandbox-Port"))
		if err == nil && strconv.Itoa(headerPort) == r.Header.Get("E2b-Sandbox-Port") && headerPort >= 1 && headerPort <= 65535 && validSandboxID(headerID) {
			id, port, ok = headerID, headerPort, true
		}
	}
	return id, port, ok
}

// serve handles r if it is traffic for an e2b sandbox, and reports whether
// it did: envd traffic, guest port traffic, or a signed file URL addressed
// to the gateway host without routing headers (the SDKs build those from
// E2B_SANDBOX_URL, so only the signature names the sandbox).
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) bool {
	if p == nil {
		return false
	}
	id, port, ok := p.target(r)
	switch {
	case ok && port != EnvdPort:
		p.servePort(w, r, id, port)
		return true
	case !envdRoute(r.URL):
		return false
	case !ok && r.URL.Path == "/files" && r.URL.Query().Has("signature") && p.onGateway(r):
		id, ok = p.Sandboxes.SignedSandbox(func(token string) bool {
			valid, _ := fileSignature(r, token)
			return valid
		})
	}
	if !ok || !p.Sandboxes.IsE2B(id) {
		return false
	}
	if status, message := p.authorized(r, id); status != 0 {
		if r.URL.Path == "/health" {
			// As Handler: E2B's edge answers 502 for a sandbox it cannot
			// reach, which the SDKs' is_running reads as "not running".
			jsonError(w, http.StatusBadGateway, "sandbox not running")
			return true
		}
		jsonError(w, status, message)
		return true
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/connect") {
		// Connect client and bidirectional streams read the request while
		// the response streams.
		_ = http.NewResponseController(w).EnableFullDuplex()
		defer closeFullDuplexBody(w, r)
	}
	ctx := context.WithValue(r.Context(), proxyTarget{}, guestHost(id, EnvdPort))
	p.proxy.ServeHTTP(w, r.WithContext(ctx))
	return true
}

// closeFullDuplexBody closes the request body of a full-duplex handler
// before it returns. In full-duplex mode net/http leaves an unread body (an
// upstream that refused or dropped the request) to its post-handler Close;
// that Close reads the body to its end, which starts the connection's
// background read after the server stopped it, and the next request's read
// then panics ("invalid concurrent Body.Read call") and drops the client's
// keep-alive connection. Closed here, the server stops that background read
// as usual. The response is flushed first, as the server would before its
// Close, so a client never waits on it while its body is drained.
func closeFullDuplexBody(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).Flush()
	_ = r.Body.Close()
}

const unauthorizedEnvd = "unauthorized access, please provide a valid access token or method signing if supported"

// authorized checks the envd access token, or for a file transfer without
// one, a URL signature made with it (E2B's v1 signing). It returns 0, or the
// refusal's status and message (envd's own for an expired signature).
func (p *Proxy) authorized(r *http.Request, id string) (int, string) {
	if token := r.Header.Get("X-Access-Token"); token != "" {
		if p.Sandboxes.AuthorizeEnvd(id, token) {
			return 0, ""
		}
		return http.StatusUnauthorized, unauthorizedEnvd
	}
	if r.URL.Path != "/files" || r.Method != http.MethodGet && r.Method != http.MethodPost {
		return http.StatusUnauthorized, unauthorizedEnvd
	}
	token, ok := p.Sandboxes.EnvdToken(id)
	if !ok {
		return http.StatusUnauthorized, unauthorizedEnvd
	}
	valid, expired := fileSignature(r, token)
	switch {
	case !valid:
		return http.StatusUnauthorized, unauthorizedEnvd
	case expired:
		return http.StatusUnauthorized, "signature is already expired"
	case !p.Sandboxes.AuthorizeEnvd(id, token):
		return http.StatusUnauthorized, unauthorizedEnvd
	}
	return 0, ""
}

// fileSignature checks signature=v1_<b64(sha256(path:op:user:token[:exp]))>
// as envd does: valid reports a signature made with token, expired one whose
// signature_expiration has passed.
func fileSignature(r *http.Request, token string) (valid, expired bool) {
	query := r.URL.Query()
	signature := query.Get("signature")
	if signature == "" {
		return false, false
	}
	operation := "read"
	if r.Method == http.MethodPost {
		operation = "write"
	}
	raw := strings.Join([]string{query.Get("path"), operation, query.Get("username"), token}, ":")
	if expiration := query.Get("signature_expiration"); expiration != "" {
		unix, err := strconv.ParseInt(expiration, 10, 64)
		if err != nil {
			return false, false
		}
		expired = unix < time.Now().Unix()
		raw += ":" + expiration
	}
	sum := sha256.Sum256([]byte(raw))
	expected := "v1_" + base64.RawStdEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1, expired
}

// endStreams makes a Connect streaming response whose envd connection breaks
// at a message boundary (the VM was destroyed) end with an "unavailable"
// end-of-stream message, as E2B's proxy does, instead of a truncated body.
func endStreams(response *http.Response) error {
	if strings.HasPrefix(response.Header.Get("Content-Type"), "application/connect+") {
		response.Body = &connectStream{body: response.Body}
	}
	return nil
}

// connectStream tracks Connect envelopes (1 flag byte, 4 length bytes,
// payload) so it knows whether a read error falls between messages.
type connectStream struct {
	body    io.ReadCloser
	header  [5]byte
	inHead  int    // header bytes seen of the current envelope
	left    uint32 // payload bytes still due
	ended   bool   // an end-of-stream envelope was forwarded
	trailer []byte // the synthesized end-of-stream envelope still to return
	done    bool
}

const streamEndFlag = 0x02

func (c *connectStream) Read(p []byte) (int, error) {
	if c.trailer != nil {
		n := copy(p, c.trailer)
		if c.trailer = c.trailer[n:]; len(c.trailer) == 0 {
			c.trailer, c.done = nil, true
		}
		return n, nil
	}
	if c.done {
		return 0, io.EOF
	}
	n, err := c.body.Read(p)
	c.track(p[:n])
	if err != nil && !errors.Is(err, io.EOF) && n == 0 && !c.ended && c.inHead == 0 && c.left == 0 {
		payload, _ := json.Marshal(map[string]any{"error": map[string]string{
			"code": "unavailable", "message": "the sandbox envd connection ended before the stream completed"}})
		c.trailer = append([]byte{streamEndFlag, 0, 0, 0, 0}, payload...)
		binary.BigEndian.PutUint32(c.trailer[1:5], uint32(len(payload)))
		return c.Read(p)
	}
	return n, err
}

func (c *connectStream) track(data []byte) {
	for len(data) > 0 {
		if c.left > 0 {
			step := min(uint32(len(data)), c.left)
			c.left -= step
			data = data[step:]
			continue
		}
		c.header[c.inHead] = data[0]
		c.inHead++
		data = data[1:]
		if c.inHead == len(c.header) {
			c.inHead = 0
			c.left = binary.BigEndian.Uint32(c.header[1:])
			c.ended = c.ended || c.header[0]&streamEndFlag != 0
		}
	}
}

func (c *connectStream) Close() error { return c.body.Close() }

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
