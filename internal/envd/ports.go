package envd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
)

// EnvdPort is the guest port upstream envd listens on.
const EnvdPort = 49983

// DefaultMaxPortStreams is Proxy.MaxPortStreams when unset.
const DefaultMaxPortStreams = 256

// trafficTokenHeader carries an e2b sandbox's traffic access token.
const trafficTokenHeader = "E2b-Traffic-Access-Token"

// guestError is the JSON body E2B's edge proxy answers guest port requests it
// refuses with; the SDKs and their tests read these fields.
type guestError struct {
	SandboxID string `json:"sandboxId"`
	Message   string `json:"message"`
	Port      int    `json:"port,omitempty"`
	Code      int    `json:"code"`
}

func writeGuestError(w http.ResponseWriter, body guestError) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(body.Code)
	_ = json.NewEncoder(w).Encode(body)
}

// newPortProxy forwards an authorized request to a guest port: everything
// but sandboxd's routing and traffic token headers passes through (the
// envd access token too: E2B's code-interpreter server reads it), the
// client's Host included, and responses and upgraded streams (WebSocket)
// flow back unbuffered.
func newPortProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(out *httputil.ProxyRequest) {
			out.Out.URL.Scheme = "http"
			out.Out.URL.Host = out.In.Context().Value(proxyTarget{}).(string)
			out.Out.Host = out.In.Host
			out.Out.Header.Del("E2b-Sandbox-Id")
			out.Out.Header.Del("E2b-Sandbox-Port")
			out.Out.Header.Del(trafficTokenHeader)
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			target := r.Context().Value(portTarget{}).(portTarget)
			writeGuestError(w, guestError{SandboxID: target.id, Message: "The sandbox is running but port is not open", Port: target.port, Code: http.StatusBadGateway})
		},
	}
}

type portTarget struct {
	id   string
	port int
}

// servePort handles a request for guest port (never envd's) of sandbox id.
// Guest ports are never public: the sandbox's traffic access token
// (E2b-Traffic-Access-Token) or its envd access token (X-Access-Token) is
// required on every request, and only the ports its template exposes are
// reachable. Refusals use E2B's bodies: 502 for an unknown or stopped
// sandbox or a closed port, 403 for a missing or invalid token.
func (p *Proxy) servePort(w http.ResponseWriter, r *http.Request, id string, port int) {
	if !p.Sandboxes.IsE2B(id) {
		writeGuestError(w, guestError{SandboxID: id, Message: "The sandbox was not found", Code: http.StatusBadGateway})
		return
	}
	header, authorized := strings.ToLower(trafficTokenHeader), false
	switch {
	case r.Header.Get(trafficTokenHeader) != "":
		authorized = p.Sandboxes.AuthorizeTraffic(id, r.Header.Get(trafficTokenHeader))
	case r.Header.Get("X-Access-Token") != "":
		header = "x-access-token"
		authorized = p.Sandboxes.AuthorizeEnvd(id, r.Header.Get("X-Access-Token"))
	default:
		writeGuestError(w, guestError{SandboxID: id, Code: http.StatusForbidden,
			Message: fmt.Sprintf("Sandbox is secured with traffic access token. Token header '%s' is missing", header)})
		return
	}
	if !authorized {
		writeGuestError(w, guestError{SandboxID: id, Code: http.StatusForbidden,
			Message: fmt.Sprintf("Sandbox is secured with traffic access token. Provided token in header '%s' is invalid", header)})
		return
	}
	if !p.Sandboxes.Exposes(id, port) {
		writeGuestError(w, guestError{SandboxID: id, Port: port, Code: http.StatusForbidden,
			Message: "The sandbox's template does not expose this port"})
		return
	}
	if !p.acquireStream(id) {
		writeGuestError(w, guestError{SandboxID: id, Port: port, Code: http.StatusTooManyRequests,
			Message: "The sandbox has too many open connections"})
		return
	}
	defer p.releaseStream(id)
	_ = http.NewResponseController(w).EnableFullDuplex()
	ctx := context.WithValue(r.Context(), proxyTarget{}, guestHost(id, port))
	ctx = context.WithValue(ctx, portTarget{}, portTarget{id: id, port: port})
	p.ports.ServeHTTP(w, r.WithContext(ctx))
}

func (p *Proxy) acquireStream(id string) bool {
	limit := p.MaxPortStreams
	if limit <= 0 {
		limit = DefaultMaxPortStreams
	}
	p.streamsMu.Lock()
	defer p.streamsMu.Unlock()
	if p.streams[id] >= limit {
		return false
	}
	p.streams[id]++
	return true
}

func (p *Proxy) releaseStream(id string) {
	p.streamsMu.Lock()
	defer p.streamsMu.Unlock()
	if p.streams[id]--; p.streams[id] <= 0 {
		delete(p.streams, id)
	}
}

// sandboxHostPort parses a wildcard sandbox host "<port>-<id>.<domain>"; a
// port on host or domain (a gateway on a non-default port) is ignored.
func sandboxHostPort(host, domain string) (string, int, bool) {
	host = strings.ToLower(hostName(host))
	domain = strings.ToLower(hostName(strings.TrimSpace(domain)))
	if domain == "" {
		return "", 0, false
	}
	label, ok := strings.CutSuffix(host, "."+domain)
	if !ok {
		return "", 0, false
	}
	portText, id, ok := strings.Cut(label, "-")
	port, err := strconv.Atoi(portText)
	if !ok || err != nil || strconv.Itoa(port) != portText || port < 1 || port > 65535 || !validSandboxID(id) {
		return "", 0, false
	}
	return id, port, true
}
