package envd

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gitmoot/sandboxd/internal/tunnel"
)

// ErrTunnelUnauthorized covers invalid, expired, revoked or mismatched leases.
var ErrTunnelUnauthorized = errors.New("tunnel lease unauthorized")

type TunnelSandboxes interface {
	OpenTunnel(context.Context, string, int, string) (TunnelConn, error)
}

// TunnelConn exposes cancellation separately from EOF: revocation must close the
// client even if the guest has already finished sending but is still receiving.
type TunnelConn interface {
	net.Conn
	CloseWrite() error
	TunnelContext() context.Context
}

func (p *Proxy) serveTunnel(w http.ResponseWriter, r *http.Request) {
	id, text, err := net.SplitHostPort(r.RequestURI)
	port, parseErr := strconv.Atoi(text)
	if err != nil || parseErr != nil || !validSandboxID(id) || port < 1 || port > 65535 || strconv.Itoa(port) != text || r.Host != r.RequestURI || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "CONNECT requires sandboxID:port without a request body", http.StatusBadRequest)
		return
	}
	if r.ProtoMajor != 1 {
		http.Error(w, "CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	tokens := r.Header.Values("E2b-Tunnel-Access-Token")
	if len(tokens) != 1 || tokens[0] == "" {
		http.Error(w, "tunnel lease unauthorized", http.StatusForbidden)
		return
	}
	service, ok := p.Sandboxes.(TunnelSandboxes)
	if !ok {
		http.Error(w, "tunnels unavailable", http.StatusNotImplemented)
		return
	}
	if !p.acquireStream(id) {
		http.Error(w, "too many sandbox streams", http.StatusTooManyRequests)
		return
	}
	defer p.releaseStream(id)
	guest, err := service.OpenTunnel(r.Context(), id, port, tokens[0])
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrTunnelUnauthorized) {
			status = http.StatusForbidden
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer guest.Close()
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(guest.TunnelContext(), func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tunnel.Bridge(conn, buffered.Reader, guest)
}
