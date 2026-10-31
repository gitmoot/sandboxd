package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/envd"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// Leases are process-local capabilities, separate from envd/traffic credentials.
// The lock order is Service.mu then tunnels.mu, never the reverse. Revocation
// removes the capability before closing streams, including pending dials.
const maxTunnelLeases = 256

type tunnelLeases struct {
	mu      sync.Mutex
	closed  bool
	byID    map[string]*tunnelLease
	byToken map[[32]byte]*tunnelLease
}

type tunnelLease struct {
	ID        string    `json:"leaseID"`
	SandboxID string    `json:"sandboxID"`
	Port      int       `json:"port"`
	ExpiresAt time.Time `json:"expiresAt"`
	hash      [32]byte
	timer     *time.Timer
	sessions  map[*tunnelSession]struct{}
}

type tunnelSession struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   net.Conn
}

type tunnelLeaseResponse struct {
	LeaseID   string    `json:"leaseID"`
	SandboxID string    `json:"sandboxID"`
	Port      int       `json:"port"`
	ExpiresAt time.Time `json:"expiresAt"`
	Token     string    `json:"token"`
}

func (s *Service) tunnelResponse(l *tunnelLease) tunnelLeaseResponse {
	return tunnelLeaseResponse{l.ID, l.SandboxID, l.Port, l.ExpiresAt, s.derive("sandboxd tunnel lease v1", l.ID)}
}

// serveTunnelLeases is reached only after the normal control-key check.
func (s *Service) serveTunnelLeases(w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/sandboxes/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "tunnel-leases" {
		return false
	}
	if !validID(parts[0]) {
		s.notFound(w, r)
		return true
	}
	id := parts[0]
	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		s.mintTunnelLease(w, r, id, "")
	case len(parts) == 4 && parts[3] == "renew" && r.Method == http.MethodPost:
		s.mintTunnelLease(w, r, id, parts[2])
	case len(parts) == 3 && r.Method == http.MethodDelete:
		s.tunnels.mu.Lock()
		if l := s.tunnels.byID[parts[2]]; l != nil && l.SandboxID == id {
			s.revokeTunnelLocked(l)
		}
		s.tunnels.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		s.notFound(w, r)
	}
	return true
}

func (s *Service) mintTunnelLease(w http.ResponseWriter, r *http.Request, id, renew string) {
	var request struct {
		Port int   `json:"port"`
		TTL  int64 `json:"ttl"`
	}
	if !readJSON(w, r, &request) || request.TTL <= 0 || (renew == "" && !vm.ValidPort(request.Port)) || (renew != "" && request.Port != 0) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid tunnel port or ttl")
		return
	}
	if _, _, err := s.live(r.Context(), id); err != nil {
		s.fail(w, ProfileE2B, statusFor(err), "sandbox unavailable")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, m, err := s.owned(r.Context(), id)
	template := s.templates.byID[row.TemplateID]
	if err != nil || row.State != "running" || s.busy[id] != nil || rowProfile(row.Profile) != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusForbidden, "sandbox unavailable")
		return
	}
	if _, ok := m.api.(vm.TunnelDialer); !ok {
		s.fail(w, ProfileE2B, http.StatusNotImplemented, "worker has no tunnel transport")
		return
	}
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	if s.tunnels.closed {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "service closing")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(min(request.TTL, int64(s.cfg.MaxTTL/time.Second))) * time.Second)
	if row.Ends.Before(expires) {
		expires = row.Ends
	}
	if !now.Before(expires) {
		s.fail(w, ProfileE2B, http.StatusForbidden, "sandbox expired")
		return
	}
	if renew != "" {
		l := s.tunnels.byID[renew]
		if l == nil || l.SandboxID != id || !now.Before(l.ExpiresAt) {
			if l != nil && l.SandboxID == id {
				s.revokeTunnelLocked(l)
			}
			s.fail(w, ProfileE2B, http.StatusForbidden, "tunnel lease expired or revoked")
			return
		}
		if !slices.Contains(template.Ports, l.Port) {
			s.revokeTunnelLocked(l)
			s.fail(w, ProfileE2B, http.StatusForbidden, "port not exposed")
			return
		}
		// Renewal extends a live lease, never shortens it. Sandbox shortening is
		// enforced separately by capTunnelLeases when the sandbox timeout changes.
		if expires.After(l.ExpiresAt) {
			l.ExpiresAt = expires
			l.timer.Reset(time.Until(expires))
		}
		jsonResponse(w, http.StatusOK, s.tunnelResponse(l))
		return
	}
	if !slices.Contains(template.Ports, request.Port) {
		s.fail(w, ProfileE2B, http.StatusForbidden, "port not exposed")
		return
	}
	count := 0
	for _, l := range s.tunnels.byID {
		if !now.Before(l.ExpiresAt) {
			s.revokeTunnelLocked(l)
			continue
		}
		if l.SandboxID == id {
			count++
		}
	}
	if count >= maxTunnelLeases {
		s.fail(w, ProfileE2B, http.StatusTooManyRequests, "too many sandbox tunnel leases")
		return
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "lease creation failed")
		return
	}
	l := &tunnelLease{ID: hex.EncodeToString(random[:]), SandboxID: id, Port: request.Port, ExpiresAt: expires, sessions: make(map[*tunnelSession]struct{})}
	response := s.tunnelResponse(l)
	l.hash = sha256.Sum256([]byte(response.Token))
	if s.tunnels.byID == nil {
		s.tunnels.byID = make(map[string]*tunnelLease)
		s.tunnels.byToken = make(map[[32]byte]*tunnelLease)
	}
	s.tunnels.byID[l.ID], s.tunnels.byToken[l.hash] = l, l
	l.timer = time.AfterFunc(time.Until(expires), func() { s.expireTunnel(l) })
	jsonResponse(w, http.StatusCreated, response)
}

func (s *Service) expireTunnel(l *tunnelLease) {
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	if s.tunnels.byID[l.ID] != l {
		return
	}
	if delay := time.Until(l.ExpiresAt); delay > 0 {
		l.timer.Reset(delay)
		return
	}
	s.revokeTunnelLocked(l)
}

func (s *Service) revokeTunnelLocked(l *tunnelLease) {
	delete(s.tunnels.byID, l.ID)
	delete(s.tunnels.byToken, l.hash)
	l.timer.Stop()
	for session := range l.sessions {
		session.cancel()
		if session.conn != nil {
			_ = session.conn.Close()
		}
	}
}

func (s *Service) revokeSandboxTunnels(id string) {
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	for _, l := range s.tunnels.byID {
		if l.SandboxID == id {
			s.revokeTunnelLocked(l)
		}
	}
}

func (s *Service) capTunnelLeases(id string, ends time.Time) {
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	for _, l := range s.tunnels.byID {
		if l.SandboxID == id && ends.Before(l.ExpiresAt) {
			l.ExpiresAt = ends
			l.timer.Reset(max(0, time.Until(ends)))
		}
	}
}

func (s *Service) closeTunnels() {
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	s.tunnels.closed = true
	for _, l := range s.tunnels.byID {
		s.revokeTunnelLocked(l)
	}
}

// OpenTunnel authenticates the lease before consulting the worker. Registration
// precedes dialing, so revoke cannot miss an in-flight connection.
func (s *Service) OpenTunnel(ctx context.Context, id string, port int, token string) (envd.TunnelConn, error) {
	hash := sha256.Sum256([]byte(token))
	s.tunnels.mu.Lock()
	l := s.tunnels.byToken[hash]
	valid := l != nil && l.SandboxID == id && l.Port == port && time.Now().Before(l.ExpiresAt)
	s.tunnels.mu.Unlock()
	if !valid {
		return nil, envd.ErrTunnelUnauthorized
	}
	if _, _, err := s.live(ctx, id); err != nil {
		return nil, envd.ErrTunnelUnauthorized
	}
	s.mu.Lock()
	row, m, err := s.owned(ctx, id)
	if err != nil || row.State != "running" || s.busy[id] != nil || !time.Now().Before(row.Ends) || !slices.Contains(s.templates.byID[row.TemplateID].Ports, port) {
		s.mu.Unlock()
		return nil, envd.ErrTunnelUnauthorized
	}
	dialer, ok := m.api.(vm.TunnelDialer)
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("worker has no tunnel transport")
	}
	s.tunnels.mu.Lock()
	if s.tunnels.byToken[hash] != l || !time.Now().Before(l.ExpiresAt) || s.tunnels.closed {
		s.tunnels.mu.Unlock()
		s.mu.Unlock()
		return nil, envd.ErrTunnelUnauthorized
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	session := &tunnelSession{ctx: streamCtx, cancel: cancel}
	l.sessions[session] = struct{}{}
	s.tunnels.mu.Unlock()
	s.mu.Unlock()
	// Request cancellation bounds the dial. Afterward, lease cancellation owns
	// the stream and the caller closes it when the CONNECT handler returns.
	stop := context.AfterFunc(ctx, cancel)
	dialCtx, timeout := context.WithTimeout(streamCtx, workerTimeout)
	conn, err := dialer.DialTunnel(dialCtx, id, port)
	timeout()
	stopped := stop()
	s.tunnels.mu.Lock()
	defer s.tunnels.mu.Unlock()
	unauthorized := !stopped || streamCtx.Err() != nil || !time.Now().Before(l.ExpiresAt)
	if err != nil || unauthorized {
		cancel()
		delete(l.sessions, session)
		if conn != nil {
			_ = conn.Close()
		}
		if unauthorized {
			return nil, envd.ErrTunnelUnauthorized
		}
		return nil, err
	}
	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		cancel()
		delete(l.sessions, session)
		_ = conn.Close()
		return nil, errors.New("worker tunnel lacks directional EOF")
	}
	session.conn = conn
	return &leasedTunnel{Conn: conn, service: s, lease: l, session: session}, nil
}

type leasedTunnel struct {
	net.Conn
	service *Service
	lease   *tunnelLease
	session *tunnelSession
	once    sync.Once
}

func (c *leasedTunnel) TunnelContext() context.Context { return c.session.ctx }
func (c *leasedTunnel) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}
func (c *leasedTunnel) Close() error {
	c.once.Do(func() {
		c.session.cancel()
		c.service.tunnels.mu.Lock()
		delete(c.lease.sessions, c.session)
		c.service.tunnels.mu.Unlock()
	})
	return c.Conn.Close()
}
