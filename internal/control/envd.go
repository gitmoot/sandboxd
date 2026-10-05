package control

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/gitmoot/sandboxd/internal/envd"
)

// envdInitTimeout bounds how long a new e2b sandbox's envd may take to come
// up and accept /init.
const envdInitTimeout = 30 * time.Second

// guestUser and guestWorkdir are the defaults E2B's base template gives envd.
const (
	guestUser    = "user"
	guestWorkdir = "/home/user"
)

// IsE2B reports whether id is an e2b-profile sandbox of this gateway.
func (s *Service) IsE2B(id string) bool {
	if !validID(id) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	s.mu.Unlock()
	return err == nil && rowProfile(row.Profile) == ProfileE2B
}

// AuthorizeEnvd is Authorize for an e2b-profile sandbox's envd traffic.
func (s *Service) AuthorizeEnvd(id, token string) bool {
	return s.authorize(id, token, ProfileE2B)
}

// EnvdToken re-derives an e2b-profile sandbox's envd access token.
func (s *Service) EnvdToken(id string) (string, bool) {
	if !s.IsE2B(id) {
		return "", false
	}
	return s.envdToken(id), true
}

// AuthorizeTraffic is AuthorizeEnvd for an e2b sandbox's traffic access
// token. Both tokens derive from the same key; the ledger stores only the
// envd token's hash, so the traffic token is checked against its derivation
// and the sandbox is then checked as AuthorizeEnvd does.
func (s *Service) AuthorizeTraffic(id, token string) bool {
	if !validID(id) || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.trafficToken(id))) != 1 {
		return false
	}
	return s.authorize(id, s.envdToken(id), ProfileE2B)
}

// SignedSandbox finds the running e2b sandbox whose envd access token signed
// a file URL that names no sandbox (the SDKs build signed URLs from
// E2B_SANDBOX_URL, without routing headers). The signature binds exactly one
// token, so at most one sandbox matches.
func (s *Service) SignedSandbox(signed func(token string) bool) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	rows, err := s.ledger.Active(ctx)
	s.mu.Unlock()
	if err != nil {
		return "", false
	}
	for _, row := range rows {
		if row.State == "running" && rowProfile(row.Profile) == ProfileE2B && signed(s.envdToken(row.ID)) {
			return row.ID, true
		}
	}
	return "", false
}

// Exposes reports whether e2b sandbox id's template exposes guest port.
func (s *Service) Exposes(id string, port int) bool {
	if !validID(id) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	s.mu.Unlock()
	if err != nil || rowProfile(row.Profile) != ProfileE2B {
		return false
	}
	template, ok := s.templates.byID[row.TemplateID]
	return ok && slices.Contains(template.Ports, port)
}

// DialPort opens a stream to a TCP port of an e2b sandbox's guest loopback
// through the worker that owns it under its current lease. Callers decide
// which ports are reachable (envd's, or Exposes).
func (s *Service) DialPort(ctx context.Context, id string, port int) (net.Conn, error) {
	s.mu.Lock()
	row, m, err := s.owned(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if rowProfile(row.Profile) != ProfileE2B {
		return nil, fmt.Errorf("sandbox %s is not an e2b sandbox", id)
	}
	return m.api.DialPort(ctx, id, port)
}

// DefaultReadyTimeout is Config.ReadyTimeout when unset.
const DefaultReadyTimeout = 3 * time.Minute

// startTemplate runs a new e2b sandbox's template start command in the
// background and then its ready command until it exits 0, both as root
// through envd.
func (s *Service) startTemplate(ctx context.Context, id string, template Template) error {
	if template.StartCmd == "" && template.ReadyCmd == "" {
		return nil
	}
	transport := envd.Transport(s.DialPort)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	token := s.envdToken(id)
	timeout := s.cfg.ReadyTimeout
	if timeout <= 0 {
		timeout = DefaultReadyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if template.StartCmd != "" {
		if _, err := envd.RunAsRoot(ctx, client, id, token, template.StartCmd, false); err != nil {
			return fmt.Errorf("start command: %w", err)
		}
	}
	if template.ReadyCmd == "" {
		return nil
	}
	for {
		code, err := envd.RunAsRoot(ctx, client, id, token, template.ReadyCmd, true)
		if err == nil && code == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("ready command never succeeded"), err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// envdInit is the body of envd's POST /init: the sandbox's access token,
// default user and working directory, and the create-time envVars.
type envdInit struct {
	AccessToken    string            `json:"accessToken"`
	EnvVars        map[string]string `json:"envVars,omitempty"`
	DefaultUser    string            `json:"defaultUser"`
	DefaultWorkdir string            `json:"defaultWorkdir"`
}

// initEnvd sends a new e2b sandbox's envd its /init, retrying while envd is
// still starting. envVars reach the guest only this way; sandboxd never
// stores or logs them.
func (s *Service) initEnvd(ctx context.Context, id string, envVars map[string]string) error {
	body, err := json.Marshal(envdInit{AccessToken: s.envdToken(id), EnvVars: envVars, DefaultUser: guestUser, DefaultWorkdir: guestWorkdir})
	if err != nil {
		return err
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(ctx, envdInitTimeout)
	defer cancel()
	transport := envd.Transport(s.DialPort)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	var last error
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, envd.EnvdURL(id)+"/init", bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return nil
			}
			// A refusal (a token already set, a malformed request) does not
			// get better by retrying.
			if response.StatusCode < 500 {
				return fmt.Errorf("envd /init answered %d", response.StatusCode)
			}
			err = fmt.Errorf("envd /init answered %d", response.StatusCode)
		}
		last = err
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("envd of %s did not initialize", id), last)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
