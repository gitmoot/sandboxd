package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// DialEnvd opens a stream to an e2b sandbox's envd through the worker that
// owns it under its current lease.
func (s *Service) DialEnvd(ctx context.Context, id string) (net.Conn, error) {
	s.mu.Lock()
	row, m, err := s.owned(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if rowProfile(row.Profile) != ProfileE2B {
		return nil, fmt.Errorf("sandbox %s is not an e2b sandbox", id)
	}
	return m.api.DialEnvd(ctx, id)
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
	transport := envd.Transport(s.DialEnvd)
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
