package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

const requestTimeout = 5 * time.Second

type request struct {
	Action string `json:"action"`
}

type response struct {
	Bridge string `json:"bridge,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Gate is the root helper's attestation contract. A successful Check means
// PF is enabled and the exact root-configured scoped policy is active on the pinned bridge.
type Gate interface {
	Arm(context.Context) (string, error)
	Check(context.Context) error
	Disarm(context.Context) error
}

// Client never falls back to a local or unprivileged firewall check.
type Client struct {
	socket string
}

func NewClient(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || strings.ContainsRune(socket, 0) {
		return nil, fmt.Errorf("firewall socket path must be absolute and clean")
	}
	return &Client{socket: socket}, nil
}

func (c *Client) call(ctx context.Context, action string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return "", fmt.Errorf("firewall helper unavailable: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", err
		}
	}
	if err := json.NewEncoder(conn).Encode(request{Action: action}); err != nil {
		return "", fmt.Errorf("firewall helper request: %w", err)
	}
	var reply response
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply); err != nil {
		return "", fmt.Errorf("firewall helper response: %w", err)
	}
	if reply.Error != "" {
		return "", fmt.Errorf("firewall helper %s: %s", action, reply.Error)
	}
	if action == "arm" && reply.Bridge == "" {
		return "", fmt.Errorf("firewall helper did not attest a bridge")
	}
	return reply.Bridge, nil
}

func (c *Client) Arm(ctx context.Context) (string, error) {
	return c.call(ctx, "arm")
}

func (c *Client) Check(ctx context.Context) error {
	_, err := c.call(ctx, "check")
	return err
}

func (c *Client) Disarm(ctx context.Context) error {
	_, err := c.call(ctx, "disarm")
	return err
}
