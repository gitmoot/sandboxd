package firewall

import (
	"context"
	"encoding/json"
	"errors"
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
// PF is enabled and the exact root-configured scoped policy is active on
// every slot's pinned bridge. Arm returns those bridges comma-separated in slot order.
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

// Arm asks the helper to guard every slot bridge. Apple adds a bridge's
// IPv6 ULA address a few seconds after its pin VM starts (measured ~4 s on
// the Mac Studio), and the helper refuses a bridge without it. Only that
// refusal is retried, until ArmSettle elapses; nothing is loaded before the
// helper attests the exact bridge, so waiting changes no policy.
func (c *Client) Arm(ctx context.Context) (string, error) {
	deadline := time.Now().Add(ArmSettle)
	for {
		bridge, err := c.call(ctx, "arm")
		if err == nil || !strings.Contains(err.Error(), bridgeNotReady) || !time.Now().Before(deadline) {
			return bridge, err
		}
		select {
		case <-ctx.Done():
			return "", errors.Join(err, ctx.Err())
		case <-time.After(armRetryInterval):
		}
	}
}

// ArmSettle bounds how long Arm waits for the pin VM's bridge to finish
// configuring.
var ArmSettle = 30 * time.Second

var armRetryInterval = 500 * time.Millisecond

// bridgeNotReady is the helper's refusal while some slot has no bridge
// carrying its configured IPv4 gateway, IPv6 ULA and link-local addresses.
const bridgeNotReady = "sandbox bridge is missing or its addresses changed"

func (c *Client) Check(ctx context.Context) error {
	_, err := c.call(ctx, "check")
	return err
}

func (c *Client) Disarm(ctx context.Context) error {
	_, err := c.call(ctx, "disarm")
	return err
}
