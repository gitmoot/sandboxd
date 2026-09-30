package firewall

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHelper answers each arm request with the next reply in order.
func fakeHelper(t *testing.T, replies ...response) (string, *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "fw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var calls atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req request
			_ = json.NewDecoder(conn).Decode(&req)
			i := int(calls.Add(1)) - 1
			if i >= len(replies) {
				i = len(replies) - 1
			}
			_ = json.NewEncoder(conn).Encode(replies[i])
			conn.Close()
		}
	}()
	return socket, &calls
}

func fastArm(t *testing.T, settle time.Duration) {
	t.Helper()
	oldSettle, oldInterval := ArmSettle, armRetryInterval
	ArmSettle, armRetryInterval = settle, 10*time.Millisecond
	t.Cleanup(func() { ArmSettle, armRetryInterval = oldSettle, oldInterval })
}

// Apple adds the bridge's IPv6 ULA a few seconds after the pin VM starts,
// so the first arm is refused as "bridge missing" (seen on the Mac Studio,
// sandboxd#8). Arm waits for the bridge instead of failing the daemon.
func TestArmWaitsForTheBridgeToFinishConfiguring(t *testing.T) {
	fastArm(t, 2*time.Second)
	notReady := response{Error: bridgeNotReady}
	socket, calls := fakeHelper(t, notReady, notReady, response{Bridge: "bridge102"})
	c, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := c.Arm(context.Background())
	if err != nil || bridge != "bridge102" {
		t.Fatalf("Arm = %q, %v; want bridge102 after the bridge settles", bridge, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("arm calls = %d, want 3", calls.Load())
	}
}

// Any other refusal (for example an unexpected policy in the anchor) is not
// a timing issue and must fail at once, and a bridge that never appears must
// fail when the settle time ends: no policy is ever skipped.
func TestArmFailsAtOnceOnOtherRefusalsAndGivesUpOnAMissingBridge(t *testing.T) {
	fastArm(t, 200*time.Millisecond)
	socket, calls := fakeHelper(t, response{Error: "refusing to replace an unexpected firewall policy"})
	c, _ := NewClient(socket)
	if _, err := c.Arm(context.Background()); err == nil || calls.Load() != 1 {
		t.Fatalf("other refusal: err=%v calls=%d, want an error after 1 call", err, calls.Load())
	}
	socket, _ = fakeHelper(t, response{Error: bridgeNotReady})
	c, _ = NewClient(socket)
	start := time.Now()
	_, err := c.Arm(context.Background())
	if err == nil || !strings.Contains(err.Error(), bridgeNotReady) {
		t.Fatalf("missing bridge: err=%v, want the helper's refusal", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("gave up after %v, want about the 200ms settle time", elapsed)
	}
}
