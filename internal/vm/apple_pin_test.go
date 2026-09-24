package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinKeepsUntrustedWorkBehindFirewallGate(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "inventory")
	calls := filepath.Join(dir, "calls")
	cli := filepath.Join(dir, "container")
	if err := os.WriteFile(state, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopped := strings.Replace(testPinJSON, `"state":"running"`, `"state":"stopped"`, 1)
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$1" in
  network) printf '%%s\n' '[{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]' ;;
  list) cat %q ;;
  create) printf 'sandboxd-pin-3c00d0a9d4c2eb08\n'; printf '%%s\n' %q > %q ;;
  start) printf 'sandboxd-pin-3c00d0a9d4c2eb08\n'; printf '%%s\n' %q > %q ;;
  delete) printf '[]\n' > %q ;;
  *) exit 88 ;;
esac
`, calls, state, "["+stopped+"]", state, "["+testPinJSON+"]", state, state)
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	gate := &fakeGate{}
	d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local", testPinImage, gate)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.Ready(ctx); err == nil {
		t.Fatal("accepted guest work without a pin")
	}
	if err := d.StartPin(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Ready(ctx); err != nil {
		t.Fatalf("rejected verified pin and PF gate: %v", err)
	}
	mounted := strings.Replace(testPinJSON, `"mounts":[]`, `"mounts":[{"source":"/Users/jerry","destination":"/host","type":{"virtiofs":{}}}]`, 1)
	if err := os.WriteFile(state, []byte("["+mounted+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Ready(ctx); err == nil {
		t.Fatal("accepted a pin VM with a host directory mounted")
	}
	if err := os.WriteFile(state, []byte("["+testPinJSON+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	gate.err = errors.New("PF disabled")
	if err := d.Ready(ctx); err == nil {
		t.Fatal("accepted a live pin without PF protection")
	}
	gate.err = nil
	if err := d.StopPin(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Ready(ctx); err == nil {
		t.Fatal("accepted guest work after pin removal")
	}
	logged, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "--cap-drop ALL") || !strings.Contains(string(logged), "--read-only") ||
		strings.Contains(string(logged), "--label gitmoot.sandboxd.owner=apple-v1") {
		t.Fatalf("pin VM was not isolated from ordinary job ownership: %s", logged)
	}
}

type cancelRaceGate struct {
	checks  atomic.Int32
	entered chan struct{}
}

func (*cancelRaceGate) Arm(context.Context) (string, error) { return "bridge102", nil }
func (*cancelRaceGate) Disarm(context.Context) error        { return nil }
func (g *cancelRaceGate) Check(ctx context.Context) error {
	if g.checks.Add(1) == 1 {
		return nil
	}
	close(g.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestCallerCancellationIsNotFirewallLoss(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "container")
	calls := filepath.Join(dir, "calls")
	inventory := "[" + testPinJSON + `,{"configuration":{"id":"sandboxd-new","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}},"status":{"state":"running"}}]`
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$1" in
  list) printf '%%s\n' %q ;;
  exec) sleep 0.3 & exec sleep 10 ;;
  delete) exit 0 ;;
  *) exit 88 ;;
esac
`, calls, inventory)
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	gate := &cancelRaceGate{entered: make(chan struct{})}
	d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local", testPinImage, gate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, runErr := d.Run(ctx, "sandboxd-new", Command{Args: []string{"/bin/id"}}, &bytes.Buffer{}, &bytes.Buffer{})
		result <- runErr
	}()
	select {
	case <-gate.entered:
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("firewall watcher did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "firewall lost") {
			t.Fatalf("caller cancellation misclassified as firewall failure: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled guest exec did not return")
	}
	logged, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "delete --force") {
		t.Fatalf("driver destroyed guest on caller cancellation: %s", logged)
	}
}

type delayedFailureGate struct {
	checks  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (*delayedFailureGate) Arm(context.Context) (string, error) { return "bridge102", nil }
func (*delayedFailureGate) Disarm(context.Context) error        { return nil }
func (g *delayedFailureGate) Check(ctx context.Context) error {
	if g.checks.Add(1) == 1 {
		return nil
	}
	close(g.entered)
	select {
	case <-g.release:
		return errors.New("PF disabled")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestInFlightFirewallFailureRevokesGuest(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "container")
	calls := filepath.Join(dir, "calls")
	state := filepath.Join(dir, "inventory")
	execDone := filepath.Join(dir, "exec-done")
	inventory := "[" + testPinJSON + `,{"configuration":{"id":"sandboxd-new","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}},"status":{"state":"running"}}]`
	if err := os.WriteFile(state, []byte(inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$1" in
  list) cat %q ;;
  exec) while [ ! -e %q ]; do sleep 0.01; done ;;
  delete) printf '%%s\n' %q > %q ;;
  volume) printf '[]\n' ;;
  *) exit 88 ;;
esac
`, calls, state, execDone, "["+testPinJSON+"]", state)
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	gate := &delayedFailureGate{entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}()
	d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local", testPinImage, gate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, runErr := d.Run(ctx, "sandboxd-new", Command{Args: []string{"/bin/id"}}, &bytes.Buffer{}, &bytes.Buffer{})
		result <- runErr
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("firewall watcher did not enter before guest command exit")
	}
	if err := os.WriteFile(execDone, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("reported command completion while gate check was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(gate.release)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "firewall lost") {
			t.Fatalf("failed to revoke guest on in-flight PF failure: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("guest did not stop after PF failure")
	}
	logged, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "delete --force sandboxd-new") {
		t.Fatalf("PF failure left guest VM alive: %s", logged)
	}
}
