package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
