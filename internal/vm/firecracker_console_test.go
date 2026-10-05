//go:build linux

package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFirecrackerKeepsEnvdGuestConsole(t *testing.T) {
	d, _, cfg := newTestFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512, Envd: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Console(ctx, fcTestID); !errors.Is(err, ErrNoConsole) {
		t.Fatalf("strict guest console: %v", err)
	}
	var lines []ConsoleLine
	for deadline := time.Now().Add(5 * time.Second); len(lines) < 2 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var err error
		if lines, err = d.Console(ctx, fcTestID2); err != nil {
			t.Fatal(err)
		}
	}
	if len(lines) != 2 || lines[0].Text != "boot line" || lines[1].Text != `{"level":"info","logger":"envd","message":"fake envd up"}` || lines[0].Time.IsZero() {
		t.Fatalf("envd guest console = %+v", lines)
	}
	if err := d.Destroy(ctx, fcTestID2); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Console(ctx, fcTestID2); err == nil {
		t.Fatal("console of a destroyed guest")
	}
	d.consoleMu.Lock()
	kept := len(d.consoles)
	d.consoleMu.Unlock()
	if kept != 0 {
		t.Fatalf("%d consoles kept after destroy", kept)
	}
}

// With ConsoleLog the console goes to the debugging file instead.
func TestFirecrackerConsoleLogKeepsTheFile(t *testing.T) {
	d, _, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) { c.ConsoleLog = true })
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512, Envd: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Console(ctx, fcTestID2); !errors.Is(err, ErrNoConsole) {
		t.Fatalf("console with ConsoleLog: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(d.jailDir(fcTestID2), "console.log"))
	if err != nil || !strings.Contains(string(data), "fake envd up") {
		t.Fatalf("console.log = %q, %v", data, err)
	}
}
