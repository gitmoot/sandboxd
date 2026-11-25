//go:build sandboxd_devdriver && linux

package devvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// procState reads the state letter of process pid.
func procState(t *testing.T, pid int) byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := statFields(string(raw))
	if !ok {
		t.Fatalf("unparsable stat %q", raw)
	}
	return stat.state
}

func TestPauseStopsTheGuestAndResumeContinuesIt(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	create(t, d, "sandboxd-a", "slot-0")
	_, stdout, _ := run(t, d, "sandboxd-a", vm.Command{Args: []string{"/bin/sh", "-c", "echo kept > kept.txt; while :; do :; done >/dev/null 2>&1 & echo $!"}})
	pid, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Resume(ctx, "sandboxd-a"); !errors.Is(err, vm.ErrNotPaused) {
		t.Fatalf("resume of a running guest: %v", err)
	}
	if err := d.Pause(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	if state := procState(t, pid); state != 'T' {
		t.Fatalf("paused guest process in state %c", state)
	}
	if list, _ := d.List(ctx); len(list) != 1 || list[0] != (vm.Instance{ID: "sandboxd-a", Paused: true, Network: "slot-0"}) {
		t.Fatalf("paused guest listed as %+v", list)
	}
	if err := d.Pause(ctx, "sandboxd-a"); !errors.Is(err, vm.ErrNotRunning) {
		t.Fatalf("pause of a paused guest: %v", err)
	}
	if _, err := d.Run(ctx, "sandboxd-a", vm.Command{Args: []string{"true"}}, nil, nil); err == nil {
		t.Fatal("a paused guest ran a command")
	}
	if _, err := d.Usage(ctx, "sandboxd-a"); err == nil {
		t.Fatal("a paused guest reported usage")
	}
	// A paused guest keeps its network.
	if _, err := d.Create(ctx, vm.Spec{ID: "sandboxd-b", Image: "img", Network: "slot-0", CPUs: 1, MemoryMiB: 256}); err == nil {
		t.Fatal("a paused guest's network was given to another guest")
	}
	if err := d.Resume(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	if state := procState(t, pid); state == 'T' {
		t.Fatal("resumed guest process still stopped")
	}
	if list, _ := d.List(ctx); len(list) != 1 || list[0] != (vm.Instance{ID: "sandboxd-a", Running: true, Network: "slot-0"}) {
		t.Fatalf("resumed guest listed as %+v", list)
	}
	if _, out, _ := run(t, d, "sandboxd-a", vm.Command{Args: []string{"cat", "kept.txt"}}); out != "kept\n" {
		t.Fatalf("file after resume = %q", out)
	}
}

func TestDestroyKillsAPausedGuest(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	create(t, d, "sandboxd-a", "slot-0")
	_, stdout, _ := run(t, d, "sandboxd-a", vm.Command{Args: []string{"/bin/sh", "-c", "sleep 300 >/dev/null 2>&1 & echo $!"}})
	pid, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Pause(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("paused guest process survived destroy: %v", err)
	}
	if err := d.Resume(ctx, "sandboxd-a"); !errors.Is(err, vm.ErrNotPaused) {
		t.Fatalf("resume of a destroyed guest: %v", err)
	}
}
