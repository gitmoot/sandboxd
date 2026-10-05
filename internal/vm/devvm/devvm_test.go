//go:build sandboxd_devdriver && linux

package devvm

import (
	"bytes"
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

func newDriver(t *testing.T) *Driver {
	t.Helper()
	driver, err := New(filepath.Join(t.TempDir(), "guests"), Envd{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := driver.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return driver
}

func create(t *testing.T, d *Driver, id, network string) {
	t.Helper()
	instance, err := d.Create(context.Background(), vm.Spec{ID: id, Image: "img", Network: network, CPUs: 1, MemoryMiB: 256})
	if err != nil {
		t.Fatal(err)
	}
	if instance != (vm.Instance{ID: id, Running: true, Network: network}) {
		t.Fatalf("instance = %+v", instance)
	}
}

func run(t *testing.T, d *Driver, id string, cmd vm.Command) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, err := d.Run(context.Background(), id, cmd, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run %v: %v", cmd.Args, err)
	}
	return code, stdout.String(), stderr.String()
}

func TestNewRefusesStateFromAnEarlierRun(t *testing.T) {
	root := filepath.Join(t.TempDir(), "guests")
	if err := os.MkdirAll(filepath.Join(root, "sandboxd-stale"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, Envd{}); err == nil {
		t.Fatal("non-empty state directory accepted")
	}
	if _, err := New("relative/guests", Envd{}); err == nil {
		t.Fatal("relative state directory accepted")
	}
}

func TestRunMapsGuestHomeAndReportsExitAndStreams(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	code, stdout, stderr := run(t, d, "sandboxd-a", vm.Command{
		Args: []string{"/bin/sh", "-c", `pwd; echo "$HOME|$X"; echo oops >&2; exit 7`},
		Dir:  "/home/user", Env: map[string]string{"X": "/home/user/x:/home/username"},
	})
	home := filepath.Join(d.root, "sandboxd-a", "home", "user")
	if code != 7 || stdout != home+"\n"+home+"|"+home+"/x:/home/username\n" || stderr != "oops\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if _, err := d.Run(context.Background(), "sandboxd-a", vm.Command{Args: []string{"true"}, Dir: "/etc"}, nil, nil); err == nil {
		t.Fatal("working directory outside the guest home accepted")
	}
	if _, err := d.Run(context.Background(), "sandboxd-a", vm.Command{Args: []string{"true"}, User: "root"}, nil, nil); err == nil {
		t.Fatal("root guest user accepted")
	}
	if _, err := d.Run(context.Background(), "sandboxd-missing", vm.Command{Args: []string{"true"}}, nil, nil); err == nil {
		t.Fatal("command ran in an unknown guest")
	}
}

func TestCopyInConfinesUploadsToTheGuest(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	source := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(source, []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyIn(context.Background(), "sandboxd-a", source, "/home/user/dir/file.txt"); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := run(t, d, "sandboxd-a", vm.Command{Args: []string{"cat", "/home/user/dir/file.txt"}})
	if stdout != "private\n" {
		t.Fatalf("guest read %q", stdout)
	}
	outside := t.TempDir()
	run(t, d, "sandboxd-a", vm.Command{Args: []string{"ln", "-s", outside, "/home/user/link"}})
	for _, destination := range []string{"/home/user/../x", "/etc/passwd", "/home/user", "/home/user/link/escape"} {
		if err := d.CopyIn(context.Background(), "sandboxd-a", source, destination); err == nil {
			t.Errorf("destination %q accepted", destination)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("upload escaped through a symlink: %v", err)
	}
}

func TestGuestsAreSeparateAndNetworksExclusive(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	create(t, d, "sandboxd-b", "slot-1")
	if _, err := d.Create(context.Background(), vm.Spec{ID: "sandboxd-c", Image: "img", Network: "slot-0", CPUs: 1, MemoryMiB: 1}); err == nil {
		t.Fatal("second guest admitted onto a busy network")
	}
	if _, err := d.Create(context.Background(), vm.Spec{ID: "sandboxd-a", Image: "img", Network: "slot-2", CPUs: 1, MemoryMiB: 1}); err == nil {
		t.Fatal("duplicate guest ID admitted")
	}
	run(t, d, "sandboxd-a", vm.Command{Args: []string{"/bin/sh", "-c", "echo a > /home/user/f"}})
	code, _, _ := run(t, d, "sandboxd-b", vm.Command{Args: []string{"test", "!", "-e", "/home/user/f"}})
	if code != 0 {
		t.Fatal("guest b sees guest a's file")
	}
	list, err := d.List(context.Background())
	if err != nil || len(list) != 2 || list[0].ID != "sandboxd-a" || list[1].Network != "slot-1" || !list[0].Running {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestDestroyKillsBackgroundProcessesAndRemovesState(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	_, stdout, _ := run(t, d, "sandboxd-a", vm.Command{Args: []string{"/bin/sh", "-c", "sleep 300 >/dev/null 2>&1 & echo $!"}})
	pid, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("background guest process not running: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Destroy(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("background guest process survived destroy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.root, "sandboxd-a")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guest directory survived destroy: %v", err)
	}
	if list, _ := d.List(ctx); len(list) != 0 {
		t.Fatalf("destroyed guest still listed: %+v", list)
	}
	if err := d.Destroy(ctx, "sandboxd-a"); err != nil {
		t.Fatalf("destroying an absent guest: %v", err)
	}
	// The network is free again.
	create(t, d, "sandboxd-b", "slot-0")
}

func TestRunCancellationStopsTheCommand(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	ctx, cancel := context.WithCancel(context.Background())
	begin := time.Now()
	_, err := d.Run(ctx, "sandboxd-a", vm.Command{Args: []string{"sleep", "60"}, OnStart: func(int) { cancel() }}, nil, nil)
	if !errors.Is(err, context.Canceled) || time.Since(begin) > 10*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(begin))
	}
}

func TestUsageMeasuresTheGuestProcessGroup(t *testing.T) {
	d := newDriver(t)
	create(t, d, "sandboxd-a", "slot-0")
	idle, err := d.Usage(context.Background(), "sandboxd-a")
	if err != nil {
		t.Fatal(err)
	}
	if idle.MemoryUsedBytes == 0 || idle.MemoryLimitBytes != 256<<20 {
		t.Fatalf("idle usage = %+v", idle)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = d.Run(ctx, "sandboxd-a", vm.Command{Args: []string{"/bin/sh", "-c", "while :; do :; done"}}, nil, nil)
	}()
	time.Sleep(200 * time.Millisecond)
	busy, err := d.Usage(context.Background(), "sandboxd-a")
	if err != nil {
		t.Fatal(err)
	}
	if busy.CPUUsedPct < 20 {
		t.Fatalf("busy loop measured at %.1f%% CPU", busy.CPUUsedPct)
	}
	if _, err := d.Usage(context.Background(), "sandboxd-missing"); err == nil {
		t.Fatal("usage of an unknown guest")
	}
}

func TestMapGuestHomeMatchesWholePathWords(t *testing.T) {
	for in, want := range map[string]string{
		"/home/user":           "H",
		"/home/user/a b":       "H/a b",
		"cd /home/user && ls":  "cd H && ls",
		"x=/home/user:/tmp":    "x=H:/tmp",
		"/home/username":       "/home/username",
		"/x/home/user":         "/x/home/user",
		"a/home/user":          "a/home/user",
		"'/home/user/'":        "'H/'",
		"/home/user/home/user": "H/home/user",
		"no guest path at all": "no guest path at all",
	} {
		if got := mapGuestHome(in, "H"); got != want {
			t.Errorf("mapGuestHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatFieldsHandlesParenthesesInCommandNames(t *testing.T) {
	raw := "1234 (a) b (c)) S 1 4321 4321 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 100 1000000 42 18446744073709551615"
	got, ok := statFields(raw)
	if !ok || got != (procStat{ppid: 1, pgrp: 4321, utime: 7, stime: 3, rssPages: 42}) {
		t.Fatalf("statFields = %+v, %v", got, ok)
	}
}
