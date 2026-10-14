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
	driver, err := New(filepath.Join(t.TempDir(), "guests"), Envd{}, VolumeConfig{})
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
	if _, err := New(root, Envd{}, VolumeConfig{}); err == nil {
		t.Fatal("non-empty state directory accepted")
	}
	if _, err := New("relative/guests", Envd{}, VolumeConfig{}); err == nil {
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

func newVolumeDriver(t *testing.T, root string) *Driver {
	t.Helper()
	driver, err := New(root, Envd{}, VolumeConfig{BudgetMiB: 3, SizeMiB: 1})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func closeDriver(t *testing.T, d *Driver) {
	t.Helper()
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestVolumesEnforceNamesAndBudget(t *testing.T) {
	d := newVolumeDriver(t, filepath.Join(t.TempDir(), "guests"))
	defer closeDriver(t, d)
	ctx := context.Background()
	for _, name := range []string{"c", "a", "b"} {
		volume, err := d.CreateVolume(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if !vm.ValidVolumeID(volume.ID) || volume.Name != name || volume.SizeMiB != 1 || volume.AttachedTo != "" {
			t.Fatalf("volume = %+v", volume)
		}
	}
	if _, err := d.CreateVolume(ctx, "a"); !errors.Is(err, vm.ErrVolumeExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := d.CreateVolume(ctx, "d"); !errors.Is(err, vm.ErrVolumeBudget) {
		t.Fatalf("over budget: %v", err)
	}
	if _, err := d.CreateVolume(ctx, "../x"); err == nil {
		t.Fatal("invalid name accepted")
	}
	volumes, err := d.Volumes(ctx)
	if err != nil || len(volumes) != 3 || volumes[0].Name != "a" || volumes[1].Name != "b" || volumes[2].Name != "c" {
		t.Fatalf("volumes = %+v, %v", volumes, err)
	}
	if err := d.DeleteVolume(ctx, volumes[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateVolume(ctx, "d"); err != nil {
		t.Fatalf("budget not released by delete: %v", err)
	}
	if volumes, err = d.Volumes(ctx); err != nil || len(volumes) != 3 {
		t.Fatalf("volumes = %+v, %v", volumes, err)
	}
	for _, v := range volumes {
		if err := d.DeleteVolume(ctx, v.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVolumesOffRefuseEverything(t *testing.T) {
	d := newDriver(t)
	ctx := context.Background()
	if _, err := d.CreateVolume(ctx, "a"); err == nil {
		t.Fatal("create with volumes off")
	}
	if _, err := d.Volumes(ctx); err == nil {
		t.Fatal("list with volumes off")
	}
	spec := vm.Spec{ID: "sandboxd-a", Image: "img", Network: "slot-0", CPUs: 1, MemoryMiB: 256, Envd: true,
		Volume: &vm.VolumeMount{ID: "vol-" + strings.Repeat("0", 32), Path: "/home/user/data"}}
	if _, err := d.Create(ctx, spec); err == nil || !strings.Contains(err.Error(), "volumes are off") {
		t.Fatalf("guest with a volume and volumes off: %v", err)
	}
	if _, err := New(filepath.Join(t.TempDir(), "x"), Envd{}, VolumeConfig{BudgetMiB: 1, SizeMiB: 2}); err == nil {
		t.Fatal("volume larger than the budget accepted")
	}
}

// The dev driver cannot confine a guest's network: a policy is refused, and
// nothing is created.
func TestCreateRefusesEgressPolicy(t *testing.T) {
	d := newDriver(t)
	ctx := context.Background()
	spec := vm.Spec{ID: "sandboxd-a", Image: "img", Network: "slot-0", CPUs: 1, MemoryMiB: 256, Envd: true,
		Egress: &vm.EgressPolicy{AllowInternet: true}}
	if _, err := d.Create(ctx, spec); !errors.Is(err, vm.ErrEgressUnsupported) {
		t.Fatalf("guest with an egress policy: %v", err)
	}
	if instances, err := d.List(ctx); err != nil || len(instances) != 0 {
		t.Fatalf("refused create left %v, %v", instances, err)
	}
}

func TestVolumeAttachRulesAndInUse(t *testing.T) {
	root := filepath.Join(t.TempDir(), "guests")
	d := newVolumeDriver(t, root)
	defer closeDriver(t, d)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	spec := func(envd bool, id, path string) vm.Spec {
		return vm.Spec{ID: "sandboxd-b", Image: "img", Network: "slot-1", CPUs: 1, MemoryMiB: 256, Envd: envd,
			Volume: &vm.VolumeMount{ID: id, Path: path}}
	}
	for name, s := range map[string]vm.Spec{
		"plain guest":        spec(false, volume.ID, "/home/user/data"),
		"outside guest home": spec(true, volume.ID, "/mnt/data"),
		"the home itself":    spec(true, volume.ID, "/home/user"),
	} {
		if _, err := d.Create(ctx, s); err == nil || errors.Is(err, vm.ErrNoEnvd) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := d.Create(ctx, spec(true, "vol-"+strings.Repeat("1", 32), "/home/user/data")); !errors.Is(err, vm.ErrVolumeNotFound) {
		t.Fatalf("unknown volume: %v", err)
	}
	// A guest holds its volume from Create until Destroy finishes; this
	// stands in for an envd guest, which needs root and an envd binary.
	d.mu.Lock()
	d.vms["sandboxd-a"] = &guest{network: "slot-0", volume: volume.ID}
	d.mu.Unlock()
	if _, err := d.Create(ctx, spec(true, volume.ID, "/home/user/data")); !errors.Is(err, vm.ErrVolumeInUse) {
		t.Fatalf("attached volume: %v", err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); !errors.Is(err, vm.ErrVolumeInUse) {
		t.Fatalf("delete attached volume: %v", err)
	}
	if volumes, err := d.Volumes(ctx); err != nil || len(volumes) != 1 || volumes[0].AttachedTo != "sandboxd-a" {
		t.Fatalf("volumes = %+v, %v", volumes, err)
	}
	d.mu.Lock()
	delete(d.vms, "sandboxd-a")
	d.mu.Unlock()
	if volumes, err := d.Volumes(ctx); err != nil || volumes[0].AttachedTo != "" {
		t.Fatalf("volumes = %+v, %v", volumes, err)
	}
	// The only envd setup left is the guest itself.
	if _, err := d.Create(ctx, spec(true, volume.ID, "/home/user/data")); !errors.Is(err, vm.ErrNoEnvd) {
		t.Fatalf("free volume: %v", err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.volumePath(volume.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted volume data: %v", err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); !errors.Is(err, vm.ErrVolumeNotFound) {
		t.Fatalf("delete deleted volume: %v", err)
	}
}

func TestVolumesSurviveRestartAndEmptyStoreIsRemoved(t *testing.T) {
	root := filepath.Join(t.TempDir(), "guests")
	d := newVolumeDriver(t, root)
	ctx := context.Background()
	volume, err := d.CreateVolume(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.volumePath(volume.ID), "kept"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An ordinary guest comes and goes; the volume stays.
	create(t, d, "sandboxd-a", "slot-0")
	if err := d.Destroy(ctx, "sandboxd-a"); err != nil {
		t.Fatal(err)
	}
	closeDriver(t, d)
	if _, err := New(root, Envd{}, VolumeConfig{}); err == nil {
		t.Fatal("volumes off accepted a state directory holding volumes")
	}
	// Leftovers of an interrupted create (no record) and delete (no data).
	orphan := "vol-" + strings.Repeat("a", 32)
	if err := errors.Join(os.Mkdir(filepath.Join(root, volumesDir, orphan), 0o755),
		os.WriteFile(filepath.Join(root, volumesDir, "vol-"+strings.Repeat("b", 32)+".json"), []byte(`{"name":"gone","sizeMiB":1}`), 0o600)); err != nil {
		t.Fatal(err)
	}
	d = newVolumeDriver(t, root)
	volumes, err := d.Volumes(ctx)
	if err != nil || len(volumes) != 1 || volumes[0] != volume {
		t.Fatalf("volumes after restart = %+v, %v", volumes, err)
	}
	if raw, err := os.ReadFile(filepath.Join(d.volumePath(volume.ID), "kept")); err != nil || string(raw) != "hi" {
		t.Fatalf("volume data after restart = %q, %v", raw, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, volumesDir))
	if err != nil || len(entries) != 2 {
		t.Fatalf("volume store after recovery = %v, %v", entries, err)
	}
	if err := d.DeleteVolume(ctx, volume.ID); err != nil {
		t.Fatal(err)
	}
	closeDriver(t, d)
	if err := os.Remove(root); err != nil {
		t.Fatalf("state directory not left empty: %v", err)
	}
}
