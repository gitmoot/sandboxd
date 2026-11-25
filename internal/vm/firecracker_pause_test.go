//go:build linux

package vm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// guestCat returns the content of file in VM id's guest.
func guestCat(t *testing.T, d *FirecrackerDriver, id, file string) string {
	t.Helper()
	var stdout bytes.Buffer
	if code, err := d.Run(context.Background(), id, Command{Args: []string{"cat", file}}, &stdout, io.Discard); err != nil || code != 0 {
		t.Fatalf("cat %s in %s: code=%d err=%v", file, id, code, err)
	}
	return stdout.String()
}

// hostCalls returns the host calls recorded since index from.
func hostCalls(host *fakeFCHost, from int) []string {
	host.mu.Lock()
	defer host.mu.Unlock()
	return slices.Clone(host.calls[from:])
}

func callCount(host *fakeFCHost) int {
	host.mu.Lock()
	defer host.mu.Unlock()
	return len(host.calls)
}

func TestFirecrackerPauseAndResume(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	spec := Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	// Every VM gets the API socket a pause goes through.
	if args := lastStart(host, fcTestID); !coldBooted(args) {
		t.Fatalf("cold boot without an API socket: %v", args)
	}
	if code, err := d.Run(ctx, fcTestID, Command{Args: []string{"/bin/sh", "-c", "echo kept > kept.txt"}}, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("write: code=%d err=%v", code, err)
	}
	if err := d.Resume(ctx, fcTestID); !errors.Is(err, ErrNotPaused) {
		t.Fatalf("resume of a running VM: %v", err)
	}
	for cycle := range 2 {
		from := callCount(host)
		if err := d.Pause(ctx, fcTestID); err != nil {
			t.Fatalf("cycle %d: pause: %v", cycle, err)
		}
		calls := hostCalls(host, from)
		pause, snapshot, kill := slices.Index(calls, "pause "+fcTestID), slices.Index(calls, "snapshot "+fcTestID), slices.Index(calls, "kill "+fcTestID)
		if pause < 0 || snapshot < pause || kill < snapshot ||
			!slices.Contains(calls, "kill "+fcNetCgroup+fcTestID) || !slices.Contains(calls, "netns delete sbx-"+fcTestID) {
			t.Fatalf("cycle %d: pause calls = %v", cycle, calls)
		}
		if list, err := d.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID, Paused: true, Network: "sbx0"}}) {
			t.Fatalf("cycle %d: paused list = %+v, %v", cycle, list, err)
		}
		meta, err := d.readMeta(fcTestID)
		if err != nil || meta == nil || !meta.Paused {
			t.Fatalf("cycle %d: record = %+v, %v", cycle, meta, err)
		}
		for _, name := range []string{fcPausedState, fcPausedMemory, "home.ext4"} {
			if _, err := os.Stat(filepath.Join(d.chroot(fcTestID), name)); err != nil {
				t.Fatalf("cycle %d: paused VM lost %s: %v", cycle, name, err)
			}
		}
		if _, err := d.Run(ctx, fcTestID, Command{Args: []string{"true"}}, io.Discard, io.Discard); err == nil {
			t.Fatalf("cycle %d: a paused VM ran a command", cycle)
		}
		if err := d.Pause(ctx, fcTestID); !errors.Is(err, ErrNotRunning) {
			t.Fatalf("cycle %d: pause of a paused VM: %v", cycle, err)
		}
		// The paused VM keeps its slot.
		if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err == nil {
			t.Fatalf("cycle %d: a paused VM's slot was given away", cycle)
		}

		from = callCount(host)
		host.mu.Lock()
		restores := len(host.restores)
		host.mu.Unlock()
		if err := d.Resume(ctx, fcTestID); err != nil {
			t.Fatalf("cycle %d: resume: %v", cycle, err)
		}
		calls = hostCalls(host, from)
		if network, load := slices.Index(calls, "network sbx-"+fcTestID), slices.Index(calls, "load "+fcTestID); network < 0 || load < network {
			t.Fatalf("cycle %d: resume calls = %v", cycle, calls)
		}
		if args := lastStart(host, fcTestID); !restored(args, fcTestID) {
			t.Fatalf("cycle %d: resumed VMM args = %v", cycle, args)
		}
		host.mu.Lock()
		personalised := len(host.restores) == restores+1
		host.mu.Unlock()
		if !personalised {
			t.Fatalf("cycle %d: resumed guest was not given fresh entropy and the clock", cycle)
		}
		if list, err := d.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID, Running: true, Network: "sbx0"}}) {
			t.Fatalf("cycle %d: resumed list = %+v, %v", cycle, list, err)
		}
		if got := guestCat(t, d, fcTestID, "kept.txt"); got != "kept\n" {
			t.Fatalf("cycle %d: file after resume = %q", cycle, got)
		}
		// The loaded snapshot's names go once the guest runs.
		for _, name := range []string{fcPausedState, fcPausedMemory} {
			if _, err := os.Stat(filepath.Join(d.chroot(fcTestID), name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cycle %d: %s kept after resume: %v", cycle, name, err)
			}
		}
	}
	if err := d.Pause(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if list, err := d.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("list after destroying a paused VM = %+v, %v", list, err)
	}
	if _, err := os.Stat(d.jailDir(fcTestID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("paused VM's jail survived destroy: %v", err)
	}
}

func TestFirecrackerPausedVMSurvivesRestart(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	for i, id := range []string{fcTestID, fcTestID2} {
		if _, err := d.Create(ctx, Spec{ID: id, Image: cfg.Images[0], Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Pause(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	// A clean shutdown destroys running VMs but keeps paused ones, and
	// disarms with only those left.
	if err := d.CleanupGuests(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Disarm(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := newFirecrackerDriver(cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Resume(ctx, fcTestID); err == nil {
		t.Fatal("resume before the firewall is armed accepted")
	}
	if err := restarted.Arm(ctx); err != nil {
		t.Fatal(err)
	}
	if list, err := restarted.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID, Paused: true, Network: "sbx0"}}) {
		t.Fatalf("list after restart = %+v, %v", list, err)
	}
	if err := restarted.Resume(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if code, err := restarted.Run(ctx, fcTestID, Command{Args: []string{"true"}}, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("resumed after restart: code=%d err=%v", code, err)
	}
}

func TestFirecrackerFailedPauseKeepsTheVMRunning(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	running := []Instance{{ID: fcTestID, Running: true, Network: "sbx0"}}
	// Not enough disk for the guest's memory above the floor.
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+511) << 20
	host.mu.Unlock()
	if err := d.Pause(ctx, fcTestID); !errors.Is(err, ErrDiskFloor) {
		t.Fatalf("pause below the disk floor: %v", err)
	}
	// A snapshot that fails part way: what it wrote is discarded, so the
	// next pause finds the space it measured before.
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+600) << 20
	host.snapshotFault = "no space left on device"
	host.snapshotPartialMiB = 200
	host.mu.Unlock()
	from := callCount(host)
	if err := d.Pause(ctx, fcTestID); err == nil {
		t.Fatal("pause with a failing snapshot succeeded")
	}
	if calls := hostCalls(host, from); !slices.Contains(calls, "resume "+fcTestID) || slices.Contains(calls, "kill "+fcTestID) {
		t.Fatalf("failed pause calls = %v", calls)
	}
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, running) {
		t.Fatalf("list after a failed pause = %+v, %v", list, err)
	}
	if meta, err := d.readMeta(fcTestID); err != nil || meta == nil || meta.Paused {
		t.Fatalf("record after a failed pause = %+v, %v", meta, err)
	}
	if _, err := os.Stat(filepath.Join(d.chroot(fcTestID), fcPausedMemory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pause kept its partial memory file: %v", err)
	}
	host.mu.Lock()
	host.snapshotFault = ""
	host.mu.Unlock()
	if err := d.Pause(ctx, fcTestID); err != nil {
		t.Fatalf("pause after the fault cleared: %v", err)
	}
}

func TestFirecrackerPauseRefusesAGuestThatCannotRestore(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	host.noRestore = true
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if err := d.Pause(ctx, fcTestID); !errors.Is(err, ErrImageTooOld) {
		t.Fatalf("pause of a guest without OpRestore: %v", err)
	}
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID, Running: true, Network: "sbx0"}}) {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestFirecrackerFailedResumeKeepsTheVMPaused(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if err := d.Pause(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	paused := []Instance{{ID: fcTestID, Paused: true, Network: "sbx0"}}
	host.mu.Lock()
	host.loadFault = "snapshot load failed"
	host.mu.Unlock()
	if err := d.Resume(ctx, fcTestID); err == nil {
		t.Fatal("resume with a failing load succeeded")
	}
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, paused) {
		t.Fatalf("list after a failed resume = %+v, %v", list, err)
	}
	host.mu.Lock()
	host.loadFault = ""
	host.restoreErr = errors.New("restore refused")
	host.mu.Unlock()
	if err := d.Resume(ctx, fcTestID); err == nil {
		t.Fatal("resume with a refused personalisation succeeded")
	}
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, paused) {
		t.Fatalf("list after a refused personalisation = %+v, %v", list, err)
	}
	// The resumed guest fails its final firewall check: it is stopped and
	// still paused, its snapshot and record kept.
	host.mu.Lock()
	host.restoreErr = nil
	host.onRestore = func(string) {
		host.mu.Lock()
		host.stateFailures, host.onRestore = 1, nil
		host.mu.Unlock()
	}
	host.mu.Unlock()
	if err := d.Resume(ctx, fcTestID); err == nil {
		t.Fatal("resume with a failing firewall confirmation succeeded")
	}
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, paused) {
		t.Fatalf("list after a failed confirmation = %+v, %v", list, err)
	}
	if meta, err := d.readMeta(fcTestID); err != nil || meta == nil || !meta.Paused {
		t.Fatalf("record after a failed confirmation = %+v, %v", meta, err)
	}
	for _, name := range []string{fcPausedState, fcPausedMemory} {
		if _, err := os.Stat(filepath.Join(d.chroot(fcTestID), name)); err != nil {
			t.Fatalf("failed confirmation lost %s: %v", name, err)
		}
	}
	if err := d.Resume(ctx, fcTestID); err != nil {
		t.Fatalf("resume after the faults cleared: %v", err)
	}
}

// Concurrent pauses each reserve their guest's memory above the disk floor:
// with room for one snapshot, a second pause is refused while the first is
// still writing, and admitted once it is done.
func TestFirecrackerConcurrentPausesShareTheDiskHeadroom(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	for i, id := range []string{fcTestID, fcTestID2} {
		if _, err := d.Create(ctx, Spec{ID: id, Image: cfg.Images[0], Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512}); err != nil {
			t.Fatal(err)
		}
	}
	writing, release := make(chan string, 2), make(chan struct{})
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+513) << 20
	host.onSnapshot = func(chroot string) {
		writing <- chroot
		<-release
	}
	host.mu.Unlock()
	first := make(chan error, 1)
	go func() { first <- d.Pause(ctx, fcTestID) }()
	<-writing
	second := make(chan error, 1)
	go func() { second <- d.Pause(ctx, fcTestID2) }()
	admitted := false
	select {
	case err := <-second:
		if !errors.Is(err, ErrDiskFloor) {
			t.Errorf("second pause beside a pause in progress: %v", err)
		}
	case <-writing:
		admitted = true
		t.Error("second pause admitted on space the first one holds")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first pause: %v", err)
	}
	if admitted {
		<-second
		return
	}
	if err := d.Pause(ctx, fcTestID2); err != nil {
		t.Fatalf("pause once the first one wrote its snapshot: %v", err)
	}
}

// A pause in progress is charged only what it has yet to write: what it
// wrote is already gone from the free space. With room for two 512 MiB
// snapshots above the floor, a second pause is admitted while the first has
// written 256 MiB.
func TestFirecrackerPausesChargeOnlyWhatIsLeftToWrite(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	for i, id := range []string{fcTestID, fcTestID2} {
		if _, err := d.Create(ctx, Spec{ID: id, Image: cfg.Images[0], Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512}); err != nil {
			t.Fatal(err)
		}
	}
	writing, release := make(chan struct{}, 1), make(chan struct{})
	host.mu.Lock()
	host.free = uint64(cfg.DiskFloorMiB+1025) << 20
	host.snapshotMemoryMiB = 256
	host.onSnapshot = func(chroot string) {
		if strings.Contains(chroot, fcTestID) {
			writing <- struct{}{}
			<-release
		}
	}
	host.mu.Unlock()
	paused := make(chan error, 1)
	go func() { paused <- d.Pause(ctx, fcTestID) }()
	<-writing
	err := d.Pause(ctx, fcTestID2)
	close(release)
	if err != nil {
		t.Errorf("second pause beside one that wrote half its snapshot: %v", err)
	}
	if err := <-paused; err != nil {
		t.Fatalf("first pause: %v", err)
	}
}

// A template build and a pause are snapshot writes admitted alike: a pause
// is refused while a build holds the space it has yet to write, and
// admitted once the build is done.
func TestFirecrackerBuildAndPauseShareTheDiskHeadroom(t *testing.T) {
	d, host, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	building, release := make(chan struct{}, 1), make(chan struct{})
	host.mu.Lock()
	// Room for the build's home disk and memory, and 256 MiB more.
	host.free = uint64(cfg.DiskFloorMiB+cfg.HomeDiskMiB+512+256) << 20
	host.onSnapshot = func(chroot string) {
		if strings.Contains(chroot, fcBuildPrefix) {
			building <- struct{}{}
			<-release
		}
	}
	host.mu.Unlock()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	<-building
	err := d.Pause(ctx, fcTestID)
	close(release)
	if !errors.Is(err, ErrDiskFloor) {
		t.Errorf("pause beside a template build in progress: %v", err)
	}
	waitBuild(t, d)
	if list, err := d.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID, Running: true, Network: "sbx0"}}) {
		t.Fatalf("list after a refused pause = %+v, %v", list, err)
	}
	if err := d.Pause(ctx, fcTestID); err != nil {
		t.Fatalf("pause once the build is done: %v", err)
	}
}

func TestFirecrackerPausedCloneLeavesItsTemplate(t *testing.T) {
	d, host, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	spec := func(id, slot string) Spec {
		return Spec{ID: id, Image: cfg.Images[0], Network: slot, CPUs: 1, MemoryMiB: 512}
	}
	// The first VM cold boots and builds the template; it is destroyed so
	// both clones come from the template.
	if _, err := d.Create(ctx, spec(fcTestID, "sbx0")); err != nil {
		t.Fatal(err)
	}
	waitBuild(t, d)
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{fcTestID, fcTestID2} {
		if _, err := d.Create(ctx, spec(id, FirecrackerSlotNames(2)[i])); err != nil {
			t.Fatal(err)
		}
		if args := lastStart(host, id); !restored(args, id) {
			t.Fatalf("%s not restored from the template: %v", id, args)
		}
	}
	host.mu.Lock()
	host.restores = nil
	host.mu.Unlock()
	for _, id := range []string{fcTestID, fcTestID2} {
		if err := d.Pause(ctx, id); err != nil {
			t.Fatal(err)
		}
		meta, err := d.readMeta(id)
		if err != nil || meta == nil || meta.Snapshot != "" {
			t.Fatalf("paused clone still names its template: %+v, %v", meta, err)
		}
		if _, err := os.Stat(filepath.Join(d.chroot(id), fcSnapshotJail)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("paused clone kept its template links: %v", err)
		}
		if err := d.Resume(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	// Each resume personalised its guest with its own entropy.
	host.mu.Lock()
	restores := slices.Clone(host.restores)
	host.mu.Unlock()
	if len(restores) != 2 || restores[0].ID != fcTestID || restores[1].ID != fcTestID2 ||
		bytes.Equal(restores[0].Entropy, restores[1].Entropy) {
		t.Fatalf("resume personalisations = %+v", restores)
	}
}
