//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

// fakeRestore is one OpRestore a fake guest agent accepted.
type fakeRestore struct {
	ID      string
	Entropy []byte
	Time    time.Time
}

// fakeVMState is what the fake VMM writes as a snapshot's VM state: the
// guest's agent features, which every clone of it keeps.
type fakeVMState struct {
	Features []string `json:"features"`
}

// The fake guest has written fakeHomeMark at fakeHomeOffset of its home
// disk by the time its snapshot is taken, as the real one formats it.
const (
	fakeHomeMark   = "template home"
	fakeHomeOffset = 3 << 20
)

// serveAPI is the API of VM id's fake VMM: it pauses the VM, writes a full
// snapshot of it, or loads one and then runs the guest it holds. Paths are
// the VMM's, inside its chroot.
func (h *fakeFCHost) serveAPI(listener *net.UnixListener, id, chroot string) {
	fault := func(w http.ResponseWriter, format string, args ...any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"fault_message": fmt.Sprintf(format, args...)})
	}
	jailed := func(path string) string { return filepath.Join(chroot, filepath.Clean("/"+path)) }
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /vm", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State string `json:"state"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.State != "Paused" {
			fault(w, "unsupported VM state change")
			return
		}
		h.record("pause " + id)
		h.mu.Lock()
		h.paused[id] = true
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /snapshot/create", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Type   string `json:"snapshot_type"`
			State  string `json:"snapshot_path"`
			Memory string `json:"mem_file_path"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != "Full" {
			fault(w, "unsupported snapshot request")
			return
		}
		h.mu.Lock()
		paused, features := h.paused[id], h.features[id]
		h.mu.Unlock()
		if !paused {
			fault(w, "the VM must be paused")
			return
		}
		state, err := json.Marshal(fakeVMState{Features: features})
		if err != nil {
			fault(w, "%v", err)
			return
		}
		home, err := os.OpenFile(filepath.Join(chroot, "home.ext4"), os.O_WRONLY, 0)
		if err == nil {
			_, err = home.WriteAt([]byte(fakeHomeMark), fakeHomeOffset)
			err = errors.Join(err, home.Close())
		}
		err = errors.Join(err, os.WriteFile(jailed(body.State), state, 0o600),
			os.WriteFile(jailed(body.Memory), []byte("memory of "+id), 0o600))
		if err != nil {
			fault(w, "%v", err)
			return
		}
		h.record("snapshot " + id)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /snapshot/load", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State   string `json:"snapshot_path"`
			Backend struct {
				Type string `json:"backend_type"`
				Path string `json:"backend_path"`
			} `json:"mem_backend"`
			Resume bool `json:"resume_vm"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Backend.Type != "File" || !body.Resume {
			fault(w, "unsupported snapshot load request")
			return
		}
		h.mu.Lock()
		loadFault := h.loadFault
		h.mu.Unlock()
		if loadFault != "" {
			fault(w, "%s", loadFault)
			return
		}
		// The VMM's own UID reads the root-owned snapshot files as others.
		for _, path := range []string{jailed(body.State), jailed(body.Backend.Path)} {
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o004 == 0 {
				fault(w, "cannot open %s: %v", path, err)
				return
			}
		}
		var state fakeVMState
		data, err := os.ReadFile(jailed(body.State))
		if err != nil || json.Unmarshal(data, &state) != nil {
			fault(w, "unreadable VM state: %v", err)
			return
		}
		h.record("load " + id)
		h.mu.Lock()
		err = h.bootGuest(id, chroot, state.Features)
		h.mu.Unlock()
		if err != nil {
			fault(w, "%v", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	_ = http.Serve(listener, mux)
}

// newSnapshotFirecracker is newTestFirecracker with snapshots on; a build
// still running when the test ends is stopped before its files go.
func newSnapshotFirecracker(t *testing.T, mutate ...func(*FirecrackerConfig)) (*FirecrackerDriver, *fakeFCHost, FirecrackerConfig) {
	t.Helper()
	d, host, cfg := newTestFirecracker(t, append([]func(*FirecrackerConfig){func(c *FirecrackerConfig) { c.Snapshots = true }}, mutate...)...)
	t.Cleanup(func() {
		if err := d.stopBuilds(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return d, host, cfg
}

// buildDone is the channel the last template snapshot build closes when it
// has ended, nil if none started.
func buildDone(d *FirecrackerDriver) chan struct{} {
	d.snap.mu.Lock()
	defer d.snap.mu.Unlock()
	return d.snap.done
}

// waitBuild waits until the last template snapshot build has ended.
func waitBuild(t *testing.T, d *FirecrackerDriver) {
	t.Helper()
	done := buildDone(d)
	if done == nil {
		t.Fatal("no template snapshot build started")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("template snapshot build did not end")
	}
}

func snapshotName(t *testing.T, d *FirecrackerDriver, spec Spec) string {
	t.Helper()
	key, err := d.snapshotKey(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return key.name()
}

// vmmStarts returns the arguments of each VMM start of VM id, in order: a
// template build can start its VMM at any time.
func vmmStarts(host *fakeFCHost, id string) [][]string {
	host.mu.Lock()
	defer host.mu.Unlock()
	var starts [][]string
	for _, args := range host.vmmArgs {
		if argAfter(args, "--id") == id {
			starts = append(starts, args)
		}
	}
	return starts
}

func lastStart(host *fakeFCHost, id string) []string {
	starts := vmmStarts(host, id)
	if len(starts) == 0 {
		return nil
	}
	return starts[len(starts)-1]
}

// coldBooted reports whether args started a VM from its configuration
// without an API: a cold boot.
func coldBooted(args []string) bool {
	return slices.Contains(args, "--no-api") && argAfter(args, "--config-file") == "/vm.json"
}

// restored reports whether args started VM id waiting for a snapshot load.
func restored(args []string, id string) bool {
	return argAfter(args, "--id") == id && argAfter(args, "--api-sock") == "/run/api.sock" &&
		!slices.Contains(args, "--config-file") && !slices.Contains(args, "--no-api")
}

func TestFirecrackerSnapshotRestore(t *testing.T) {
	d, host, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	first := Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}
	// The first VM of a shape cold boots and starts its template's build.
	if _, err := d.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID); !coldBooted(args) {
		t.Fatalf("first VM did not cold boot: %v", args)
	}
	waitBuild(t, d)
	name := snapshotName(t, d, first)
	build := fcBuildPrefix + name
	buildArgs := lastStart(host, build)
	host.mu.Lock()
	calls := slices.Clone(host.calls)
	host.mu.Unlock()
	// The build VM ran as the reserved last UID pair, booted from its
	// configuration with an API socket, and was paused for its snapshot.
	if argAfter(buildArgs, "--id") != build || argAfter(buildArgs, "--uid") != strconv.Itoa(cfg.UIDBase+fcBuildSlot) ||
		argAfter(buildArgs, "--api-sock") != "/run/api.sock" || argAfter(buildArgs, "--config-file") != "/vm.json" {
		t.Fatalf("build VMM args = %v", buildArgs)
	}
	if pause, snap := slices.Index(calls, "pause "+build), slices.Index(calls, "snapshot "+build); pause < 0 || snap < pause {
		t.Fatalf("calls = %v", calls)
	}
	if traces, err := d.buildTraces(); err != nil || len(traces) != 0 {
		t.Fatalf("build traces = %v, %v", traces, err)
	}
	store := d.snapshotDir(name)
	for file, mode := range map[string]os.FileMode{fcSnapshotState: 0o444, fcSnapshotMemory: 0o444, fcSnapshotHome: 0o400, fcSnapshotMetaName: 0o444} {
		info, err := os.Lstat(filepath.Join(store, file))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
			t.Errorf("stored %s: %v %v", file, info, err)
		}
	}

	// The next VM of that shape restores the snapshot in its own jail.
	before := time.Now()
	if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID2); !restored(args, fcTestID2) || argAfter(args, "--uid") != strconv.Itoa(cfg.UIDBase+1) {
		t.Fatalf("clone VMM args = %v", args)
	}
	if meta, err := d.readMeta(fcTestID2); err != nil || meta.Snapshot != name {
		t.Fatalf("clone record = %+v, %v", meta, err)
	}
	chroot := d.chroot(fcTestID2)
	// Clones share the snapshot's VM state and memory (hard links: one
	// page cache), each with its own sparse copy of the template's home.
	for _, file := range []string{fcSnapshotState, fcSnapshotMemory} {
		a, errA := os.Stat(filepath.Join(chroot, fcSnapshotJail, file))
		b, errB := os.Stat(filepath.Join(store, file))
		if errA != nil || errB != nil || !os.SameFile(a, b) {
			t.Errorf("%s is not the stored one: %v %v", file, errA, errB)
		}
	}
	home := filepath.Join(chroot, "home.ext4")
	a, errA := os.Stat(home)
	b, errB := os.Stat(filepath.Join(store, fcSnapshotHome))
	if errA != nil || errB != nil || os.SameFile(a, b) || a.Size() != b.Size() {
		t.Fatalf("clone home disk: %v %v", errA, errB)
	}
	if allocated := a.Sys().(*syscall.Stat_t).Blocks * 512; allocated > 1<<20 {
		t.Errorf("clone home disk is not sparse: %d bytes allocated", allocated)
	}
	mark := make([]byte, len(fakeHomeMark))
	if file, err := os.Open(home); err != nil {
		t.Fatal(err)
	} else if _, err := file.ReadAt(mark, fakeHomeOffset); errors.Join(err, file.Close()) != nil || string(mark) != fakeHomeMark {
		t.Fatalf("clone home disk lacks the template's content: %q %v", mark, err)
	}
	// Before it was handed out, its agent took fresh entropy and the clock.
	host.mu.Lock()
	restores := slices.Clone(host.restores)
	host.mu.Unlock()
	if len(restores) != 1 || restores[0].ID != fcTestID2 || len(restores[0].Entropy) != guestagent.RestoreEntropyBytes ||
		restores[0].Time.Before(before) || time.Since(restores[0].Time) > time.Minute {
		t.Fatalf("restores = %+v", restores)
	}
	if code, err := d.Run(ctx, fcTestID2, Command{Args: []string{"true"}}, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("run in clone = %d, %v", code, err)
	}

	// Another clone of the same snapshot gets other entropy.
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID); !restored(args, fcTestID) {
		t.Fatalf("second clone VMM args = %v", args)
	}
	host.mu.Lock()
	restores = slices.Clone(host.restores)
	host.mu.Unlock()
	if len(restores) != 2 || slices.Equal(restores[0].Entropy, restores[1].Entropy) {
		t.Fatalf("clones share entropy: %+v", restores)
	}
	// Removing the clones keeps the snapshot: it is still current.
	for _, id := range []string{fcTestID, fcTestID2} {
		if err := d.Destroy(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	assertNoTraces(t, d, host)
	if _, err := os.Stat(filepath.Join(store, fcSnapshotMetaName)); err != nil {
		t.Fatalf("current snapshot collected: %v", err)
	}
}

func TestFirecrackerSnapshotCollectedWhenStaleAndUnused(t *testing.T) {
	d, host, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	spec := func(id, slot string) Spec {
		return Spec{ID: id, Image: cfg.Images[0], Network: slot, CPUs: 1, MemoryMiB: 512}
	}
	if _, err := d.Create(ctx, spec(fcTestID, "sbx0")); err != nil {
		t.Fatal(err)
	}
	waitBuild(t, d)
	old := snapshotName(t, d, spec(fcTestID, "sbx0"))
	if _, err := d.Create(ctx, spec(fcTestID2, "sbx1")); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID2); !restored(args, fcTestID2) {
		t.Fatalf("not restored: %v", args)
	}
	// Firecracker is upgraded: the snapshot it no longer loads is not used.
	if err := os.Remove(cfg.Firecracker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Firecracker, []byte("firecracker, upgraded"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(ctx, spec(fcTestID, "sbx0")); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID); !coldBooted(args) {
		t.Fatalf("stale snapshot restored: %v", args)
	}
	waitBuild(t, d)
	current := snapshotName(t, d, spec(fcTestID, "sbx0"))
	if current == old {
		t.Fatal("the upgraded Firecracker names the same snapshot")
	}
	for _, name := range []string{old, current} {
		if _, err := os.Stat(d.snapshotDir(name)); err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
	}
	// The old snapshot goes with the last VM restored from it.
	if err := d.Destroy(ctx, fcTestID2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.snapshotDir(old)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale snapshot kept: %v", err)
	}
	if _, err := os.Stat(d.snapshotDir(current)); err != nil {
		t.Fatalf("current snapshot: %v", err)
	}
}

func TestFirecrackerSnapshotFallsBackToColdBoot(t *testing.T) {
	ctx := context.Background()
	spec := func(cfg FirecrackerConfig, id, slot string) Spec {
		return Spec{ID: id, Image: cfg.Images[0], Network: slot, CPUs: 1, MemoryMiB: 512}
	}
	// withSnapshot returns a driver whose template snapshot is built.
	withSnapshot := func(t *testing.T) (*FirecrackerDriver, *fakeFCHost, FirecrackerConfig, string) {
		d, host, cfg := newSnapshotFirecracker(t)
		if _, err := d.Create(ctx, spec(cfg, fcTestID, "sbx0")); err != nil {
			t.Fatal(err)
		}
		waitBuild(t, d)
		name := snapshotName(t, d, spec(cfg, fcTestID, "sbx0"))
		if _, err := os.Stat(d.snapshotDir(name)); err != nil {
			t.Fatal(err)
		}
		return d, host, cfg, name
	}
	// createCold creates fcTestID2, requires that it tried the snapshot
	// (when tried) and then cold booted, and destroys it.
	createCold := func(t *testing.T, d *FirecrackerDriver, host *fakeFCHost, cfg FirecrackerConfig, tried bool) {
		t.Helper()
		from := len(vmmStarts(host, fcTestID2))
		if _, err := d.Create(ctx, spec(cfg, fcTestID2, "sbx1")); err != nil {
			t.Fatal(err)
		}
		starts := vmmStarts(host, fcTestID2)[from:]
		if tried && (len(starts) != 2 || !restored(starts[0], fcTestID2) || !coldBooted(starts[1])) ||
			!tried && (len(starts) != 1 || !coldBooted(starts[0])) {
			t.Fatalf("VMM starts = %v", starts)
		}
		if meta, err := d.readMeta(fcTestID2); err != nil || meta.Snapshot != "" {
			t.Fatalf("cold-booted record = %+v, %v", meta, err)
		}
		if code, err := d.Run(ctx, fcTestID2, Command{Args: []string{"true"}}, io.Discard, io.Discard); err != nil || code != 0 {
			t.Fatalf("run = %d, %v", code, err)
		}
		if err := d.Destroy(ctx, fcTestID2); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("rejected load", func(t *testing.T) {
		d, host, cfg, name := withSnapshot(t)
		host.mu.Lock()
		host.loadFault = "Cannot restore microVM state"
		host.mu.Unlock()
		// Each rejected load cold boots; the third retires the snapshot,
		// which is not built again at once.
		for range fcRestoreFaults {
			createCold(t, d, host, cfg, true)
		}
		if _, err := os.Stat(d.snapshotDir(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("snapshot not retired: %v", err)
		}
		done := buildDone(d)
		createCold(t, d, host, cfg, false)
		if buildDone(d) != done {
			t.Fatal("retired snapshot rebuilt at once")
		}
		if err := d.Destroy(ctx, fcTestID); err != nil {
			t.Fatal(err)
		}
		assertNoTraces(t, d, host)
		if names, err := readDirNames(d.snapshotsDir()); err != nil || len(names) != 0 {
			t.Fatalf("snapshots left: %v %v", names, err)
		}
	})
	t.Run("agent refuses restore", func(t *testing.T) {
		d, host, cfg, name := withSnapshot(t)
		host.mu.Lock()
		host.restoreErr = errors.New("no entropy for you")
		host.mu.Unlock()
		createCold(t, d, host, cfg, true)
		if _, err := os.Stat(d.snapshotDir(name)); err != nil {
			t.Fatalf("snapshot retired for a guest's refusal: %v", err)
		}
		// Once the guest takes it again, clones are restored.
		host.mu.Lock()
		host.restoreErr = nil
		host.mu.Unlock()
		if _, err := d.Create(ctx, spec(cfg, fcTestID2, "sbx1")); err != nil {
			t.Fatal(err)
		}
		if args := lastStart(host, fcTestID2); !restored(args, fcTestID2) {
			t.Fatalf("not restored: %v", args)
		}
	})
	t.Run("agent without restore", func(t *testing.T) {
		d, host, cfg := newSnapshotFirecracker(t)
		host.noRestore = true
		if _, err := d.Create(ctx, spec(cfg, fcTestID, "sbx0")); err != nil {
			t.Fatal(err)
		}
		waitBuild(t, d)
		if names, err := readDirNames(d.snapshotsDir()); err != nil || len(names) != 0 {
			t.Fatalf("snapshot of an agent without OpRestore: %v %v", names, err)
		}
		done := buildDone(d)
		createCold(t, d, host, cfg, false)
		if buildDone(d) != done {
			t.Fatal("failed build retried at once")
		}
	})
	t.Run("volume", func(t *testing.T) {
		d, host, cfg := newSnapshotFirecracker(t, func(c *FirecrackerConfig) {
			c.VolumeBudgetMiB, c.VolumeMiB, c.VolumeDir = 256, 128, filepath.Join(c.Root, "volumes")
		})
		volume, err := d.CreateVolume(ctx, "data")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Create(ctx, volumeSpec(cfg, fcTestID, "sbx0", volume.ID)); err != nil {
			t.Fatal(err)
		}
		if args := lastStart(host, fcTestID); !coldBooted(args) || buildDone(d) != nil {
			t.Fatalf("a VM with a volume used a template snapshot: %v", args)
		}
	})
}

func TestFirecrackerSnapshotArmRemovesLeftovers(t *testing.T) {
	d, host, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	waitBuild(t, d)
	name := snapshotName(t, d, Spec{Image: cfg.Images[0], CPUs: 1, MemoryMiB: 512})
	// A daemon that died mid-build leaves the build VM and a partial
	// snapshot behind, beside a retired snapshot and something foreign.
	const other = "0123456789abcdef01234567"
	build := fcBuildPrefix + other
	if err := os.MkdirAll(d.chroot(build), 0o700); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	host.netns["sbx-"+build] = true
	host.cgroups[build] = true
	host.cgroups[fcNetCgroup+build] = true
	host.mu.Unlock()
	for _, dir := range []string{other + ".tmp", name + ".retired-1", "foreign"} {
		if err := os.Mkdir(d.snapshotDir(dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := newFirecrackerDriver(cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Arm(ctx); err != nil {
		t.Fatal(err)
	}
	if traces, err := restarted.buildTraces(); err != nil || len(traces) != 0 {
		t.Fatalf("build traces = %v, %v", traces, err)
	}
	names, err := readDirNames(restarted.snapshotsDir())
	slices.Sort(names)
	if err != nil || !slices.Equal(names, []string{name, "foreign"}) {
		t.Fatalf("snapshots = %v, %v", names, err)
	}
	// The surviving VM still runs; a new one restores the kept snapshot.
	if code, err := restarted.Run(ctx, fcTestID, Command{Args: []string{"true"}}, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("run = %d, %v", code, err)
	}
	if _, err := restarted.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if args := lastStart(host, fcTestID2); !restored(args, fcTestID2) {
		t.Fatalf("not restored after restart: %v", args)
	}
	// Disarm stops builds and removes their traces too.
	if err := restarted.CleanupGuests(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Disarm(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoTraces(t, restarted, host)
}

func TestFirecrackerSnapshotsOffCollectsSnapshots(t *testing.T) {
	d, _, cfg := newSnapshotFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	waitBuild(t, d)
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	cfg.Snapshots = false
	off, err := newFirecrackerDriver(cfg, newFakeFCHost(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := off.Arm(ctx); err != nil {
		t.Fatal(err)
	}
	if names, err := readDirNames(off.snapshotsDir()); err != nil || len(names) != 0 {
		t.Fatalf("snapshots kept with snapshots off: %v %v", names, err)
	}
}

func TestFirecrackerMemoryFloor(t *testing.T) {
	d, host, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) { c.MemoryFloorMiB = 2048 })
	ctx := context.Background()
	spec := Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}
	host.memory.AvailableBytes = 2048<<20 - 1
	if _, err := d.Create(ctx, spec); !errors.Is(err, ErrMemoryPressure) {
		t.Fatalf("err = %v", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("host touched below the memory floor: %v", host.calls)
	}
	assertNoTraces(t, d, host)
	report, err := d.HostMemory(ctx)
	if err != nil || report != (HostMemory{TotalBytes: 64 << 30, AvailableBytes: 2048<<20 - 1, FloorBytes: 2048 << 20}) {
		t.Fatalf("host memory = %+v, %v", report, err)
	}
	host.memory.AvailableBytes++
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
}
