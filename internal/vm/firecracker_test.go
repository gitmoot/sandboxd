//go:build linux

package vm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

const fcWriteHelperArg = "sandboxd-fc-write-helper"

// The test binary doubles as the guest agent's write helper.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == fcWriteHelperArg {
		if err := guestagent.RunWriteHelper(os.Args[2], os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeFCHost models the host: namespaces, cgroups and the firewall are in
// memory; StartVMM "boots" a guest whose agent is a real guestagent.Server
// serving a per-VM directory standing in for the guest filesystem.
type fakeFCHost struct {
	mu        sync.Mutex
	t         *testing.T
	free      uint64
	untrusted map[string]bool
	firewall  string
	netns     map[string]bool
	cgroups   map[string]bool // name -> populated
	parent    bool
	guests    map[string]string // jail chroot -> guest root dir
	networks  []fcNetwork
	vmmArgs   [][]string
	calls     []string
	failVMM   error
	failNet   error
	bootDies  bool
	stats     [][3]uint64
}

func newFakeFCHost(t *testing.T) *fakeFCHost {
	return &fakeFCHost{
		t: t, free: 100 << 30, untrusted: map[string]bool{}, netns: map[string]bool{},
		cgroups: map[string]bool{}, guests: map[string]string{},
	}
}

func (h *fakeFCHost) record(call string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, call)
}

func (h *fakeFCHost) TrustedFile(path string, _ bool) error {
	if h.untrusted[path] {
		return fmt.Errorf("%s is untrusted", path)
	}
	return nil
}
func (h *fakeFCHost) FreeBytes(string) (uint64, error) { return h.free, nil }
func (h *fakeFCHost) Chown(string, int, int) error     { return nil }
func (h *fakeFCHost) ApplyFirewall(_ context.Context, ruleset string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.firewall = ruleset
	return nil
}
func (h *fakeFCHost) FirewallState(context.Context) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.firewall, nil
}
func (h *fakeFCHost) RemoveFirewall(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.firewall = ""
	return nil
}
func (h *fakeFCHost) EnsureCgroupParent() error { h.parent = true; return nil }
func (h *fakeFCHost) RemoveCgroupParent() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cgroups) != 0 {
		return errors.New("cgroup parent busy")
	}
	h.parent = false
	return nil
}
func (h *fakeFCHost) Cgroups() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var names []string
	for name := range h.cgroups {
		names = append(names, name)
	}
	return names, nil
}
func (h *fakeFCHost) CgroupPopulated(name string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cgroups[name], nil
}
func (h *fakeFCHost) CgroupStats(string) (uint64, uint64, uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sample := h.stats[0]
	h.stats = h.stats[1:]
	return sample[0], sample[1], sample[2], nil
}
func (h *fakeFCHost) KillCgroup(_ context.Context, name string) error {
	h.record("kill " + name)
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.cgroups, name)
	return nil
}
func (h *fakeFCHost) Netns() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var names []string
	for name := range h.netns {
		names = append(names, name)
	}
	return names, nil
}
func (h *fakeFCHost) NetnsPath(name string) string { return "/run/netns/" + name }
func (h *fakeFCHost) CreateNetwork(_ context.Context, network fcNetwork) error {
	h.record("network " + network.Netns)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.networks = append(h.networks, network)
	h.netns[network.Netns] = true
	h.cgroups[network.Cgroup] = true
	return h.failNet
}
func (h *fakeFCHost) DeleteNetns(_ context.Context, name string) error {
	h.record("netns delete " + name)
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.netns, name)
	return nil
}

func argAfter(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

func (h *fakeFCHost) StartVMM(_ context.Context, _ string, args []string, _ string) error {
	h.record("vmm")
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vmmArgs = append(h.vmmArgs, args)
	if h.failVMM != nil {
		return h.failVMM
	}
	id := argAfter(args, "--id")
	h.cgroups[id] = !h.bootDies
	chroot := filepath.Join(argAfter(args, "--chroot-base-dir"), "firecracker", id, "root")
	h.guests[chroot] = h.t.TempDir()
	return nil
}

// Dial answers the vsock handshake and serves a real guest agent whose
// filesystem is the VM's guest directory.
func (h *fakeFCHost) Dial(_ context.Context, path string) (net.Conn, error) {
	h.mu.Lock()
	guest, ok := h.guests[filepath.Dir(filepath.Dir(path))]
	h.mu.Unlock()
	if !ok || filepath.Base(path) != "v.sock" {
		return nil, fmt.Errorf("dial %s: no such socket", path)
	}
	server := &guestagent.Server{
		Env: []string{"PATH=/usr/bin:/bin", "HOME=" + guest}, Dir: guest,
		WriteHelper: []string{os.Args[0], fcWriteHelperArg}, WaitDelay: time.Second,
	}
	host, end := net.Pipe()
	go func() {
		line, err := bufio.NewReader(io.LimitReader(end, 13)).ReadString('\n')
		if err != nil || line != "CONNECT 1024\n" {
			_ = end.Close()
			return
		}
		_, _ = io.WriteString(end, "OK 1073741824\n")
		server.ServeConn(end)
	}()
	return host, nil
}

func (h *fakeFCHost) guestDir(d *FirecrackerDriver, id string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.guests[d.chroot(id)]
}

const (
	fcTestID  = "sandboxd-00000000000000000000000000000001"
	fcTestID2 = "sandboxd-00000000000000000000000000000002"
)

func newTestFirecracker(t *testing.T, mutate ...func(*FirecrackerConfig)) (*FirecrackerDriver, *fakeFCHost, FirecrackerConfig) {
	t.Helper()
	// Short, like a real install: the jail's vsock path must fit sun_path.
	root, err := os.MkdirTemp("", "sbxfc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, dir := range []string{"bin", "kernel", "images"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := FirecrackerConfig{
		Root: root, Firecracker: filepath.Join(root, "bin", "firecracker"), Jailer: filepath.Join(root, "bin", "jailer"),
		Kernel: filepath.Join(root, "kernel", "vmlinux"), Images: []string{filepath.Join(root, "images", "review.ext4")},
		Slots: FirecrackerSlotNames(2), UIDBase: 2900000, HomeDiskMiB: 1024, DiskFloorMiB: 4096, BootTimeout: 2 * time.Second,
	}
	for _, path := range []string{cfg.Firecracker, cfg.Jailer, cfg.Kernel, cfg.Images[0]} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range mutate {
		m(&cfg)
	}
	host := newFakeFCHost(t)
	d, err := newFirecrackerDriver(cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d, host, cfg
}

func TestFirecrackerConfigValidation(t *testing.T) {
	_, _, base := newTestFirecracker(t)
	for name, mutate := range map[string]func(*FirecrackerConfig){
		"relative root":     func(c *FirecrackerConfig) { c.Root = "var/lib" },
		"no images":         func(c *FirecrackerConfig) { c.Images = nil },
		"no slots":          func(c *FirecrackerConfig) { c.Slots = nil },
		"misnamed slot":     func(c *FirecrackerConfig) { c.Slots = []string{"sbx1"} },
		"low uid base":      func(c *FirecrackerConfig) { c.UIDBase = 1000 },
		"tiny home":         func(c *FirecrackerConfig) { c.HomeDiskMiB = 1 },
		"no boot timeout":   func(c *FirecrackerConfig) { c.BootTimeout = 0 },
		"renamed vmm":       func(c *FirecrackerConfig) { c.Firecracker = "/usr/bin/vmm" },
		"socket path long":  func(c *FirecrackerConfig) { c.Root = "/" + strings.Repeat("r", 60) },
		"negative floor":    func(c *FirecrackerConfig) { c.DiskFloorMiB = -1 },
		"relative image":    func(c *FirecrackerConfig) { c.Images = []string{"images/x.ext4"} },
		"unclean jailer":    func(c *FirecrackerConfig) { c.Jailer = "/usr/bin/../bin/jailer" },
		"duplicate slot":    func(c *FirecrackerConfig) { c.Slots = []string{"sbx0", "sbx0"} },
		"too long root uid": func(c *FirecrackerConfig) { c.UIDBase = 1 << 31 },
	} {
		cfg := base
		cfg.Images = slices.Clone(base.Images)
		mutate(&cfg)
		if _, err := newFirecrackerDriver(cfg, newFakeFCHost(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	host := newFakeFCHost(t)
	host.untrusted[base.Images[0]] = true
	if _, err := newFirecrackerDriver(base, host); err == nil {
		t.Error("untrusted image accepted")
	}
}

func TestFirecrackerCreateRunCopyDestroy(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	instance, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx1", CPUs: 2, MemoryMiB: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if instance != (Instance{ID: fcTestID, Running: true, Network: "sbx1"}) {
		t.Fatalf("instance = %+v", instance)
	}
	// Slot 1 runs its VMM and network stack as their own UIDs.
	if len(host.networks) != 1 || host.networks[0].VMMUID != 2900001 || host.networks[0].NetUID != 2901001 ||
		host.networks[0].Netns != "sbx-"+fcTestID || host.networks[0].Cgroup != "net-"+fcTestID {
		t.Fatalf("network = %+v", host.networks)
	}
	args := host.vmmArgs[0]
	for flag, want := range map[string]string{
		"--uid": "2900001", "--gid": "2900001", "--netns": "/run/netns/sbx-" + fcTestID, "--parent-cgroup": "sbx-fc",
		"--cgroup-version": "2", "--chroot-base-dir": filepath.Join(cfg.Root, "jail"), "--config-file": "/vm.json",
	} {
		if got := argAfter(args, flag); got != want {
			t.Errorf("%s = %q, want %q", flag, got, want)
		}
	}
	for _, want := range []string{"memory.max=2281701376", "cpu.max=200000 100000", "memory.swap.max=0", "pids.max=64"} {
		if !slices.Contains(args, want) {
			t.Errorf("jailer args lack %q: %v", want, args)
		}
	}
	// The jail holds hard links of the read-only kernel and image, a fresh
	// sparse home disk of the configured size, and the VM configuration.
	chroot := d.chroot(fcTestID)
	for name, source := range map[string]string{"vmlinux": cfg.Kernel, "rootfs.ext4": cfg.Images[0]} {
		a, errA := os.Stat(filepath.Join(chroot, name))
		b, errB := os.Stat(source)
		if errA != nil || errB != nil || !os.SameFile(a, b) {
			t.Errorf("%s is not a hard link of %s: %v %v", name, source, errA, errB)
		}
	}
	if info, err := os.Stat(filepath.Join(chroot, "home.ext4")); err != nil || info.Size() != 1024<<20 {
		t.Errorf("home disk: %v %v", info, err)
	}
	var config struct {
		Drives []struct {
			ID       string `json:"drive_id"`
			Path     string `json:"path_on_host"`
			Root     bool   `json:"is_root_device"`
			ReadOnly bool   `json:"is_read_only"`
		} `json:"drives"`
		Machine struct {
			VCPUs  int `json:"vcpu_count"`
			Memory int `json:"mem_size_mib"`
		} `json:"machine-config"`
		Vsock struct {
			Path string `json:"uds_path"`
		} `json:"vsock"`
		Network []struct {
			Tap string `json:"host_dev_name"`
		} `json:"network-interfaces"`
	}
	data, err := os.ReadFile(filepath.Join(chroot, "vm.json"))
	if err != nil || json.Unmarshal(data, &config) != nil {
		t.Fatalf("vm.json: %v %s", err, data)
	}
	if len(config.Drives) != 2 || !config.Drives[0].Root || !config.Drives[0].ReadOnly || config.Drives[1].ReadOnly ||
		config.Drives[1].Path != "/home.ext4" || config.Machine.VCPUs != 2 || config.Machine.Memory != 2048 ||
		config.Vsock.Path != "/run/v.sock" || len(config.Network) != 1 || config.Network[0].Tap != "sbxvm0" {
		t.Fatalf("vm.json = %+v", config)
	}

	var stdout, stderr bytes.Buffer
	started := 0
	code, err := d.Run(ctx, fcTestID, Command{Args: []string{"sh", "-c", `echo "$X"; exit 5`}, Env: map[string]string{"X": "y"}, User: "1000:1000", OnStart: func(id int) { started = id }}, &stdout, &stderr)
	if err != nil || code != 5 || stdout.String() != "y\n" || started <= 0 {
		t.Fatalf("run: code=%d err=%v stdout=%q started=%d", code, err, stdout.String(), started)
	}
	if _, err := d.Run(ctx, fcTestID, Command{Args: []string{"true"}, User: "root"}, io.Discard, io.Discard); err == nil {
		t.Fatal("root guest user accepted")
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	guest := host.guestDir(d, fcTestID)
	dest := filepath.Join(guest, "nested", "dir", "file")
	if err := d.CopyIn(ctx, fcTestID, src, dest); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dest); err != nil || string(data) != "secret" {
		t.Fatalf("copied %q, %v", data, err)
	}
	if info, err := os.Stat(filepath.Join(guest, "nested")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode %v %v", info, err)
	}
	if err := d.CopyIn(ctx, fcTestID, src, "/home/user/../etc/passwd"); err == nil {
		t.Fatal("unsafe destination accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyIn(ctx, fcTestID, link, "/home/user/x"); err == nil {
		t.Fatal("symlink source accepted")
	}

	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	assertNoTraces(t, d, host)
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatalf("second destroy: %v", err)
	}
}

func assertNoTraces(t *testing.T, d *FirecrackerDriver, host *fakeFCHost) {
	t.Helper()
	if list, err := d.List(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.netns) != 0 || len(host.cgroups) != 0 {
		t.Fatalf("netns=%v cgroups=%v", host.netns, host.cgroups)
	}
	for _, dir := range []string{d.runDir(), d.jailsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
			t.Fatalf("%s still has %v (%v)", dir, entries, err)
		}
	}
}

func TestFirecrackerDiskFloorRefusesCreation(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	// Exactly the floor plus the home disk is enough; one byte less is not.
	host.free = uint64(cfg.DiskFloorMiB+cfg.HomeDiskMiB)<<20 - 1
	_, err := d.Create(context.Background(), Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512})
	if !errors.Is(err, ErrDiskFloor) {
		t.Fatalf("err = %v", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("host touched despite floor: %v", host.calls)
	}
	assertNoTraces(t, d, host)
	host.free++
	if _, err := d.Create(context.Background(), Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
}

func TestFirecrackerCreateRefusals(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	good := Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}
	for name, spec := range map[string]Spec{
		"foreign image": {ID: fcTestID, Image: "/other.ext4", Network: "sbx0", CPUs: 1, MemoryMiB: 512},
		"unknown slot":  {ID: fcTestID, Image: cfg.Images[0], Network: "sbx9", CPUs: 1, MemoryMiB: 512},
		"bad id":        {ID: "../x", Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512},
		"no cpus":       {ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 0, MemoryMiB: 512},
		"tiny memory":   {ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 64},
	} {
		if _, err := d.Create(ctx, spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := d.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err == nil {
		t.Fatal("second VM on a busy slot accepted")
	}
	// A changed host firewall blocks admission.
	host.mu.Lock()
	host.firewall += "# tampered\n"
	host.mu.Unlock()
	if _, err := d.Create(ctx, Spec{ID: fcTestID2, Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512}); err == nil {
		t.Fatal("create accepted with a changed firewall")
	}
}

func TestFirecrackerFailedCreateLeavesNoTraces(t *testing.T) {
	for name, setup := range map[string]func(*fakeFCHost){
		"network fails": func(h *fakeFCHost) { h.failNet = errors.New("netns failed") },
		"jailer fails":  func(h *fakeFCHost) { h.failVMM = errors.New("jailer failed") },
		"guest dies":    func(h *fakeFCHost) { h.bootDies = true },
	} {
		t.Run(name, func(t *testing.T) {
			d, host, cfg := newTestFirecracker(t)
			setup(host)
			if _, err := d.Create(context.Background(), Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err == nil {
				t.Fatal("create succeeded")
			}
			assertNoTraces(t, d, host)
		})
	}
}

// After a daemon restart a fresh driver rebuilds its inventory from the
// host alone: complete VMs are running on their slots, partial ones and
// unrecorded leftovers are stopped, and Destroy removes every trace.
func TestFirecrackerReconcilesAfterRestart(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	for i, id := range []string{fcTestID, fcTestID2} {
		if _, err := d.Create(ctx, Spec{ID: id, Image: cfg.Images[0], Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512}); err != nil {
			t.Fatal(err)
		}
	}
	const orphan = "sandboxd-0000000000000000000000000000000f"
	host.mu.Lock()
	host.cgroups["net-"+fcTestID2] = false // its network stack died
	host.netns["sbx-"+orphan] = true       // namespace without any record
	host.cgroups[orphan] = true
	host.mu.Unlock()

	restarted, err := newFirecrackerDriver(cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Run(ctx, fcTestID, Command{Args: []string{"true"}}, io.Discard, io.Discard); err == nil {
		t.Fatal("run before the firewall is re-armed accepted")
	}
	if err := restarted.Arm(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := restarted.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Instance{
		{ID: fcTestID, Running: true, Network: "sbx0"},
		{ID: fcTestID2, Running: false, Network: "sbx1"},
		{ID: orphan, Running: false, Network: ""},
	}
	if !slices.Equal(list, want) {
		t.Fatalf("list = %+v, want %+v", list, want)
	}
	if code, err := restarted.Run(ctx, fcTestID, Command{Args: []string{"true"}}, io.Discard, io.Discard); err != nil || code != 0 {
		t.Fatalf("surviving VM: code=%d err=%v", code, err)
	}
	if _, err := restarted.Run(ctx, fcTestID2, Command{Args: []string{"true"}}, io.Discard, io.Discard); err == nil {
		t.Fatal("run on a VM without its network stack accepted")
	}
	// An orphan without a record blocks admission until destroyed.
	if _, err := restarted.Create(ctx, Spec{ID: "sandboxd-00000000000000000000000000000003", Image: cfg.Images[0], Network: "sbx1", CPUs: 1, MemoryMiB: 512}); err == nil {
		t.Fatal("create accepted beside an unrecorded orphan")
	}
	if err := restarted.CleanupGuests(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoTraces(t, restarted, host)
	if err := restarted.Disarm(ctx); err != nil || host.firewall != "" || host.parent {
		t.Fatalf("disarm: %v firewall=%q parent=%v", err, host.firewall, host.parent)
	}
}

func TestFirecrackerInventoryFailsOnForeignState(t *testing.T) {
	d, host, _ := newTestFirecracker(t)
	host.cgroups["not-a-sandbox"] = true
	if _, err := d.List(context.Background()); err == nil {
		t.Fatal("foreign cgroup accepted as complete inventory")
	}
	delete(host.cgroups, "not-a-sandbox")
	if err := os.MkdirAll(d.runDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.runDir(), "stray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.List(context.Background()); err == nil {
		t.Fatal("stray record accepted as complete inventory")
	}
	// Foreign namespaces are not ours and are ignored.
	if err := os.Remove(filepath.Join(d.runDir(), "stray")); err != nil {
		t.Fatal(err)
	}
	host.netns["docker-ns"] = true
	if list, err := d.List(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestFirecrackerRunDestroysGuestWhenFirewallLost(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = host.RemoveFirewall(ctx)
	}()
	_, err := d.Run(ctx, fcTestID, Command{Args: []string{"sleep", "30"}}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "firewall lost") {
		t.Fatalf("err = %v", err)
	}
	host.mu.Lock()
	_, alive := host.cgroups[fcTestID]
	host.mu.Unlock()
	if alive {
		t.Fatal("guest survived firewall loss")
	}
}

func TestFirecrackerUsageFromCgroup(t *testing.T) {
	d, host, cfg := newTestFirecracker(t)
	if _, err := d.Create(context.Background(), Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	host.stats = [][3]uint64{{1_000_000, 0, 0}, {1_125_000, 300 << 20, 640 << 20}}
	usage, err := d.Usage(context.Background(), fcTestID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.MemoryUsedBytes != 300<<20 || usage.MemoryLimitBytes != 640<<20 || usage.CPUUsedPct <= 0 || usage.CPUUsedPct > 50 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestFirecrackerRulesetsDenyPrivateAndHost(t *testing.T) {
	host := FirecrackerHostRuleset(2900000, 2901999)
	for _, want := range []string{
		"table inet sbx_fc", "meta skuid 2900000-2901999 jump guest", "fib daddr type { local, broadcast, multicast, anycast }",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
		"fc00::/7", "fe80::/10", "hook output",
	} {
		if !strings.Contains(host, want) {
			t.Errorf("host ruleset lacks %q", want)
		}
	}
	for _, banned := range []string{"hook forward", "hook prerouting", "iptables", "DOCKER"} {
		if strings.Contains(host, banned) {
			t.Errorf("host ruleset contains %q", banned)
		}
	}
	netns := firecrackerNetnsRuleset()
	for _, want := range []string{
		"table inet sbx_vm", `iifname "sbxvm0" oifname "sbxsl0" meta nfproto ipv4 ip daddr != @deny4 accept`,
		`oifname "sbxsl0" masquerade`, "policy drop", "10.0.0.0/8",
	} {
		if !strings.Contains(netns, want) {
			t.Errorf("namespace ruleset lacks %q", want)
		}
	}
}
