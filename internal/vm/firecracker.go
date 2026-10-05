//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/egress"
	"github.com/gitmoot/sandboxd/internal/guestagent"
)

const (
	fcNetnsPrefix  = "sbx-"
	fcNetCgroup    = "net-"
	fcGuestTap     = "sbxvm0"
	fcSlirpTap     = "sbxsl0"
	fcGuestAddr    = "10.200.0.2"
	fcGatewayAddr  = "10.200.0.1"
	fcGatewayCIDR  = fcGatewayAddr + "/30"
	fcGuestMAC     = "06:00:0a:c8:00:02"
	fcGuestCID     = 3
	fcHostTable    = "sbx_fc"
	fcNetnsTable   = "sbx_vm"
	fcUIDStride    = 1000
	fcMaxSlots     = fcUIDStride
	fcVMMOverhead  = 128 // MiB of cgroup memory above guest RAM for the VMM
	fcVMMPids      = 64
	fcNetMemoryMax = 256 << 20
	fcNetPids      = 16
	fcVsockDir     = "run"
	fcVsockName    = "v.sock"
	fcVsockPath    = "/" + fcVsockDir + "/" + fcVsockName
	fcConfigPath   = "/vm.json"
	fcMaxCPUs      = 32
	fcMinMemoryMiB = 128
	fcMaxMemoryMiB = 256 << 10
)

var fcSlotName = regexp.MustCompile(`^sbx[0-9]{1,3}$`)

// FirecrackerConfig fixes a Linux/KVM worker. All paths are absolute. Root
// holds the per-VM jails (Root/jail) and ownership records (Root/run); the
// kernel and images must be on the same filesystem so they can be hard-linked
// read-only into each jail.
type FirecrackerConfig struct {
	Root        string
	Firecracker string
	Jailer      string
	Kernel      string
	Images      []string
	Slots       []string
	// UIDBase is the first host UID of the VMMs; slot i runs its VMM as
	// UIDBase+i and its user-mode network stack as UIDBase+1000+i.
	UIDBase      int
	HomeDiskMiB  int
	DiskFloorMiB int
	BootTimeout  time.Duration
	// ConsoleLog keeps the guest serial console in <jail>/console.log for
	// debugging. Off by default; the log is bounded by the VMM's fsize limit.
	ConsoleLog bool
	// DenyCIDRs extends both guest deny lists, for example with a cloud
	// provider's metadata endpoints on public addresses.
	DenyCIDRs []netip.Prefix
}

// FirecrackerDriver runs one Firecracker microVM per sandbox under the jailer:
// a separate UID pair per VM, a chroot, cgroup v2 CPU, memory and PID limits,
// a read-only root image, a fresh private ext4 home disk, and a private
// network namespace whose only exit is a user-mode NAT (slirp4netns) confined
// by the sandboxd-owned nftables table. The host reaches the guest agent only
// over vsock.
type FirecrackerDriver struct {
	cfg          FirecrackerConfig
	images       map[string]struct{}
	deny4, deny6 []string
	host         fcHost

	mu    sync.Mutex
	armed string
}

var (
	_ Driver        = (*FirecrackerDriver)(nil)
	_ ResourceMeter = (*FirecrackerDriver)(nil)
)

// ErrDiskFloor reports that creating a VM would leave less free disk than the
// configured floor.
var ErrDiskFloor = errors.New("free disk is below the configured floor")

// fcHost is every host operation the driver performs outside Root. The
// production implementation is linuxFCHost; tests substitute a fake.
type fcHost interface {
	TrustedFile(path string, executable bool) error
	FreeBytes(path string) (uint64, error)
	Chown(path string, uid, gid int) error

	ApplyFirewall(ctx context.Context, ruleset string) error
	FirewallState(ctx context.Context) (string, error)
	RemoveFirewall(ctx context.Context) error

	EnsureCgroupParent() error
	RemoveCgroupParent() error
	Cgroups() ([]string, error)
	CgroupPopulated(name string) (bool, error)
	CgroupStats(name string) (cpuUsec, memory, memoryMax uint64, err error)
	KillCgroup(ctx context.Context, name string) error

	Netns() ([]string, error)
	NetnsPath(name string) string
	CreateNetwork(ctx context.Context, network fcNetwork) error
	DeleteNetns(ctx context.Context, name string) error

	StartVMM(ctx context.Context, jailer string, args []string, console string) error
	// Dial connects to the VMM's vsock socket <chroot>/run/v.sock, which
	// must be a socket owned by owner, without following symlinks.
	Dial(ctx context.Context, chroot string, owner int) (net.Conn, error)
}

// fcNetwork is one VM's private network: a namespace owned by a user
// namespace of NetUID, the VMM's tap (owned by VMMUID), the namespace's own
// nftables table, and slirp4netns running as NetUID in Cgroup.
type fcNetwork struct {
	Netns   string
	Cgroup  string
	NetUID  int
	VMMUID  int
	Ruleset string
}

// fcMeta is the ownership record of one VM, written before any host state
// exists and removed last.
type fcMeta struct {
	ID        string `json:"id"`
	Slot      string `json:"slot"`
	VMMUID    int    `json:"vmmUid"`
	NetUID    int    `json:"netUid"`
	Image     string `json:"image"`
	CPUs      int    `json:"cpus"`
	MemoryMiB int    `json:"memoryMiB"`
}

func cleanAbs(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

// NewFirecrackerDriver validates cfg against the real host.
func NewFirecrackerDriver(cfg FirecrackerConfig) (*FirecrackerDriver, error) {
	return newFirecrackerDriver(cfg, newLinuxFCHost())
}

func newFirecrackerDriver(cfg FirecrackerConfig, host fcHost) (*FirecrackerDriver, error) {
	for _, path := range []string{cfg.Root, cfg.Firecracker, cfg.Jailer, cfg.Kernel} {
		if !cleanAbs(path) {
			return nil, fmt.Errorf("Firecracker paths must be absolute and clean: %q", path)
		}
	}
	if !strings.Contains(filepath.Base(cfg.Firecracker), "firecracker") {
		return nil, errors.New("the jailer requires a Firecracker binary whose name contains \"firecracker\"")
	}
	if len(cfg.Images) == 0 {
		return nil, errors.New("Firecracker image allowlist must not be empty")
	}
	if len(cfg.Slots) == 0 || len(cfg.Slots) > fcMaxSlots {
		return nil, fmt.Errorf("Firecracker worker needs between 1 and %d slots", fcMaxSlots)
	}
	for i, slot := range cfg.Slots {
		if slot != "sbx"+strconv.Itoa(i) || !fcSlotName.MatchString(slot) {
			return nil, fmt.Errorf("Firecracker slot %d must be named sbx%d", i, i)
		}
	}
	if cfg.UIDBase < 1<<20 || cfg.UIDBase > 1<<30 {
		return nil, errors.New("Firecracker UID base must be between 2^20 and 2^30")
	}
	if cfg.HomeDiskMiB < 64 || cfg.HomeDiskMiB > 1<<20 || cfg.DiskFloorMiB < 0 {
		return nil, errors.New("invalid Firecracker home disk size or disk floor")
	}
	if cfg.BootTimeout <= 0 {
		return nil, errors.New("Firecracker boot timeout must be positive")
	}
	for _, path := range []string{cfg.Firecracker, cfg.Jailer} {
		if err := host.TrustedFile(path, true); err != nil {
			return nil, err
		}
	}
	images := make(map[string]struct{}, len(cfg.Images))
	for _, image := range append([]string{cfg.Kernel}, cfg.Images...) {
		if !cleanAbs(image) {
			return nil, fmt.Errorf("Firecracker image paths must be absolute and clean: %q", image)
		}
		if err := host.TrustedFile(image, false); err != nil {
			return nil, err
		}
		if image != cfg.Kernel {
			images[image] = struct{}{}
		}
	}
	// Host addresses on every interface are denied separately (fib daddr
	// type local).
	deny4, deny6, err := egress.Deny(cfg.DenyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("invalid Firecracker %w", err)
	}
	cfg.Images = slices.Clone(cfg.Images)
	cfg.Slots = slices.Clone(cfg.Slots)
	cfg.DenyCIDRs = slices.Clone(cfg.DenyCIDRs)
	return &FirecrackerDriver{cfg: cfg, images: images, deny4: prefixStrings(deny4), deny6: prefixStrings(deny6), host: host}, nil
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.String()
	}
	return out
}

func (d *FirecrackerDriver) runDir() string   { return filepath.Join(d.cfg.Root, "run") }
func (d *FirecrackerDriver) jailBase() string { return filepath.Join(d.cfg.Root, "jail") }
func (d *FirecrackerDriver) jailsDir() string {
	return filepath.Join(d.jailBase(), filepath.Base(d.cfg.Firecracker))
}
func (d *FirecrackerDriver) jailDir(id string) string  { return filepath.Join(d.jailsDir(), id) }
func (d *FirecrackerDriver) chroot(id string) string   { return filepath.Join(d.jailDir(id), "root") }
func (d *FirecrackerDriver) metaPath(id string) string { return filepath.Join(d.runDir(), id+".json") }
func (d *FirecrackerDriver) uidRange() (int, int) {
	return d.cfg.UIDBase, d.cfg.UIDBase + 2*fcUIDStride - 1
}

// fcHostRuleset is the sandboxd-owned host table. Every socket of a VMM or
// user-mode network stack UID is denied host addresses (on every interface),
// private and special ranges; everything else is the internet. The output
// hook only adds rejects for those UIDs and never touches other tables,
// Docker or iptables chains. auto-merge accepts overlapping deny entries.
func fcHostRuleset(uidLow, uidHigh int, deny4, deny6 []string) string {
	return fmt.Sprintf(`table inet %s {
	set deny4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { %s }
	}
	set deny6 {
		type ipv6_addr
		flags interval
		auto-merge
		elements = { %s }
	}
	chain output {
		type filter hook output priority filter - 10; policy accept;
		meta skuid %d-%d jump guest
	}
	chain guest {
		fib daddr type { local, broadcast, multicast, anycast } counter reject with icmpx type admin-prohibited
		ip daddr @deny4 counter reject with icmpx type admin-prohibited
		ip6 daddr @deny6 counter reject with icmpx type admin-prohibited
	}
}
`, fcHostTable, strings.Join(deny4, ", "), strings.Join(deny6, ", "), uidLow, uidHigh)
}

// fcNetnsRuleset confines the VM's own namespace: the guest may only be
// forwarded to public addresses through the NAT tap, never to the namespace
// itself, the NAT's virtual host (10.0.2.2) or its resolver.
func fcNetnsRuleset(deny4 []string) string {
	return fmt.Sprintf(`table inet %s {
	set deny4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { %s }
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname %[3]q reject with icmpx type admin-prohibited
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		iifname %[3]q oifname %[4]q meta nfproto ipv4 ip daddr != @deny4 accept
		iifname %[3]q reject with icmpx type admin-prohibited
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %[4]q masquerade
	}
}
`, fcNetnsTable, strings.Join(deny4, ", "), fcGuestTap, fcSlirpTap)
}

// Arm creates the cgroup parent and atomically (re)installs the host table,
// then records its exact state for Ready. Call it before admitting guests,
// including after a daemon restart with surviving guests.
func (d *FirecrackerDriver) Arm(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.armed = ""
	if err := d.host.EnsureCgroupParent(); err != nil {
		return err
	}
	low, high := d.uidRange()
	if err := d.host.ApplyFirewall(ctx, fcHostRuleset(low, high, d.deny4, d.deny6)); err != nil {
		return err
	}
	state, err := d.host.FirewallState(ctx)
	if err != nil {
		return err
	}
	if state == "" {
		return errors.New("host firewall table is empty after install")
	}
	d.armed = state
	return nil
}

// Ready confirms the host table is still exactly as armed.
func (d *FirecrackerDriver) Ready(ctx context.Context) error {
	d.mu.Lock()
	armed := d.armed
	d.mu.Unlock()
	if armed == "" {
		return errors.New("host firewall is not armed")
	}
	state, err := d.host.FirewallState(ctx)
	if err != nil {
		return fmt.Errorf("host firewall check failed: %w", err)
	}
	if state != armed {
		return errors.New("host firewall table changed since it was armed")
	}
	return nil
}

// Disarm removes the host table and cgroup parent once no VM remains.
func (d *FirecrackerDriver) Disarm(ctx context.Context) error {
	vms, err := d.inventory()
	if err != nil {
		return err
	}
	if len(vms) != 0 {
		return fmt.Errorf("%d Firecracker VMs remain; destroy them before disarming", len(vms))
	}
	d.mu.Lock()
	d.armed = ""
	d.mu.Unlock()
	return errors.Join(d.host.RemoveFirewall(ctx), d.host.RemoveCgroupParent())
}

// CleanupGuests destroys every VM this driver owns.
func (d *FirecrackerDriver) CleanupGuests(ctx context.Context) error {
	vms, err := d.inventory()
	if err != nil {
		return err
	}
	var errs []error
	for _, vm := range vms {
		errs = append(errs, d.Destroy(ctx, vm.id))
	}
	return errors.Join(errs...)
}

// fcVM is every trace of one VM found on the host.
type fcVM struct {
	id      string
	meta    *fcMeta
	netns   bool
	jail    bool
	vmm     bool // VMM cgroup exists
	vmmUp   bool // VMM cgroup has processes
	network bool
	netUp   bool
}

func (vm fcVM) running() bool { return vm.meta != nil && vm.netns && vm.vmmUp && vm.netUp }

func (d *FirecrackerDriver) readMeta(id string) (*fcMeta, error) {
	data, err := os.ReadFile(d.metaPath(id))
	if err != nil {
		return nil, err
	}
	var meta fcMeta
	if json.Unmarshal(data, &meta) != nil || meta.ID != id || !slices.Contains(d.cfg.Slots, meta.Slot) {
		return nil, nil
	}
	slot := slices.Index(d.cfg.Slots, meta.Slot)
	if meta.VMMUID != d.cfg.UIDBase+slot || meta.NetUID != d.cfg.UIDBase+fcUIDStride+slot {
		return nil, nil
	}
	return &meta, nil
}

func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

// inventory merges every trace (records, jails, namespaces, cgroups) into a
// complete list. Any unreadable source or foreign name makes it fail rather
// than report an incomplete observation.
func (d *FirecrackerDriver) inventory() ([]fcVM, error) {
	vms := map[string]*fcVM{}
	get := func(id string) (*fcVM, error) {
		if err := validAppleID(id); err != nil {
			return nil, fmt.Errorf("incomplete Firecracker inventory: %w", err)
		}
		vm, ok := vms[id]
		if !ok {
			vm = &fcVM{id: id}
			vms[id] = vm
		}
		return vm, nil
	}
	records, err := readDirNames(d.runDir())
	if err != nil {
		return nil, err
	}
	for _, name := range records {
		id, ok := strings.CutSuffix(name, ".json")
		if !ok {
			return nil, fmt.Errorf("incomplete Firecracker inventory: unexpected record %q", name)
		}
		vm, err := get(id)
		if err != nil {
			return nil, err
		}
		meta, err := d.readMeta(id)
		if err != nil {
			return nil, err
		}
		vm.meta = meta
	}
	jails, err := readDirNames(d.jailsDir())
	if err != nil {
		return nil, err
	}
	for _, id := range jails {
		vm, err := get(id)
		if err != nil {
			return nil, err
		}
		vm.jail = true
	}
	namespaces, err := d.host.Netns()
	if err != nil {
		return nil, err
	}
	for _, name := range namespaces {
		id, ok := strings.CutPrefix(name, fcNetnsPrefix)
		if !ok {
			continue
		}
		vm, err := get(id)
		if err != nil {
			return nil, err
		}
		vm.netns = true
	}
	cgroups, err := d.host.Cgroups()
	if err != nil {
		return nil, err
	}
	for _, name := range cgroups {
		id, network := strings.CutPrefix(name, fcNetCgroup)
		vm, err := get(id)
		if err != nil {
			return nil, err
		}
		populated, err := d.host.CgroupPopulated(name)
		if err != nil {
			return nil, err
		}
		if network {
			vm.network, vm.netUp = true, populated
		} else {
			vm.vmm, vm.vmmUp = true, populated
		}
	}
	ids := make([]string, 0, len(vms))
	for id := range vms {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]fcVM, 0, len(ids))
	for _, id := range ids {
		out = append(out, *vms[id])
	}
	return out, nil
}

func (d *FirecrackerDriver) lookup(id string) (fcVM, bool, error) {
	vms, err := d.inventory()
	if err != nil {
		return fcVM{}, false, err
	}
	for _, vm := range vms {
		if vm.id == id {
			return vm, true, nil
		}
	}
	return fcVM{}, false, nil
}

// List reports every VM with any host trace. Only a VM whose record,
// namespace, VMM and network stack are all present is running; anything else
// is stopped and must be destroyed by the caller.
func (d *FirecrackerDriver) List(ctx context.Context) ([]Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vms, err := d.inventory()
	if err != nil {
		return nil, err
	}
	instances := make([]Instance, 0, len(vms))
	for _, vm := range vms {
		instance := Instance{ID: vm.id, Running: vm.running()}
		if vm.meta != nil && vm.netns {
			instance.Network = vm.meta.Slot
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

func (d *FirecrackerDriver) bootArgs() string {
	return "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd " +
		"random.trust_cpu=on quiet init=/sbin/sandboxd-agent " +
		"ip=" + fcGuestAddr + "::" + fcGatewayAddr + ":255.255.255.252:sandbox:eth0:off"
}

func (d *FirecrackerDriver) vmConfig(spec Spec) ([]byte, error) {
	type drive struct {
		ID       string `json:"drive_id"`
		Path     string `json:"path_on_host"`
		Root     bool   `json:"is_root_device"`
		ReadOnly bool   `json:"is_read_only"`
	}
	return json.MarshalIndent(map[string]any{
		"boot-source": map[string]any{"kernel_image_path": "/vmlinux", "boot_args": d.bootArgs()},
		"drives": []drive{
			{ID: "rootfs", Path: "/rootfs.ext4", Root: true, ReadOnly: true},
			{ID: "home", Path: "/home.ext4"},
		},
		"machine-config": map[string]any{"vcpu_count": spec.CPUs, "mem_size_mib": spec.MemoryMiB, "smt": false},
		"network-interfaces": []map[string]any{
			{"iface_id": "eth0", "host_dev_name": fcGuestTap, "guest_mac": fcGuestMAC},
		},
		"vsock": map[string]any{"guest_cid": fcGuestCID, "uds_path": fcVsockPath},
	}, "", "  ")
}

func (d *FirecrackerDriver) jailerArgs(meta fcMeta) []string {
	home := int64(d.cfg.HomeDiskMiB) << 20
	return []string{
		"--id", meta.ID,
		"--exec-file", d.cfg.Firecracker,
		"--uid", strconv.Itoa(meta.VMMUID), "--gid", strconv.Itoa(meta.VMMUID),
		"--chroot-base-dir", d.jailBase(),
		"--netns", d.host.NetnsPath(fcNetnsPrefix + meta.ID),
		"--new-pid-ns",
		"--cgroup-version", "2",
		"--parent-cgroup", fcCgroupParent,
		"--cgroup", "memory.max=" + strconv.FormatInt(int64(meta.MemoryMiB+fcVMMOverhead)<<20, 10),
		"--cgroup", "memory.swap.max=0",
		"--cgroup", "cpu.max=" + strconv.Itoa(meta.CPUs*100000) + " 100000",
		"--cgroup", "pids.max=" + strconv.Itoa(fcVMMPids),
		"--resource-limit", "fsize=" + strconv.FormatInt(home, 10),
		"--resource-limit", "no-file=256",
		"--",
		"--no-api", "--config-file", fcConfigPath, "--level", "Warning",
	}
}

// writeFileExcl creates path with exactly mode and data; it never replaces
// an existing file. The mode is set explicitly: the daemon's umask (0077
// under a hardened service manager) must not decide what the VMM can read.
func writeFileExcl(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Chmod(mode), file.Sync(), file.Close())
}

// mkdirExact creates one directory with exactly mode, whatever the umask.
func mkdirExact(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// prepareJail lays out the chroot before the jailer runs: hard links of the
// read-only kernel and root image, a fresh sparse home disk and a socket
// directory owned by the VMM UID, and the world-readable VM configuration.
// The VMM reads these as its own UID, so no mode may depend on the umask.
func (d *FirecrackerDriver) prepareJail(spec Spec, meta fcMeta) error {
	root := d.chroot(spec.ID)
	for _, dir := range []string{d.jailBase(), d.jailsDir()} {
		if err := mkdirExact(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if err := mkdirExact(d.jailDir(spec.ID), 0o700); err != nil {
		return err
	}
	if err := mkdirExact(root, 0o755); err != nil {
		return err
	}
	if err := os.Link(d.cfg.Kernel, filepath.Join(root, "vmlinux")); err != nil {
		return fmt.Errorf("link kernel into jail (same filesystem required): %w", err)
	}
	if err := os.Link(spec.Image, filepath.Join(root, "rootfs.ext4")); err != nil {
		return fmt.Errorf("link image into jail (same filesystem required): %w", err)
	}
	home := filepath.Join(root, "home.ext4")
	file, err := os.OpenFile(home, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := errors.Join(file.Truncate(int64(d.cfg.HomeDiskMiB)<<20), file.Chmod(0o600), file.Close()); err != nil {
		return err
	}
	if err := d.host.Chown(home, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	run := filepath.Join(root, filepath.Dir(fcVsockPath))
	if err := mkdirExact(run, 0o700); err != nil {
		return err
	}
	if err := d.host.Chown(run, meta.VMMUID, meta.VMMUID); err != nil {
		return err
	}
	config, err := d.vmConfig(spec)
	if err != nil {
		return err
	}
	return writeFileExcl(filepath.Join(root, fcConfigPath), config, 0o444)
}

// Create boots one VM on spec.Network's slot. Any failure after the record is
// written destroys every trace it created.
func (d *FirecrackerDriver) Create(ctx context.Context, spec Spec) (Instance, error) {
	if err := validAppleID(spec.ID); err != nil {
		return Instance{}, err
	}
	if _, ok := d.images[spec.Image]; !ok {
		return Instance{}, fmt.Errorf("Firecracker image %q is not allowlisted", spec.Image)
	}
	slot := slices.Index(d.cfg.Slots, spec.Network)
	if slot < 0 {
		return Instance{}, fmt.Errorf("Firecracker slot %q is not configured", spec.Network)
	}
	if spec.CPUs < 1 || spec.CPUs > fcMaxCPUs || spec.MemoryMiB < fcMinMemoryMiB || spec.MemoryMiB > fcMaxMemoryMiB {
		return Instance{}, errors.New("Firecracker VM shape out of range")
	}
	if err := d.Ready(ctx); err != nil {
		return Instance{}, fmt.Errorf("firewall is not armed before guest start: %w", err)
	}
	vms, err := d.inventory()
	if err != nil {
		return Instance{}, err
	}
	for _, vm := range vms {
		switch {
		case vm.id == spec.ID:
			return Instance{}, fmt.Errorf("Firecracker VM %q already exists", spec.ID)
		case vm.meta == nil:
			return Instance{}, fmt.Errorf("Firecracker VM %q has no ownership record; destroy it first", vm.id)
		case vm.meta.Slot == spec.Network:
			return Instance{}, fmt.Errorf("Firecracker slot %q is in use by %q", spec.Network, vm.id)
		}
	}
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return Instance{}, err
	}
	if need := uint64(d.cfg.DiskFloorMiB+d.cfg.HomeDiskMiB) << 20; free < need {
		return Instance{}, fmt.Errorf("%w: %d MiB free, %d MiB floor plus %d MiB home disk needed",
			ErrDiskFloor, free>>20, d.cfg.DiskFloorMiB, d.cfg.HomeDiskMiB)
	}
	meta := fcMeta{
		ID: spec.ID, Slot: spec.Network, VMMUID: d.cfg.UIDBase + slot, NetUID: d.cfg.UIDBase + fcUIDStride + slot,
		Image: spec.Image, CPUs: spec.CPUs, MemoryMiB: spec.MemoryMiB,
	}
	record, err := json.Marshal(meta)
	if err != nil {
		return Instance{}, err
	}
	if err := os.MkdirAll(d.runDir(), 0o700); err != nil {
		return Instance{}, err
	}
	if err := writeFileExcl(d.metaPath(spec.ID), record, 0o600); err != nil {
		return Instance{}, err
	}
	if err := d.start(ctx, spec, meta); err != nil {
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	return Instance{ID: spec.ID, Running: true, Network: spec.Network}, nil
}

func (d *FirecrackerDriver) start(ctx context.Context, spec Spec, meta fcMeta) error {
	if err := d.prepareJail(spec, meta); err != nil {
		return err
	}
	if err := d.host.CreateNetwork(ctx, fcNetwork{
		Netns: fcNetnsPrefix + spec.ID, Cgroup: fcNetCgroup + spec.ID,
		NetUID: meta.NetUID, VMMUID: meta.VMMUID, Ruleset: fcNetnsRuleset(d.deny4),
	}); err != nil {
		return err
	}
	console := os.DevNull
	if d.cfg.ConsoleLog {
		console = filepath.Join(d.jailDir(spec.ID), "console.log")
	}
	if err := d.host.StartVMM(ctx, d.cfg.Jailer, d.jailerArgs(meta), console); err != nil {
		return err
	}
	if err := d.waitAgent(ctx, spec.ID); err != nil {
		return err
	}
	vm, found, err := d.lookup(spec.ID)
	if err != nil {
		return err
	}
	if !found || !vm.running() {
		return fmt.Errorf("Firecracker VM %q did not stay running", spec.ID)
	}
	if err := d.Ready(ctx); err != nil {
		return fmt.Errorf("firewall lost after guest start: %w", err)
	}
	return nil
}

// waitAgent polls the guest agent until it answers or the VMM is gone.
func (d *FirecrackerDriver) waitAgent(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.BootTimeout)
	defer cancel()
	started := time.Now()
	var last error
	for {
		conn, err := d.dialAgent(ctx, id)
		if err == nil {
			err = guestagent.Ping(ctx, conn)
			_ = conn.Close()
			if err == nil {
				return nil
			}
		}
		last = err
		if time.Since(started) > 3*time.Second {
			populated, perr := d.host.CgroupPopulated(id)
			if perr != nil || !populated {
				return errors.Join(fmt.Errorf("Firecracker VMM for %q exited during boot", id), last, perr)
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("guest agent of %q did not answer: %w", id, ctx.Err()), last)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (d *FirecrackerDriver) dialAgent(ctx context.Context, id string) (net.Conn, error) {
	meta, err := d.readMeta(id)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, fmt.Errorf("Firecracker VM %q has no valid ownership record", id)
	}
	conn, err := d.host.Dial(ctx, d.chroot(id), meta.VMMUID)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err = guestagent.Handshake(conn, guestagent.Port)
	if !stop() || err != nil {
		_ = conn.Close()
		return nil, errors.Join(err, ctx.Err())
	}
	return conn, nil
}

func (d *FirecrackerDriver) cleanupCreated(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return d.Destroy(ctx, id)
}

func (d *FirecrackerDriver) running(id string) error {
	vm, found, err := d.lookup(id)
	if err != nil {
		return err
	}
	if !found || !vm.running() {
		return fmt.Errorf("Firecracker VM %q is not running", id)
	}
	return nil
}

// CopyIn streams at most 512 MiB of a regular host file to the guest, where
// the agent writes it as the guest user, creating missing parents (0700) and
// the file (0600) as `umask 077; mkdir -p; cat >` does.
func (d *FirecrackerDriver) CopyIn(ctx context.Context, id, source, destination string) error {
	if !safeGuestPath(destination) {
		return fmt.Errorf("unsafe guest destination %q", destination)
	}
	if !cleanAbs(source) {
		return errors.New("source must be an absolute clean host file path")
	}
	if err := d.running(id); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCopyBytes {
		return fmt.Errorf("copy source must be a regular file no larger than %d bytes", maxCopyBytes)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return errors.New("copy source changed while opening")
	}
	conn, err := d.dialAgent(ctx, id)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := guestagent.Write(ctx, conn, destination, opened.Size(), in); err != nil {
		return fmt.Errorf("guest copy failed: %w", err)
	}
	return nil
}

// Run executes a command as the guest user through the vsock agent. It
// re-checks the host firewall every second and destroys the VM if it was
// lost. OnStart receives the agent's correlation ID, not a guest PID.
func (d *FirecrackerDriver) Run(ctx context.Context, id string, command Command, stdout, stderr io.Writer) (int, error) {
	if err := d.Ready(ctx); err != nil {
		return 0, fmt.Errorf("firewall is not armed before guest execution: %w", err)
	}
	if len(command.Args) == 0 || command.Args[0] == "" {
		return 0, errors.New("empty guest command")
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, 0) {
			return 0, errors.New("NUL in guest command")
		}
	}
	if command.User != "" && command.User != "user" && command.User != "1000" && command.User != "1000:1000" {
		return 0, fmt.Errorf("guest user %q is not permitted", command.User)
	}
	if command.Dir != "" && !safeGuestPath(command.Dir) && command.Dir != "/" {
		return 0, fmt.Errorf("unsafe guest working directory %q", command.Dir)
	}
	for key, value := range command.Env {
		if !envName.MatchString(key) || strings.ContainsRune(value, 0) {
			return 0, fmt.Errorf("unsafe guest environment variable %q", key)
		}
	}
	if err := d.running(id); err != nil {
		return 0, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, err := d.dialAgent(runCtx, id)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	failed := make(chan error, 1)
	done := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(runCtx, 5*time.Second)
				checkErr := d.Ready(checkCtx)
				stop()
				if checkErr != nil {
					failed <- checkErr
					cancel()
					return
				}
			}
		}
	}()
	code, err := guestagent.Exec(runCtx, conn, guestagent.Request{Args: command.Args, Dir: command.Dir, Env: command.Env}, stdout, stderr, command.OnStart)
	close(done)
	<-monitorDone
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	select {
	case gateErr := <-failed:
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		return 0, errors.Join(fmt.Errorf("firewall lost during guest execution: %w", gateErr), d.Destroy(cleanupCtx, id))
	default:
	}
	if err != nil {
		return 0, err
	}
	return code, nil
}

// Usage samples the VMM cgroup twice: CPU from usage_usec, memory against
// the cgroup limit (guest RAM plus VMM overhead).
func (d *FirecrackerDriver) Usage(ctx context.Context, id string) (Usage, error) {
	if err := d.running(id); err != nil {
		return Usage{}, err
	}
	firstCPU, _, _, err := d.host.CgroupStats(id)
	if err != nil {
		return Usage{}, err
	}
	started := time.Now()
	select {
	case <-ctx.Done():
		return Usage{}, ctx.Err()
	case <-time.After(250 * time.Millisecond):
	}
	secondCPU, memory, limit, err := d.host.CgroupStats(id)
	if err != nil {
		return Usage{}, err
	}
	if secondCPU < firstCPU || limit == 0 || memory > limit {
		return Usage{}, fmt.Errorf("inconsistent VM resource sample for %q", id)
	}
	return Usage{
		CPUUsedPct:       float64(secondCPU-firstCPU) / float64(time.Since(started).Microseconds()) * 100,
		MemoryUsedBytes:  memory,
		MemoryLimitBytes: limit,
	}, nil
}

// Destroy kills the VMM and network stack, deletes the namespace (and with it
// the tap), the jail and finally the record, then confirms nothing remains.
// It is idempotent and works from any partial state, including after a host
// or daemon restart.
func (d *FirecrackerDriver) Destroy(ctx context.Context, id string) error {
	if err := validAppleID(id); err != nil {
		return err
	}
	vm, found, err := d.lookup(id)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if vm.vmm {
		if err := d.host.KillCgroup(ctx, id); err != nil {
			return err
		}
	}
	if vm.network {
		if err := d.host.KillCgroup(ctx, fcNetCgroup+id); err != nil {
			return err
		}
	}
	if vm.netns {
		if err := d.host.DeleteNetns(ctx, fcNetnsPrefix+id); err != nil {
			return err
		}
	}
	if vm.jail {
		if err := os.RemoveAll(d.jailDir(id)); err != nil {
			return err
		}
	}
	if err := os.Remove(d.metaPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, still, err := d.lookup(id); err != nil || still {
		return errors.Join(err, fmt.Errorf("Firecracker VM %q remains after destroy", id))
	}
	return nil
}
