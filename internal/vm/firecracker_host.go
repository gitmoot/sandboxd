//go:build linux

package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fcCgroupRoot   = "/sys/fs/cgroup"
	fcCgroupParent = "sbx-fc"
	fcNetnsDir     = "/run/netns"
	fcHostPath     = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
)

// fcTools are the host binaries the real host runs, resolved once from
// fixed system directories, never from the daemon's PATH.
type fcTools struct {
	ip, nft, nsenter, setpriv, unshare, slirp, sleep string
}

type linuxFCHost struct {
	tools    fcTools
	toolsErr error
}

func newLinuxFCHost() *linuxFCHost {
	h := &linuxFCHost{}
	find := func(name string) string {
		for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			path := filepath.Join(dir, name)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				return path
			}
		}
		h.toolsErr = errors.Join(h.toolsErr, fmt.Errorf("required host tool %q not found", name))
		return ""
	}
	h.tools = fcTools{
		ip: find("ip"), nft: find("nft"), nsenter: find("nsenter"), setpriv: find("setpriv"),
		unshare: find("unshare"), slirp: find("slirp4netns"), sleep: find("sleep"),
	}
	return h
}

func (h *linuxFCHost) run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if h.toolsErr != nil {
		return nil, h.toolsErr
	}
	c := exec.CommandContext(ctx, name, args...)
	c.Env = []string{fcHostPath}
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// TrustedFile requires a root-owned regular file that neither it nor any
// parent directory is writable by anyone else.
func (h *linuxFCHost) TrustedFile(path string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := trustedFileMode(path, info.Mode(), executable); err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s must be root-owned and not group or world writable", current)
		}
		if current == "/" {
			return nil
		}
	}
}

// trustedFileMode checks the file's own mode. Kernels and root images are
// hard-linked into each jail and opened by the unprivileged VMM UID, so they
// must be readable by others; a 0600 or 0400 install would otherwise pass
// startup and fail every create with an opaque boot error.
func trustedFileMode(path string, mode fs.FileMode, executable bool) error {
	if !mode.IsRegular() || (executable && mode.Perm()&0o100 == 0) {
		return fmt.Errorf("%s must be a regular%s file", path, map[bool]string{true: " executable", false: ""}[executable])
	}
	if !executable && mode.Perm()&0o004 == 0 {
		return fmt.Errorf("%s must be readable by others (mode %04o): the jailed VMM opens it as an unprivileged user", path, mode.Perm())
	}
	return nil
}

func (h *linuxFCHost) FreeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func (h *linuxFCHost) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

func (h *linuxFCHost) ApplyFirewall(ctx context.Context, ruleset string) error {
	// One transaction: the table is replaced atomically, never absent.
	script := "table inet " + fcHostTable + " {}\ndelete table inet " + fcHostTable + "\n" + ruleset
	_, err := h.run(ctx, []byte(script), h.tools.nft, "-f", "-")
	return err
}

// FirewallState is the stateless listing (without counters) of the table, or
// "" when it does not exist.
func (h *linuxFCHost) FirewallState(ctx context.Context) (string, error) {
	out, err := h.run(ctx, nil, h.tools.nft, "-s", "list", "tables", "inet")
	if err != nil {
		return "", err
	}
	if !strings.Contains("\n"+string(out), "\ntable inet "+fcHostTable+"\n") {
		return "", nil
	}
	out, err = h.run(ctx, nil, h.tools.nft, "-s", "list", "table", "inet", fcHostTable)
	return string(out), err
}

func (h *linuxFCHost) RemoveFirewall(ctx context.Context) error {
	state, err := h.FirewallState(ctx)
	if err != nil || state == "" {
		return err
	}
	_, err = h.run(ctx, nil, h.tools.nft, "delete", "table", "inet", fcHostTable)
	return err
}

func cgroupPath(name string) string {
	if name == "" {
		return filepath.Join(fcCgroupRoot, fcCgroupParent)
	}
	return filepath.Join(fcCgroupRoot, fcCgroupParent, name)
}

func (h *linuxFCHost) EnsureCgroupParent() error {
	if err := os.Mkdir(cgroupPath(""), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return os.WriteFile(filepath.Join(cgroupPath(""), "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0)
}

func (h *linuxFCHost) RemoveCgroupParent() error {
	err := unix.Rmdir(cgroupPath(""))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (h *linuxFCHost) Cgroups() ([]string, error) {
	entries, err := os.ReadDir(cgroupPath(""))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

func (h *linuxFCHost) CgroupPopulated(name string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath(name), "cgroup.events"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "populated "); ok {
			return value == "1", nil
		}
	}
	return false, fmt.Errorf("cgroup %s has no populated field", name)
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func (h *linuxFCHost) CgroupStats(name string) (uint64, uint64, uint64, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath(name), "cpu.stat"))
	if err != nil {
		return 0, 0, 0, err
	}
	var cpu uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "usage_usec "); ok {
			cpu, err = strconv.ParseUint(value, 10, 64)
			found = err == nil
		}
	}
	if !found {
		return 0, 0, 0, fmt.Errorf("cgroup %s has no CPU usage", name)
	}
	memory, err := readUint(filepath.Join(cgroupPath(name), "memory.current"))
	if err != nil {
		return 0, 0, 0, err
	}
	limit, err := readUint(filepath.Join(cgroupPath(name), "memory.max"))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cgroup %s has no numeric memory limit: %w", name, err)
	}
	return cpu, memory, limit, nil
}

// KillCgroup kills every process in the cgroup, waits until it is empty and
// removes it.
func (h *linuxFCHost) KillCgroup(ctx context.Context, name string) error {
	path := cgroupPath(name)
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for {
		populated, err := h.CgroupPopulated(name)
		if err != nil {
			return err
		}
		if !populated {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("cgroup %s still populated: %w", name, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := unix.Rmdir(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (h *linuxFCHost) Netns() ([]string, error) {
	entries, err := os.ReadDir(fcNetnsDir)
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

func (h *linuxFCHost) NetnsPath(name string) string { return filepath.Join(fcNetnsDir, name) }

func (h *linuxFCHost) DeleteNetns(ctx context.Context, name string) error {
	_, err := h.run(ctx, nil, h.tools.ip, "netns", "delete", name)
	if err != nil {
		if _, statErr := os.Stat(h.NetnsPath(name)); errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
	}
	return err
}

// startInCgroup starts c directly inside cgroup name (clone3 CLONE_INTO_CGROUP),
// so it is never outside the cgroup that Destroy kills.
func startInCgroup(c *exec.Cmd, name string) error {
	dir, err := os.Open(cgroupPath(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.UseCgroupFD = true
	c.SysProcAttr.CgroupFD = int(dir.Fd())
	c.SysProcAttr.Setsid = true
	return c.Start()
}

func writeCgroup(name, file, value string) error {
	return os.WriteFile(filepath.Join(cgroupPath(name), file), []byte(value), 0)
}

// CreateNetwork builds the VM's network namespace. A holder process, running
// as NetUID with CAP_SYS_ADMIN only to create it, unshares a user namespace
// mapping only NetUID and a network namespace owned by it; the namespace is
// pinned under /run/netns. slirp4netns then joins it as NetUID without any
// host capabilities (sandboxed and seccomp-filtered) and is the namespace's
// only exit. The VMM's tap belongs to VMMUID.
func (h *linuxFCHost) CreateNetwork(ctx context.Context, network fcNetwork) error {
	if h.toolsErr != nil {
		return h.toolsErr
	}
	if err := os.MkdirAll(fcNetnsDir, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(cgroupPath(network.Cgroup), 0o755); err != nil {
		return err
	}
	if err := errors.Join(
		writeCgroup(network.Cgroup, "memory.max", strconv.Itoa(fcNetMemoryMax)),
		writeCgroup(network.Cgroup, "pids.max", strconv.Itoa(fcNetPids)),
	); err != nil {
		return err
	}
	uid := strconv.Itoa(network.NetUID)
	holder := exec.Command(h.tools.setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups",
		"--inh-caps=-all,+sys_admin", "--ambient-caps=+sys_admin", "--",
		h.tools.unshare, "--user", "--map-root-user", "--net", "--", h.tools.sleep, "infinity")
	holder.Env = []string{fcHostPath}
	holder.Dir = "/"
	if err := startInCgroup(holder, network.Cgroup); err != nil {
		return err
	}
	holderPID := holder.Process.Pid
	go func() { _ = holder.Wait() }()
	// Wait until the holder is in its own user and network namespaces.
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", holderPID))
		if err == nil && link != own {
			if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", holderPID)); err == nil && strings.TrimSpace(string(data)) == "sleep" {
				break
			}
		}
		if time.Now().After(deadline) {
			return errors.New("network namespace holder did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := h.run(ctx, nil, h.tools.ip, "netns", "attach", network.Netns, strconv.Itoa(holderPID)); err != nil {
		return err
	}
	ns := "--net=" + h.NetnsPath(network.Netns)
	vmm := strconv.Itoa(network.VMMUID)
	steps := [][]string{
		{h.tools.ip, "-n", network.Netns, "link", "set", "lo", "up"},
		{h.tools.ip, "-n", network.Netns, "tuntap", "add", "dev", fcGuestTap, "mode", "tap", "user", vmm, "group", vmm},
		{h.tools.ip, "-n", network.Netns, "addr", "add", fcGatewayCIDR, "dev", fcGuestTap},
		{h.tools.ip, "-n", network.Netns, "link", "set", fcGuestTap, "up"},
		{h.tools.nsenter, ns, "--", "/bin/sh", "-c",
			"echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 && echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 && echo 1 > /proc/sys/net/ipv4/ip_forward"},
	}
	for _, step := range steps {
		if _, err := h.run(ctx, nil, step[0], step[1:]...); err != nil {
			return err
		}
	}
	if _, err := h.run(ctx, []byte(network.Ruleset), h.tools.nsenter, ns, "--", h.tools.nft, "-f", "-"); err != nil {
		return err
	}
	ready, readyWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ready.Close()
	slirp := exec.Command(h.tools.setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups",
		"--inh-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
		h.tools.slirp, "--configure", "--mtu=1500", "--disable-host-loopback", "--disable-dns",
		"--enable-sandbox", "--enable-seccomp", "--ready-fd=3",
		strconv.Itoa(holderPID), fcSlirpTap)
	slirp.Env = []string{fcHostPath}
	slirp.Dir = "/"
	slirp.ExtraFiles = []*os.File{readyWrite}
	err = startInCgroup(slirp, network.Cgroup)
	_ = readyWrite.Close()
	if err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- slirp.Wait() }()
	got := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := ready.Read(one[:])
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			return fmt.Errorf("slirp4netns did not become ready: %w", err)
		}
	case err := <-exited:
		return fmt.Errorf("slirp4netns exited during setup: %v", err)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("slirp4netns did not become ready")
	}
	return nil
}

// StartVMM runs the jailer, which forks the VMM into a new PID namespace and
// exits. The VMM's stdio (the guest serial console) goes to console.
func (h *linuxFCHost) StartVMM(ctx context.Context, jailer string, args []string, console string) error {
	out, err := os.OpenFile(console, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	c := exec.CommandContext(ctx, jailer, args...)
	c.Env = []string{}
	c.Dir = "/"
	c.Stdout, c.Stderr = out, out
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Run(); err != nil {
		return fmt.Errorf("jailer: %w", err)
	}
	return nil
}

func (h *linuxFCHost) Dial(ctx context.Context, chroot string, owner int) (net.Conn, error) {
	return dialJailSocket(ctx, chroot, owner)
}

// dialJailSocket connects to the VMM's vsock socket <chroot>/run/v.sock
// without following anything the VMM can replace. The VMM owns <chroot> and
// <chroot>/run, so each component is opened beneath the root-owned jail
// directory with O_NOFOLLOW; the run directory and the socket must belong to
// owner; and the connection goes to the opened socket inode through
// /proc/self/fd/N, never through a path that is resolved again. This also
// keeps sun_path short whatever the install directory.
func dialJailSocket(ctx context.Context, chroot string, owner int) (net.Conn, error) {
	const flags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	dir, err := unix.Open(filepath.Dir(chroot), flags|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open jail: %w", err)
	}
	defer unix.Close(dir)
	for _, name := range []string{filepath.Base(chroot), fcVsockDir} {
		next, err := unix.Openat(dir, name, flags|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, fmt.Errorf("open jail directory %q: %w", name, err)
		}
		defer unix.Close(next)
		dir = next
	}
	if err := checkOwned(dir, unix.S_IFDIR, owner); err != nil {
		return nil, fmt.Errorf("jail socket directory: %w", err)
	}
	sock, err := unix.Openat(dir, fcVsockName, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open jail socket: %w", err)
	}
	defer unix.Close(sock)
	if err := checkOwned(sock, unix.S_IFSOCK, owner); err != nil {
		return nil, fmt.Errorf("jail socket: %w", err)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(sock))
}

// checkOwned requires fd to be of the given file type and owned by owner.
func checkOwned(fd int, kind uint32, owner int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != kind {
		return fmt.Errorf("unexpected file type %#o", stat.Mode&unix.S_IFMT)
	}
	if int(stat.Uid) != owner {
		return fmt.Errorf("owned by uid %d, want %d", stat.Uid, owner)
	}
	return nil
}
