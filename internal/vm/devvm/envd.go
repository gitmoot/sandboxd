//go:build sandboxd_devdriver && linux

package devvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// Envd lets the dev driver run e2b guests (vm.Spec.Envd): upstream envd as a
// local root process in private mount, PID, network, UTS and IPC namespaces.
// envd needs root (it switches to the requested user, setgroups included),
// so it is started through Helper, a root helper: the sandboxd-dev binary
// itself, directly when already root or behind "sudo -n" otherwise.
//
// An envd guest is NOT isolated either: it shares the host filesystem, except
// that /home (with /home/user), /root, /run and /tmp are private and
// /etc/passwd and /etc/group name only root and user (1000:1000). Its network
// namespace holds only loopback, so envd is never reachable from the host
// network; the driver reaches it through a Unix socket the helper bridges to
// envd's port, the dev stand-in for the Firecracker vsock channel.
type Envd struct {
	// Binary is the absolute path of the envd executable; empty disables
	// envd guests.
	Binary string
	// Helper is the argv prefix that runs this package's helper as root,
	// for example {"/usr/bin/sudo", "-n", "/path/to/sandboxd-dev"}. The
	// helper's own arguments are appended; its program must dispatch them to
	// RunEnvdGuest.
	Helper []string
}

const (
	// EnvdGuestCommand is the helper's first argument; programs used as the
	// helper pass os.Args[2:] to RunEnvdGuest when they see it.
	EnvdGuestCommand = "envd-guest"
	envdInitCommand  = "envd-guest-init"
	envdSocket       = "envd.sock"
	guestUID         = 1000
	guestGID         = 1000
	envdStartTimeout = 15 * time.Second
)

// envdGuestLayout lists what the helper creates in the guest directory, all
// removed by the helper itself (root owns them) before it exits.
var envdGuestLayout = []string{"home", "tmp", "root", "passwd", "group", envdSocket, envdSocket + ".pending"}

func (e Envd) validate() error {
	if e.Binary == "" {
		return nil
	}
	if !filepath.IsAbs(e.Binary) || len(e.Helper) == 0 || !filepath.IsAbs(e.Helper[0]) {
		return errors.New("dev driver envd binary and helper must be absolute paths")
	}
	info, err := os.Stat(e.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("dev driver envd binary %s is not an executable file", e.Binary)
	}
	return nil
}

// createEnvd starts an envd guest in dir. Callers hold d.mu.
func (d *Driver) createEnvd(spec vm.Spec, dir string) (*guest, error) {
	if d.envd.Binary == "" {
		return nil, fmt.Errorf("dev driver: %w (start sandboxd-dev with -envd)", vm.ErrNoEnvd)
	}
	args := append(append([]string{}, d.envd.Helper[1:]...), EnvdGuestCommand, dir, d.envd.Binary,
		strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	helper := exec.Command(d.envd.Helper[0], args...)
	helper.Dir = "/"
	helper.Env = []string{"PATH=" + guestPath}
	helper.Stdout, helper.Stderr = os.Stderr, os.Stderr
	// A new session: no controlling terminal, so sudo never allocates a pty
	// and passes the lifeline pipe straight to the helper.
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	lifeline, err := helper.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := helper.Start(); err != nil {
		return nil, err
	}
	g := &guest{network: spec.Network, memoryMiB: spec.MemoryMiB, dir: dir, home: filepath.Join(dir, "home"),
		holder: helper, exited: make(chan struct{}), envd: true, lifeline: lifeline}
	go func() {
		_ = helper.Wait()
		close(g.exited)
	}()
	socket := filepath.Join(dir, envdSocket)
	deadline := time.Now().Add(envdStartTimeout)
	for {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&fs.ModeSocket != 0 {
			return g, nil
		}
		if !g.running() || time.Now().After(deadline) {
			_ = lifeline.Close()
			<-g.exited
			return nil, fmt.Errorf("dev driver envd guest %q did not start (is the helper root? see the server log)", spec.ID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// DialEnvd connects to an envd guest's bridge socket.
func (d *Driver) DialEnvd(ctx context.Context, id string) (net.Conn, error) {
	g, err := d.running(id)
	if err != nil {
		return nil, err
	}
	if !g.envd {
		return nil, fmt.Errorf("guest %q runs no envd", id)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", filepath.Join(g.dir, envdSocket))
}

// destroyEnvd closes the helper's lifeline: it kills every process of the
// guest, removes what it created and exits.
func (g *guest) destroyEnvd(ctx context.Context) error {
	_ = g.lifeline.Close()
	select {
	case <-g.exited:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("envd guest helper did not exit: %w", ctx.Err())
	}
}

// RunEnvdGuest is the root helper (args after EnvdGuestCommand: guest
// directory, envd binary, owner UID and GID). It starts the guest's init in
// new namespaces and returns when that init exits.
func RunEnvdGuest(args []string) error {
	if len(args) != 4 {
		return errors.New("usage: envd-guest <dir> <envd> <uid> <gid>")
	}
	if os.Geteuid() != 0 {
		return errors.New("the envd guest helper must run as root")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	init := exec.Command(self, append([]string{envdInitCommand}, args...)...)
	init.Stdin, init.Stdout, init.Stderr = os.Stdin, os.Stdout, os.Stderr
	init.Env = []string{"PATH=" + guestPath}
	init.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
		Pdeathsig:  syscall.SIGKILL,
	}
	err = init.Run()
	// The guest's mounts and processes ended with its namespaces; what it
	// created in dir is removed here, in the host mount namespace.
	cleanEnvdGuest(args[0])
	return err
}

// RunEnvdGuestInit dispatches the helper's second stage; it reports whether
// args named it.
func RunEnvdGuestInit(args []string) (bool, error) {
	if len(args) == 0 || args[0] != envdInitCommand {
		return false, nil
	}
	return true, envdInit(args[1:])
}

// envdInit is PID 1 of an envd guest's namespaces.
func envdInit(args []string) error {
	if len(args) != 4 || os.Getpid() != 1 {
		return errors.New("envd guest init must be PID 1 of its namespaces")
	}
	dir, binary := args[0], args[1]
	uid, err1 := strconv.Atoi(args[2])
	gid, err2 := strconv.Atoi(args[3])
	if err := errors.Join(err1, err2); err != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("invalid envd guest arguments")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || !info.IsDir() || int(stat.Uid) != uid {
		return fmt.Errorf("envd guest directory %s must be a directory owned by uid %d", dir, uid)
	}
	// The socket is bound before the mounts below can hide dir; the driver
	// waits for it to appear only once setup is done (its rename).
	pending := filepath.Join(dir, envdSocket+".pending")
	listener, err := net.Listen("unix", pending)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := errors.Join(os.Chown(pending, uid, gid), os.Chmod(pending, 0o600)); err != nil {
		return err
	}
	dirFD, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	// Likewise the envd binary, executed through its descriptor.
	envdFD, err := unix.Open(binary, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(envdFD)
	if err := setupEnvdGuest(dir); err != nil {
		return err
	}
	children := make(chan os.Signal, 16)
	signal.Notify(children, syscall.SIGCHLD)
	envd := exec.Command(fmt.Sprintf("/proc/self/fd/%d", envdFD), "-isnotfc", "-no-cgroups", "-port", strconv.Itoa(vm.EnvdPort))
	envd.Dir = "/"
	envd.Env = []string{"PATH=" + guestPath, "HOME=/root", "LANG=C.UTF-8"}
	envd.Stdout, envd.Stderr = os.Stderr, os.Stderr
	if err := envd.Start(); err != nil {
		return err
	}
	go bridgeEnvd(listener)
	if err := unix.Renameat(dirFD, envdSocket+".pending", dirFD, envdSocket); err != nil {
		killAll()
		return err
	}
	lifeline := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(lifeline)
	}()
	for {
		select {
		case <-lifeline:
			killAll()
			return nil
		case <-children:
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
				if pid == envd.Process.Pid {
					killAll()
					return fmt.Errorf("envd exited: %v", status)
				}
			}
		}
	}
}

// setupEnvdGuest gives the guest its private directories and identities.
func setupEnvdGuest(dir string) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	if err := loopbackUp(); err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	_ = unix.Sethostname([]byte("sandbox"))
	for _, entry := range []struct {
		name string
		mode os.FileMode
		uid  int
	}{{"home", 0o755, guestUID}, {"tmp", 0o1777, 0}, {"root", 0o700, 0}} {
		path := filepath.Join(dir, entry.name)
		if err := os.Mkdir(path, entry.mode); err != nil {
			return err
		}
		if err := errors.Join(os.Chmod(path, entry.mode), os.Chown(path, entry.uid, entry.uid)); err != nil {
			return err
		}
	}
	files := map[string]string{
		"passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		"group":  "root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	// Open every bind source before mounting anything: dir itself may lie
	// below a target (/tmp, /root, /home) the mounts then hide.
	binds := [][2]string{
		{filepath.Join(dir, "home"), "/home/user"}, {filepath.Join(dir, "tmp"), "/tmp"}, {filepath.Join(dir, "root"), "/root"},
		{filepath.Join(dir, "passwd"), "/etc/passwd"}, {filepath.Join(dir, "group"), "/etc/group"},
	}
	sources := make([]int, len(binds))
	for i, bind := range binds {
		fd, err := unix.Open(bind[0], unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", bind[0], err)
		}
		defer unix.Close(fd)
		sources[i] = fd
	}
	mounts := []struct{ source, target, fstype, data string }{
		{"tmpfs", "/home", "tmpfs", "mode=0755,size=1m"},
		{"tmpfs", "/run", "tmpfs", "mode=0755,size=32m"},
	}
	for _, m := range mounts {
		if err := unix.Mount(m.source, m.target, m.fstype, unix.MS_NOSUID|unix.MS_NODEV, m.data); err != nil {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	if err := os.Mkdir("/home/user", 0o755); err != nil {
		return err
	}
	for i, bind := range binds {
		if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", sources[i]), bind[1], "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", bind[1], err)
		}
	}
	return nil
}

// cleanEnvdGuest removes what the helper created; the guest's processes are
// gone by then, so nothing can race the removal.
func cleanEnvdGuest(dir string) {
	for _, name := range envdGuestLayout {
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
}

// killAll kills every other process of the PID namespace and reaps them.
func killAll() {
	_ = syscall.Kill(-1, syscall.SIGKILL)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if errors.Is(err, syscall.ECHILD) {
			return
		}
		if pid <= 0 && err != nil && !errors.Is(err, syscall.EINTR) {
			return
		}
	}
}

// bridgeEnvd connects every accepted connection to envd on the namespace's
// loopback, retrying while envd is still starting.
func bridgeEnvd(listener net.Listener) {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(vm.EnvdPort))
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer client.Close()
			var upstream net.Conn
			deadline := time.Now().Add(envdStartTimeout)
			for {
				upstream, err = net.DialTimeout("tcp", address, time.Second)
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				return
			}
			defer upstream.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
			go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
			<-done
		}()
	}
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// sampleTree sums CPU ticks, resident and shared (file-backed) memory of pid
// and all its descendants, which for an envd guest is every process it runs
// (orphans are reparented to the guest's init, a descendant of pid).
func sampleTree(root int) (groupSample, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return groupSample{}, err
	}
	type proc struct {
		ppid  int
		stat  procStat
		share uint64
	}
	procs := map[int]proc{}
	page := uint64(os.Getpagesize())
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		fields, ok := statFields(string(raw))
		if !ok {
			continue
		}
		var shared uint64
		if statm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "statm")); err == nil {
			if values := strings.Fields(string(statm)); len(values) >= 3 {
				shared, _ = strconv.ParseUint(values[2], 10, 64)
			}
		}
		procs[pid] = proc{ppid: fields.ppid, stat: fields, share: shared * page}
	}
	var sample groupSample
	for pid, p := range procs {
		for current, seen := pid, 0; seen < len(procs); seen++ {
			if current == root {
				sample.ticks += p.stat.utime + p.stat.stime
				sample.rssBytes += p.stat.rssPages * page
				sample.fileBytes += p.share
				break
			}
			parent, ok := procs[current]
			if !ok || current <= 1 {
				break
			}
			current = parent.ppid
		}
	}
	return sample, nil
}

// readableBytes is allocatedBytes over trees the dev driver may not fully
// read (an envd guest's root user can make directories unreadable).
func readableBytes(roots ...string) uint64 {
	var total uint64
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if info, err := entry.Info(); err == nil {
				if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Blocks > 0 {
					total += uint64(stat.Blocks) * 512
				}
			}
			return nil
		})
	}
	return total
}
