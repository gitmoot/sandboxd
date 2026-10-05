// Command sandboxd-guest-agent is PID 1 of a Firecracker guest. As init it
// mounts the guest's private filesystems, formats the per-VM writable home
// disk, and supervises the vsock server, which runs commands and file writes
// as the guest user (uid/gid 1000). It never listens on the guest network.
//
// An e2b guest (kernel argument sandboxd.envd=1) instead gets a writable
// overlay root on the per-VM disk and runs upstream envd as root; the vsock
// server then also bridges host connections to TCP ports on the guest
// loopback (envd, and the ports its template exposes; sandboxd chooses).
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

const (
	guestUID = 1000
	guestGID = 1000
	homeDir  = "/home/user"
	homeDisk = "/dev/vdb"
	envFile  = "/etc/sandboxd/env"
	// envdKernelArg marks an e2b guest (vm.Spec.Envd): a writable overlay
	// root on the per-VM disk and upstream envd as its service.
	envdKernelArg = "sandboxd.envd=1"
	envdPath      = "/usr/bin/envd"
	// stateDir is where an e2b guest mounts its disk before pivot_root; it
	// exists in every Debian-based image.
	stateDir = "/mnt"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("sandboxd-agent: ")
	switch {
	case len(os.Args) == 3 && os.Args[1] == "write":
		if err := guestagent.RunWriteHelper(os.Args[2], os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case len(os.Args) == 2 && (os.Args[1] == "serve" || os.Args[1] == "serve-envd"):
		if err := serve(os.Args[1] == "serve-envd"); err != nil {
			log.Fatal(err)
		}
	case os.Getpid() == 1:
		initGuest()
	default:
		log.Fatal("must run as PID 1, or with 'serve', 'serve-envd' or 'write <path>'")
	}
}

// halt resets the VM; Firecracker exits on guest reset, and sandboxd then
// sees a stopped VM and destroys it.
func halt(format string, args ...any) {
	log.Printf(format, args...)
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}

type mount struct {
	source, target, fstype string
	flags                  uintptr
	data                   string
	mode                   os.FileMode
}

func initGuest() {
	const nosuid = unix.MS_NOSUID | unix.MS_NODEV
	// /proc first: the kernel command line says which guest this is.
	if err := unix.Mount("proc", "/proc", "proc", nosuid|unix.MS_NOEXEC, ""); err != nil {
		halt("mount /proc: %v", err)
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		halt("read /proc/cmdline: %v", err)
	}
	envd := slices.Contains(strings.Fields(string(cmdline)), envdKernelArg)
	if envd {
		if err := unix.Unmount("/proc", 0); err != nil {
			halt("unmount /proc: %v", err)
		}
		writableRoot()
		if err := unix.Mount("proc", "/proc", "proc", nosuid|unix.MS_NOEXEC, ""); err != nil {
			halt("mount /proc: %v", err)
		}
	}
	mounts := []mount{
		{"sysfs", "/sys", "sysfs", nosuid | unix.MS_NOEXEC | unix.MS_RDONLY, "", 0o555},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID | unix.MS_NOEXEC, "mode=0755", 0o755},
		{"devpts", "/dev/pts", "devpts", unix.MS_NOSUID | unix.MS_NOEXEC, "newinstance,gid=5,mode=0620,ptmxmode=0666", 0o755},
		{"tmpfs", "/dev/shm", "tmpfs", nosuid, "mode=1777,size=64m", 0o1777},
		{"tmpfs", "/run", "tmpfs", nosuid, "mode=0755,size=32m", 0o755},
	}
	if !envd {
		// The strict guest's root is read-only; an e2b guest keeps /tmp on
		// its writable root, as E2B does.
		mounts = append(mounts,
			mount{"tmpfs", "/tmp", "tmpfs", nosuid, "mode=1777,size=512m", 0o1777},
			mount{"tmpfs", "/var/tmp", "tmpfs", nosuid, "mode=1777,size=256m", 0o1777})
	}
	for _, m := range mounts {
		if err := os.MkdirAll(m.target, m.mode); err != nil && !errors.Is(err, unix.EROFS) {
			halt("mkdir %s: %v", m.target, err)
		}
		if err := unix.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			// The kernel mounts devtmpfs on /dev itself (DEVTMPFS_MOUNT).
			if m.target == "/dev" && errors.Is(err, unix.EBUSY) {
				continue
			}
			halt("mount %s: %v", m.target, err)
		}
	}
	_ = os.Remove("/dev/ptmx")
	if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
		halt("ptmx: %v", err)
	}
	if !envd {
		// The writable home disk is fresh for every VM; its root belongs to
		// the guest user, like the Apple driver's private volume.
		formatDisk("root_owner=1000:1000,lazy_itable_init=1", "home")
		if err := unix.Mount(homeDisk, homeDir, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			halt("mount home disk: %v", err)
		}
		if err := os.Chmod(homeDir, 0o755); err != nil {
			halt("chmod home: %v", err)
		}
	}
	_ = unix.Sethostname([]byte("sandbox"))
	if err := loopbackUp(); err != nil {
		halt("loopback: %v", err)
	}
	// PID 1 only reaps; commands are children of the server process so their
	// own waits never race this loop.
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, unix.SIGCHLD)
	mode := "serve"
	if envd {
		mode = "serve-envd"
	}
	server := exec.Command("/proc/self/exe", mode)
	server.Stdout, server.Stderr = os.Stdout, os.Stderr
	server.Env = []string{}
	if err := server.Start(); err != nil {
		halt("start server: %v", err)
	}
	serverPID, envdPID := server.Process.Pid, 0
	if envd {
		envdPID = startEnvd()
	}
	for range signals {
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
			switch pid {
			case serverPID:
				halt("server exited: %v", status)
			case envdPID:
				// Without envd the sandbox is unusable; end the VM so the
				// host sees it stopped and destroys it.
				halt("envd exited: %v", status)
			}
		}
	}
}

func formatDisk(extended, label string) {
	mkfs := exec.Command("/sbin/mkfs.ext4", "-q", "-F", "-m", "0", "-E", extended, "-L", label, homeDisk)
	mkfs.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if out, err := mkfs.CombinedOutput(); err != nil {
		halt("format %s disk: %v: %s", label, err, out)
	}
}

// writableRoot gives an e2b guest the writable root E2B provides: an overlay
// of the read-only image (lower) and the fresh per-VM disk (upper), which
// becomes / by pivot_root. The image itself is never written, and the old
// root is detached, so nothing else of the boot environment stays reachable.
func writableRoot() {
	formatDisk("root_owner=0:0,lazy_itable_init=1", "state")
	if err := unix.Mount(homeDisk, stateDir, "ext4", unix.MS_NODEV, ""); err != nil {
		halt("mount state disk: %v", err)
	}
	for _, dir := range []string{"upper", "work", "root"} {
		if err := os.Mkdir(stateDir+"/"+dir, 0o755); err != nil {
			halt("mkdir state %s: %v", dir, err)
		}
	}
	options := "lowerdir=/,upperdir=" + stateDir + "/upper,workdir=" + stateDir + "/work"
	if err := unix.Mount("overlay", stateDir+"/root", "overlay", 0, options); err != nil {
		halt("mount overlay root: %v", err)
	}
	if err := unix.Chdir(stateDir + "/root"); err != nil {
		halt("chdir new root: %v", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		halt("pivot_root: %v", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		halt("detach old root: %v", err)
	}
	if err := unix.Chdir("/"); err != nil {
		halt("chdir /: %v", err)
	}
}

// startEnvd starts upstream envd as root, on the guest loopback only being
// reachable from the host: the agent bridges vsock to it. The guest network
// is outbound-only (the host never routes to it), so envd's wildcard listener
// is reachable from inside the guest alone.
func startEnvd() int {
	env, err := readEnv()
	if err != nil {
		halt("envd environment: %v", err)
	}
	cmd := exec.Command(envdPath, "-isnotfc", "-no-cgroups", "-port", strconv.Itoa(guestagent.EnvdPort))
	// envd takes PATH from its own environment for every process it starts.
	cmd.Env = []string{"PATH=" + lookupEnv(env, "PATH"), "HOME=/root", "LANG=" + lookupEnv(env, "LANG")}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		halt("start envd: %v", err)
	}
	return cmd.Process.Pid
}

func lookupEnv(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if key, v, ok := strings.Cut(entry, "="); ok && key == name {
			value = v
		}
	}
	return value
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

// readEnv loads the image's base environment (KEY=VALUE lines).
func readEnv() ([]string, error) {
	file, err := os.Open(envFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var env []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			return nil, fmt.Errorf("malformed %s line %q", envFile, line)
		}
		env = append(env, line)
	}
	return env, scanner.Err()
}

func serve(envd bool) error {
	env, err := readEnv()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	server := &guestagent.Server{
		Env:         env,
		Dir:         homeDir,
		Credential:  &syscall.Credential{Uid: guestUID, Gid: guestGID, Groups: []uint32{}},
		WriteHelper: []string{self, "write"},
		WaitDelay:   2 * time.Second,
		DiskPath:    homeDir,
	}
	if envd {
		server.DialHost = "127.0.0.1"
		server.DiskPath = "/"
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: guestagent.Port}); err != nil {
		return err
	}
	if err := unix.Listen(fd, 64); err != nil {
		return err
	}
	for {
		conn, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNABORTED) {
				continue
			}
			return err
		}
		go server.ServeConn(os.NewFile(uintptr(conn), "vsock"))
	}
}
