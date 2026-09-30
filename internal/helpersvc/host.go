// Package helpersvc installs sandboxd-pf-helper as a launchd system service
// and updates it to a release that GitHub Actions built. Every command it
// runs, and every path it writes, goes through a Host so that the whole flow
// is testable off the Mac.
package helpersvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	// Label is the launchd job label of the helper service.
	Label = "org.gitmoot.sandboxd-pf-helper"
	// DefaultPinImage is the reviewed bridge pin image.
	DefaultPinImage     = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	DefaultWorkerID     = "mac-local"
	DefaultContainerCLI = "/usr/local/bin/container"
)

// Cred runs a command as the worker account, the way the helper runs the
// Apple container CLI: that account owns the container API server.
type Cred struct {
	UID, GID int
	Home     string
}

// Host is the Mac as seen by install and update.
type Host struct {
	GOOS   string
	EUID   func() int
	Getenv func(string) string
	// LookupUser returns the account's numeric UID and home directory.
	LookupUser func(name string) (uid, home string, err error)
	Executable func() (string, error)
	// Run runs an absolute-path command; a non-nil cred runs it as that user.
	Run   func(ctx context.Context, cred *Cred, name string, args ...string) ([]byte, error)
	Kill  func(pid int, sig syscall.Signal) error
	Lstat func(string) (fs.FileInfo, error)
	// RootUID owns every trusted path; Chown gives a written file to it.
	RootUID     int
	Chown       func(path string) error
	SocketReady func(path string) bool
	Sleep       func(time.Duration)

	HTTP         *http.Client
	ReleasesAPI  string
	DownloadBase string

	// TrustRoot is the top of every trusted-tree check: / on the Mac.
	TrustRoot     string
	Libexec       string
	Bin           string
	LaunchDaemons string
	Logs          string
	Socket        string

	Stdout io.Writer
}

// MacHost is the real Mac.
func MacHost(stdout io.Writer) *Host {
	return &Host{
		GOOS:   runtime.GOOS,
		EUID:   os.Geteuid,
		Getenv: os.Getenv,
		LookupUser: func(name string) (string, string, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return "", "", err
			}
			return u.Uid, u.HomeDir, nil
		},
		Executable:  os.Executable,
		Run:         runCommand,
		Kill:        syscall.Kill,
		Lstat:       os.Lstat,
		RootUID:     0,
		Chown:       func(path string) error { return os.Chown(path, 0, 0) },
		SocketReady: socketReady,
		Sleep:       time.Sleep,

		HTTP:         &http.Client{Timeout: 5 * time.Minute},
		ReleasesAPI:  "https://api.github.com/repos/gitmoot/sandboxd/releases",
		DownloadBase: "https://github.com/gitmoot/sandboxd/releases/download/",

		TrustRoot:     "/",
		Libexec:       "/usr/local/libexec",
		Bin:           "/usr/local/bin",
		LaunchDaemons: "/Library/LaunchDaemons",
		Logs:          "/Library/Logs",
		Socket:        "/private/var/run/sandboxd-pf/helper.sock",

		Stdout: stdout,
	}
}

func (h *Host) helperPath() string   { return filepath.Join(h.Libexec, "sandboxd-pf-helper") }
func (h *Host) sandboxdPath() string { return filepath.Join(h.Libexec, "sandboxd") }
func (h *Host) plistPath() string    { return filepath.Join(h.LaunchDaemons, Label+".plist") }
func (h *Host) logPath() string      { return filepath.Join(h.Logs, "sandboxd-pf-helper.log") }
func (h *Host) wrapperPath() string  { return filepath.Join(h.Bin, "sandboxd-helper-update") }

func runCommand(ctx context.Context, cred *Cred, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if cred != nil {
		cmd.Env = append(cmd.Env, "HOME="+cred.Home)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uint32(cred.UID), Gid: uint32(cred.GID),
		}}
	}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(exit.Stderr)))
		}
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

func socketReady(path string) bool {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (h *Host) requireRootOnMac(what string) error {
	if h.GOOS != "darwin" {
		return fmt.Errorf("%s manages the Mac helper service; run it on the Mac", what)
	}
	if h.EUID() != 0 {
		return fmt.Errorf("%s must run as root: use sudo", what)
	}
	return nil
}

func (h *Host) launchctl(ctx context.Context, args ...string) error {
	_, err := h.Run(ctx, nil, "/bin/launchctl", args...)
	return err
}

// waitSocket waits for the service to accept connections on socket.
func (h *Host) waitSocket(socket string) error {
	for range 60 {
		if h.SocketReady(socket) {
			return nil
		}
		h.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the helper did not open %s within 30s; see %s", socket, h.logPath())
}

// EnsureSocketDir creates the socket's parent directory if it is missing:
// macOS may empty /var/run at boot. The helper still refuses a directory
// that is not root-owned or is group/world writable.
func EnsureSocketDir(socket string) error {
	dir := filepath.Dir(socket)
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Mkdir(dir, 0o755)
}
