package helpersvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	testCLI  = "/usr/local/bin/container"
	testHash = "0ff237d70aef48830a10cd1ac4470a22531afb5d0e261a3c502ca4961b5799b6"
)

// fakeMac is a Mac in a temporary directory: its root-owned tree belongs to
// the test's user, and every command is answered from its fields.
type fakeMac struct {
	t    *testing.T
	root string
	host *Host
	out  bytes.Buffer

	env         map[string]string
	users       map[string][2]string // name -> uid, home
	networks    string               // container network list --format json
	inspect     map[string]string    // container network inspect <name>
	containers  string               // container list --all --format json
	pfRules     string
	procs       []string // ps -axww -o pid=,command= lines
	loaded      bool     // the launchd job
	stuckLoaded bool     // bootout succeeds but the job stays loaded
	socketUp    bool
	neverUp     bool
	calls       []string
	launchd     []string
	killed      []int
}

func newFakeMac(t *testing.T) *fakeMac {
	t.Helper()
	root := t.TempDir()
	m := &fakeMac{
		t: t, root: root,
		env:   map[string]string{"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "jerry"},
		users: map[string][2]string{"jerry": {"501", "/Users/jerry"}, "root": {"0", "/var/root"}},
		networks: `[
			{"id":"default","configuration":{"mode":"nat","labels":{}}},
			{"id":"sandboxd-slot-2","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}},
			{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}},
			{"id":"someone-else","configuration":{"mode":"hostOnly","labels":{}}}
		]`,
		inspect: map[string]string{
			"sandboxd-internal": inspectJSON("sandboxd-internal", "192.168.128.0/24", "192.168.128.1", "fd1e:68b8:2ef4:5d5a::/64"),
			"sandboxd-slot-2":   inspectJSON("sandboxd-slot-2", "192.168.130.0/24", "192.168.130.1", "fd5a:d4d:4046:6a21::/64"),
		},
		containers: `[]`,
		pfRules:    "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n",
	}
	for _, d := range []string{"usr/local/libexec", "usr/local/bin", "Library/LaunchDaemons", "Library/Logs", "var/run/sandboxd-pf", "release"} {
		for p := filepath.Join(root, d); p != root; p = filepath.Dir(p) {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	m.writeRelease("sandboxd-pf-helper", "helper v1")
	m.writeRelease("sandboxd", "sandboxd v1")
	m.host = &Host{
		GOOS:   "darwin",
		EUID:   func() int { return 0 },
		Getenv: func(k string) string { return m.env[k] },
		LookupUser: func(name string) (string, string, error) {
			u, ok := m.users[name]
			if !ok {
				return "", "", fmt.Errorf("no user %s", name)
			}
			return u[0], u[1], nil
		},
		Executable:  func() (string, error) { return filepath.Join(root, "release", "sandboxd-pf-helper"), nil },
		Run:         m.run,
		Kill:        m.kill,
		Lstat:       os.Lstat,
		RootUID:     os.Getuid(),
		Chown:       func(string) error { return nil },
		SocketReady: func(string) bool { return m.socketUp },
		Sleep:       func(time.Duration) {},

		HTTP:         &http.Client{Transport: failTransport{}},
		ReleasesAPI:  "http://github.invalid/api",
		DownloadBase: "http://github.invalid/download/",

		TrustRoot:     root,
		Libexec:       filepath.Join(root, "usr/local/libexec"),
		Bin:           filepath.Join(root, "usr/local/bin"),
		LaunchDaemons: filepath.Join(root, "Library/LaunchDaemons"),
		Logs:          filepath.Join(root, "Library/Logs"),
		Socket:        filepath.Join(root, "var/run/sandboxd-pf/helper.sock"),
		Stdout:        &m.out,
	}
	return m
}

// symlinkInfo is a root-owned 0755 symlink, as macOS can report one.
type symlinkInfo struct{ uid int }

func (symlinkInfo) Name() string       { return "bin" }
func (symlinkInfo) Size() int64        { return 0 }
func (symlinkInfo) Mode() fs.FileMode  { return fs.ModeSymlink | 0o755 }
func (symlinkInfo) ModTime() time.Time { return time.Time{} }
func (symlinkInfo) IsDir() bool        { return false }
func (s symlinkInfo) Sys() any         { return &syscall.Stat_t{Uid: uint32(s.uid)} }

type failTransport struct{}

func (failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected fetch of %s", r.URL)
}

func inspectJSON(name, ipv4, gw, ipv6 string) string {
	return fmt.Sprintf(`[{"configuration":{"name":%q,"mode":"hostOnly","plugin":"container-network-vmnet","labels":{"gitmoot.sandboxd.network":"apple-v1"}},"status":{"ipv4Subnet":%q,"ipv4Gateway":%q,"ipv6Subnet":%q}}]`, name, ipv4, gw, ipv6)
}

func (m *fakeMac) writeRelease(name, body string) {
	m.t.Helper()
	path := filepath.Join(m.root, "release", name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		m.t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		m.t.Fatal(err)
	}
}

func (m *fakeMac) run(_ context.Context, cred *Cred, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	if cred != nil {
		call = fmt.Sprintf("as %d:%d %s: %s", cred.UID, cred.GID, cred.Home, call)
	}
	m.calls = append(m.calls, call)
	switch name {
	case testCLI:
		if cred == nil || cred.UID != 501 || cred.GID != 20 || cred.Home != "/Users/jerry" {
			return nil, fmt.Errorf("container CLI run as %+v, not the worker", cred)
		}
		switch {
		case call == "as 501:20 /Users/jerry: "+testCLI+" network list --format json":
			return []byte(m.networks), nil
		case len(args) == 3 && args[0] == "network" && args[1] == "inspect":
			if s, ok := m.inspect[args[2]]; ok {
				return []byte(s), nil
			}
			return nil, fmt.Errorf("no network %s", args[2])
		case strings.Join(args, " ") == "list --all --format json":
			if m.containers == "" {
				return nil, errors.New("container API server is not running")
			}
			return []byte(m.containers), nil
		}
	case "/sbin/pfctl":
		if cred == nil && strings.Join(args, " ") == "-sr" {
			return []byte(m.pfRules), nil
		}
	case "/bin/ps":
		if cred == nil && strings.Join(args, " ") == "-axww -o pid=,command=" {
			return []byte(strings.Join(m.procs, "\n") + "\n"), nil
		}
	case "/bin/launchctl":
		if cred != nil {
			break
		}
		m.launchd = append(m.launchd, strings.Join(args, " "))
		target := "system/" + Label
		switch {
		case len(args) == 2 && args[0] == "print" && args[1] == target:
			if !m.loaded {
				return nil, errors.New("Could not find service")
			}
			return nil, nil
		case len(args) == 2 && args[0] == "bootout" && args[1] == target && m.loaded:
			m.loaded, m.socketUp = m.stuckLoaded, false
			return nil, nil
		case len(args) == 3 && args[0] == "bootstrap" && args[1] == "system" && args[2] == m.host.plistPath() && !m.loaded:
			m.loaded, m.socketUp = true, !m.neverUp
			return nil, nil
		case len(args) == 3 && args[0] == "kickstart" && args[1] == "-k" && args[2] == target && m.loaded:
			m.socketUp = !m.neverUp
			return nil, nil
		}
		return nil, fmt.Errorf("launchctl %v refused", args)
	}
	return nil, fmt.Errorf("unexpected command %q", call)
}

func (m *fakeMac) kill(pid int, sig syscall.Signal) error {
	if sig != syscall.SIGTERM {
		return fmt.Errorf("signal %v", sig)
	}
	m.killed = append(m.killed, pid)
	prefix := fmt.Sprint(pid) + " "
	kept := m.procs[:0]
	for _, p := range m.procs {
		if !strings.HasPrefix(strings.TrimSpace(p), prefix) {
			kept = append(kept, p)
		}
	}
	m.procs = kept
	return nil
}

func (m *fakeMac) path(rel string) string { return filepath.Join(m.root, rel) }

func (m *fakeMac) read(rel string) string {
	m.t.Helper()
	b, err := os.ReadFile(m.path(rel))
	if err != nil {
		m.t.Fatal(err)
	}
	return string(b)
}

func (m *fakeMac) install(opts InstallOptions) error {
	if opts.WorkerID == "" {
		opts.WorkerID = DefaultWorkerID
	}
	if opts.PinImage == "" {
		opts.PinImage = DefaultPinImage
	}
	if opts.ContainerCLI == "" {
		opts.ContainerCLI = testCLI
	}
	return m.host.Install(context.Background(), opts, "v0.6.0")
}
