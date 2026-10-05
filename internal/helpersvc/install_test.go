package helpersvc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func (m *fakeMac) wantArgs(hash string) []string {
	return []string{
		m.path("usr/local/libexec/sandboxd-pf-helper"), "run",
		"--socket", m.path("var/run/sandboxd-pf/helper.sock"),
		"--worker-uid", "501",
		"--worker-gid", "20",
		"--worker-home", "/Users/jerry",
		"--worker-id", "mac-local",
		"--container-cli", "/usr/local/bin/container",
		"--slot", "name=sandboxd-internal,ipv4=192.168.128.0/24,gw=192.168.128.1,ipv6=fd1e:68b8:2ef4:5d5a::/64",
		"--slot", "name=sandboxd-slot-2,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd5a:d4d:4046:6a21::/64",
		"--pin-image", DefaultPinImage,
		"--main-rules-sha256", hash,
		"--model-relay-port", "0",
	}
}

func TestInstallWritesTheLaunchdJobWithEveryResolvedFlag(t *testing.T) {
	m := newFakeMac(t)
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatalf("install: %v\n%s", err, m.out.String())
	}
	data := m.read("Library/LaunchDaemons/" + Label + ".plist")
	plist, err := parsePlist([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(m.pfRules)))
	log := m.path("Library/Logs/sandboxd-pf-helper.log")
	want := map[string]any{
		"Label":             Label,
		"ProgramArguments":  m.wantArgs(hash),
		"RunAtLoad":         true,
		"KeepAlive":         true,
		"StandardOutPath":   log,
		"StandardErrorPath": log,
	}
	if !reflect.DeepEqual(plist, want) {
		t.Fatalf("plist\n got %#v\nwant %#v", plist, want)
	}
	if info, _ := os.Stat(m.path("Library/LaunchDaemons/" + Label + ".plist")); info.Mode().Perm() != 0o644 {
		t.Fatalf("plist mode %v, want 0644", info.Mode())
	}
	for rel, body := range map[string]string{"usr/local/libexec/sandboxd-pf-helper": "helper v1", "usr/local/libexec/sandboxd": "sandboxd v1"} {
		if got := m.read(rel); got != body {
			t.Fatalf("%s = %q, want %q", rel, got, body)
		}
		if info, _ := os.Stat(m.path(rel)); info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode %v, want 0755", rel, info.Mode())
		}
	}
	for _, s := range []string{"v0.6.0", hash, "--slot name=sandboxd-internal,", "--slot name=sandboxd-slot-2,", "sudo sandboxd-helper-update"} {
		if !strings.Contains(m.out.String(), s) {
			t.Fatalf("summary lacks %q:\n%s", s, m.out.String())
		}
	}
}

// The owner enables the relay by rerunning install from the installed helper
// (after sandboxd-helper-update): it installs itself onto its own path.
func TestInstallFromTheInstalledHelperReplacesItSafely(t *testing.T) {
	m := newFakeMac(t)
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatalf("install: %v\n%s", err, m.out.String())
	}
	m.host.Executable = func() (string, error) { return m.host.helperPath(), nil }
	// Rewriting a running Mac binary in place can kill it; install must
	// replace the path with a new file instead.
	before := map[string]fs.FileInfo{}
	var err error
	for _, rel := range []string{"usr/local/libexec/sandboxd-pf-helper", "usr/local/libexec/sandboxd"} {
		if before[rel], err = os.Stat(m.path(rel)); err != nil {
			t.Fatal(err)
		}
	}
	m.out.Reset()
	if err := m.install(InstallOptions{ModelRelayPort: 43181}); err != nil {
		t.Fatalf("install from the installed path: %v\n%s", err, m.out.String())
	}
	for rel, body := range map[string]string{"usr/local/libexec/sandboxd-pf-helper": "helper v1", "usr/local/libexec/sandboxd": "sandboxd v1"} {
		after, err := os.Stat(m.path(rel))
		if err != nil || m.read(rel) != body || after.Mode().Perm() != 0o755 {
			t.Fatalf("%s = %q (%v), want %q mode 0755", rel, m.read(rel), err, body)
		}
		if os.SameFile(before[rel], after) {
			t.Fatalf("%s was rewritten in place under the running helper", rel)
		}
	}
	plist, err := parsePlist([]byte(m.read("Library/LaunchDaemons/" + Label + ".plist")))
	if err != nil {
		t.Fatal(err)
	}
	want := m.wantArgs(fmt.Sprintf("%x", sha256.Sum256([]byte(m.pfRules))))
	want[len(want)-1] = "43181"
	if !reflect.DeepEqual(plist["ProgramArguments"], want) {
		t.Fatalf("relay job args\n got %#v\nwant %#v", plist["ProgramArguments"], want)
	}
}

func TestInstallRefusesSettingsTheHelperWouldRefuse(t *testing.T) {
	for name, opts := range map[string]InstallOptions{
		"tag instead of digest": {PinImage: "docker.io/library/alpine:latest"},
		"short rules hash":      {MainRulesSHA256: "0ff237d7"},
		"bad worker id":         {WorkerID: "Mac Local"},
		"relative container":    {ContainerCLI: "container"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			if opts.ContainerCLI != "" {
				// Discovery must still find the slots.
				m.host.Run = func(ctx context.Context, cred *Cred, cmd string, args ...string) ([]byte, error) {
					if cmd == opts.ContainerCLI {
						cmd = testCLI
					}
					return m.run(ctx, cred, cmd, args...)
				}
			}
			if err := m.install(opts); err == nil {
				t.Fatal("installed")
			}
			m.nothingInstalled()
		})
	}
}

func TestInstallUsesTheGivenMainRulesHashAndSettings(t *testing.T) {
	m := newFakeMac(t)
	err := m.install(InstallOptions{MainRulesSHA256: testHash, WorkerID: "mac-2", ModelRelayPort: 8443,
		PinImage:  "example/pin@sha256:" + strings.Repeat("a", 64),
		DenyCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, EgressInterface: "en1"})
	if err != nil {
		t.Fatal(err)
	}
	args, err := programArguments([]byte(m.read("Library/LaunchDaemons/" + Label + ".plist")))
	if err != nil {
		t.Fatal(err)
	}
	for flag, want := range map[string]string{"--main-rules-sha256": testHash, "--worker-id": "mac-2", "--model-relay-port": "8443",
		"--pin-image": "example/pin@sha256:" + strings.Repeat("a", 64), "--deny-cidr": "203.0.113.0/24", "--egress-interface": "en1"} {
		if got, err := flagValue(args, flag); err != nil || got != want {
			t.Fatalf("%s = %q (%v), want %q", flag, got, err, want)
		}
	}
	for _, c := range m.calls {
		if strings.HasPrefix(c, "/sbin/pfctl") {
			t.Fatalf("pfctl ran although the hash was given: %v", m.calls)
		}
	}
}

func TestInstallDiscoversOnlyLabelledHostOnlyNetworks(t *testing.T) {
	m := newFakeMac(t)
	// A labelled network in another mode is not a slot, even if inspect
	// would describe a valid one.
	m.networks = strings.Replace(m.networks, `]`, `,{"id":"sandboxd-nat","configuration":{"mode":"nat","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]`, 1)
	m.inspect["sandboxd-nat"] = inspectJSON("sandboxd-nat", "192.168.140.0/24", "192.168.140.1", "fd00:1::/64")
	slots, err := m.host.discoverSlots(t.Context(), Cred{UID: 501, GID: 20, Home: "/Users/jerry"}, testCLI)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range slots {
		got = append(got, s.String())
	}
	want := []string{
		"name=sandboxd-internal,ipv4=192.168.128.0/24,gw=192.168.128.1,ipv6=fd1e:68b8:2ef4:5d5a::/64",
		"name=sandboxd-slot-2,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd5a:d4d:4046:6a21::/64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("slots %v, want %v", got, want)
	}
}

func TestInstallRefusesWithoutValidSlots(t *testing.T) {
	for name, change := range map[string]func(m *fakeMac){
		"none labelled": func(m *fakeMac) {
			m.networks = `[{"id":"default","configuration":{"mode":"nat","labels":{}}}]`
		},
		"no network list": func(m *fakeMac) { m.networks = `null` },
		// container 1.4.1 with --subnet-v6 reports a host address.
		"IPv6 host address": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = inspectJSON("sandboxd-slot-2", "192.168.130.0/24", "192.168.130.1", "fd5a:d4d:4046:6a21::1/64")
		},
		"gateway outside subnet": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = inspectJSON("sandboxd-slot-2", "192.168.130.0/24", "192.168.131.1", "fd5a:d4d:4046:6a21::/64")
		},
		"overlapping subnets": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = inspectJSON("sandboxd-slot-2", "192.168.128.0/24", "192.168.128.1", "fd5a:d4d:4046:6a21::/64")
		},
		"inspect disagrees on the label": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = strings.Replace(m.inspect["sandboxd-slot-2"], `"apple-v1"`, `"other"`, 1)
		},
		"inspect disagrees on the mode": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = strings.Replace(m.inspect["sandboxd-slot-2"], `"hostOnly"`, `"nat"`, 1)
		},
		"inspect is of another network": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = inspectJSON("sandboxd-slot-3", "192.168.130.0/24", "192.168.130.1", "fd5a:d4d:4046:6a21::/64")
		},
		"inspect disagrees on the plugin": func(m *fakeMac) {
			m.inspect["sandboxd-slot-2"] = strings.Replace(m.inspect["sandboxd-slot-2"], `"container-network-vmnet"`, `"other"`, 1)
		},
		"inspect returns two networks": func(m *fakeMac) {
			one := strings.TrimSuffix(strings.TrimPrefix(m.inspect["sandboxd-slot-2"], "["), "]")
			m.inspect["sandboxd-slot-2"] = "[" + one + "," + one + "]"
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			change(m)
			err := m.install(InstallOptions{})
			if err == nil {
				t.Fatalf("installed:\n%s", m.out.String())
			}
			switch name {
			case "none labelled":
				if !strings.Contains(err.Error(), "create the slot networks first") {
					t.Fatalf("no slots, but the error does not say to create them: %v", err)
				}
			case "no network list":
			default:
				// The operator learns which network to fix.
				if !strings.Contains(err.Error(), `sandboxd-slot-2`) {
					t.Fatalf("the error does not name the network: %v", err)
				}
			}
			m.nothingInstalled()
		})
	}
}

func (m *fakeMac) nothingInstalled() {
	m.t.Helper()
	for _, rel := range []string{"usr/local/libexec/sandboxd-pf-helper", "Library/LaunchDaemons/" + Label + ".plist", "usr/local/bin/sandboxd-helper-update"} {
		if _, err := os.Lstat(m.path(rel)); !os.IsNotExist(err) {
			m.t.Fatalf("%s was written (%v)", rel, err)
		}
	}
	if len(m.launchd) != 0 || len(m.killed) != 0 {
		m.t.Fatalf("launchctl %v, killed %v", m.launchd, m.killed)
	}
}

func TestInstallTakesTheWorkerFromSudo(t *testing.T) {
	const missing, root = "SUDO_UID, SUDO_GID and SUDO_USER", "refusing root"
	for name, tc := range map[string]struct {
		env  map[string]string
		home string
		want string
	}{
		"not through sudo": {env: map[string]string{}, want: missing},
		"sudo from root":   {env: map[string]string{"SUDO_UID": "0", "SUDO_GID": "0", "SUDO_USER": "root"}, want: root},
		"root uid":         {env: map[string]string{"SUDO_UID": "0", "SUDO_GID": "20", "SUDO_USER": "jerry"}, want: root},
		"no user":          {env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}, want: missing},
		"no gid":           {env: map[string]string{"SUDO_UID": "501", "SUDO_USER": "jerry"}, want: missing},
		"negative uid":     {env: map[string]string{"SUDO_UID": "-2", "SUDO_GID": "20", "SUDO_USER": "jerry"}, want: missing},
		"negative gid":     {env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "-1", "SUDO_USER": "jerry"}, want: missing},
		"uid not the user": {env: map[string]string{"SUDO_UID": "502", "SUDO_GID": "20", "SUDO_USER": "jerry"}, want: "has uid 501"},
		"unknown user":     {env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "nobody-here"}, want: "look up"},
		"relative home":    {home: "Users/jerry", want: "clean absolute"},
		"unclean home":     {home: "/Users/../var/root", want: "clean absolute"},
		"clean home":       {home: "/Users/jerry"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			if tc.env != nil {
				m.env = tc.env
			}
			if tc.home != "" {
				m.users["jerry"] = [2]string{"501", tc.home}
			}
			err := m.install(InstallOptions{})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("worker %v: %v, want %q", tc.env, err, tc.want)
			}
			// Nothing, above all not the container CLI, runs as a worker
			// that is not settled.
			if len(m.calls) != 0 {
				t.Fatalf("ran %q", m.calls)
			}
			m.nothingInstalled()
		})
	}
}

func TestInstallNeedsRootOnTheMac(t *testing.T) {
	m := newFakeMac(t)
	m.host.EUID = func() int { return 501 }
	if err := m.install(InstallOptions{}); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("non-root install: %v", err)
	}
	m.host.EUID = func() int { return 0 }
	m.host.GOOS = "linux"
	if err := m.install(InstallOptions{}); err == nil {
		t.Fatal("installed off the Mac")
	}
	m.nothingInstalled()
}

func TestInstallRefusesBinariesOthersCouldHaveChanged(t *testing.T) {
	for name, change := range map[string]func(m *fakeMac){
		"release dir group-writable": func(m *fakeMac) { os.Chmod(m.path("release"), 0o775) },
		"ancestor world-writable":    func(m *fakeMac) { os.Chmod(m.root, 0o777) },
		"helper group-writable":      func(m *fakeMac) { os.Chmod(m.path("release/sandboxd-pf-helper"), 0o775) },
		"sandboxd world-writable":    func(m *fakeMac) { os.Chmod(m.path("release/sandboxd"), 0o757) },
		"sandboxd symlink": func(m *fakeMac) {
			os.Remove(m.path("release/sandboxd"))
			os.Symlink("/bin/sh", m.path("release/sandboxd"))
		},
		"libexec group-writable": func(m *fakeMac) { os.Chmod(m.path("usr/local/libexec"), 0o775) },
		"helper outside the trusted root": func(m *fakeMac) {
			m.host.Executable = func() (string, error) { return "/bin/sh", nil }
		},
		"files not owned by root": func(m *fakeMac) { m.host.RootUID = os.Getuid() + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			change(m)
			if err := m.install(InstallOptions{}); err == nil {
				t.Fatal("installed")
			}
			m.nothingInstalled()
		})
	}
}

func TestInstallWithoutSandboxdInstallsTheHelperOnly(t *testing.T) {
	m := newFakeMac(t)
	os.Remove(m.path("release/sandboxd"))
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(m.path("usr/local/libexec/sandboxd")); !os.IsNotExist(err) {
		t.Fatalf("sandboxd appeared: %v", err)
	}
}

func TestInstallWritesTheUpdateCommandOnlyWhereRootAloneWrites(t *testing.T) {
	wrapper := "usr/local/bin/sandboxd-helper-update"
	m := newFakeMac(t)
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	want := "#!/bin/sh\nexec " + m.path("usr/local/libexec/sandboxd-pf-helper") + " update \"$@\"\n"
	if got := m.read(wrapper); got != want {
		t.Fatalf("wrapper %q, want %q", got, want)
	}
	if info, _ := os.Stat(m.path(wrapper)); info.Mode().Perm() != 0o755 {
		t.Fatalf("wrapper mode %v", info.Mode())
	}

	for name, change := range map[string]func(m *fakeMac){
		"bin group-writable": func(m *fakeMac) { os.Chmod(m.path("usr/local/bin"), 0o775) },
		"usr world-writable": func(m *fakeMac) { os.Chmod(m.path("usr"), 0o777) },
		// Linux symlinks are 0777; a macOS one can be 0755 and root-owned,
		// so the type check alone must refuse it.
		"bin is a root-only symlink": func(m *fakeMac) {
			bin := m.path("usr/local/bin")
			m.host.Lstat = func(p string) (fs.FileInfo, error) {
				if p == bin {
					return symlinkInfo{uid: m.host.RootUID}, nil
				}
				return os.Lstat(p)
			}
		},
		"bin is a symlink": func(m *fakeMac) {
			os.Remove(m.path("usr/local/bin"))
			os.Mkdir(m.path("homebrew-bin"), 0o755)
			os.Symlink(m.path("homebrew-bin"), m.path("usr/local/bin"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			if name == "usr world-writable" {
				// libexec shares the ancestor: keep it trusted via its own tree.
				m.host.Libexec = m.path("libexec")
				os.Mkdir(m.host.Libexec, 0o755)
				os.Chmod(m.host.Libexec, 0o755)
			}
			change(m)
			if err := m.install(InstallOptions{}); err != nil {
				t.Fatal(err)
			}
			if entries, _ := os.ReadDir(m.path("homebrew-bin")); len(entries) != 0 {
				t.Fatalf("wrote through the symlink: %v", entries)
			}
			if fileExists(m.path("homebrew-bin/sandboxd-helper-update")) || name != "bin is a symlink" && fileExists(m.path(wrapper)) {
				t.Fatal("wrapper written on an untrusted path")
			}
			if !strings.Contains(m.out.String(), "is not root-only") {
				t.Fatalf("no note about the untrusted bin:\n%s", m.out.String())
			}
		})
	}
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestInstallStopsHandStartedHelpersAndReplacesTheJob(t *testing.T) {
	m := newFakeMac(t)
	legacy := m.path("usr/local/libexec/sandboxd-pf-helper-608a930")
	m.procs = []string{
		"  1 /sbin/launchd",
		"4242 " + legacy + " --socket /private/var/run/sandboxd-pf/helper.sock --worker-uid 501",
		"4243 sudo " + legacy + " --socket /private/var/run/sandboxd-pf/helper.sock",
		"4244 " + legacy + "0 --socket x",
		"4245 " + m.path("usr/local/libexec/sandboxd-pf-helper") + " run --socket x",
		"4246 /usr/bin/less " + legacy,
		"4247 /elsewhere" + legacy + " --socket x",
		// Started from another directory or as ./: still a hand-started
		// helper holding the socket (review P3).
		"4248 ./sandboxd-pf-helper-4ae1ed5 --socket x",
		"4249 /tmp/sandboxd-pf-helper-c423255 --socket x",
	}
	m.loaded = true
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatalf("%v\n%s", err, m.out.String())
	}
	if !reflect.DeepEqual(m.killed, []int{4242, 4247, 4248, 4249}) {
		t.Fatalf("killed %v, want every hand-started helper however its path is spelled", m.killed)
	}
	wantLaunchd := []string{
		"print system/" + Label,
		"bootout system/" + Label,
		"print system/" + Label,
		"bootstrap system " + m.host.plistPath(),
	}
	if !reflect.DeepEqual(m.launchd, wantLaunchd) {
		t.Fatalf("launchctl\n got %q\nwant %q", m.launchd, wantLaunchd)
	}

	fresh := newFakeMac(t)
	if err := fresh.install(InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"print system/" + Label, "bootstrap system " + fresh.host.plistPath()}; !reflect.DeepEqual(fresh.launchd, want) {
		t.Fatalf("first install launchctl %q, want %q", fresh.launchd, want)
	}
}

func TestInstallRefusesWhileAHandStartedHelperKeepsRunning(t *testing.T) {
	m := newFakeMac(t)
	m.procs = []string{"4242 " + m.path("usr/local/libexec/sandboxd-pf-helper-608a930") + " --socket x"}
	m.host.Kill = func(pid int, _ syscall.Signal) error { m.killed = append(m.killed, pid); return nil }
	if err := m.install(InstallOptions{}); err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("installed beside a running legacy helper: %v", err)
	}
	if fileExists(m.host.plistPath()) || len(m.launchd) != 0 {
		t.Fatalf("service installed beside a running legacy helper: launchctl %q", m.launchd)
	}
}

func TestInstallFailsWhenTheHelperNeverOpensItsSocket(t *testing.T) {
	m := newFakeMac(t)
	m.neverUp = true
	err := m.install(InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "sandboxd-pf-helper.log") {
		t.Fatalf("install with a dead helper: %v", err)
	}
}

func TestInstallRefusesAnUnreadableProcessList(t *testing.T) {
	for _, line := range []string{"x /usr/local/libexec/sandboxd-pf-helper-608a930", "1 /usr/local/libexec/sandboxd-pf-helper-608a930"} {
		m := newFakeMac(t)
		m.procs = []string{strings.Replace(line, "/usr/local/libexec", m.host.Libexec, 1)}
		if err := m.install(InstallOptions{}); err == nil {
			t.Fatalf("installed with process line %q", line)
		}
		m.nothingInstalled()
	}
}

func TestInstallRefusesWhenTheOldJobWillNotUnload(t *testing.T) {
	m := newFakeMac(t)
	m.loaded, m.stuckLoaded = true, true
	if err := m.install(InstallOptions{}); err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("bootstrapped over a loaded job: %v", err)
	}
	for _, c := range m.launchd {
		if strings.HasPrefix(c, "bootstrap") {
			t.Fatalf("launchctl %q", m.launchd)
		}
	}
}

func TestInstalledServiceRefusesAMalformedJob(t *testing.T) {
	good := []string{"/h", "run", "--socket", "/s", "--worker-uid", "501", "--worker-gid", "20", "--worker-home", "/Users/jerry", "--container-cli", "/c"}
	// Each case breaks a good job in exactly one way.
	job := string(renderPlist(good, "/l"))
	broken := func(old, new string) string {
		if !strings.Contains(job, old) {
			t.Fatalf("job lacks %q", old)
		}
		return strings.Replace(job, old, new, 1)
	}
	for name, data := range map[string]string{
		"not a plist":          strings.NewReplacer(`<plist version="1.0">`, "<array>", "</plist>", "</array>").Replace(job),
		"two dicts":            broken("</dict>", "</dict><dict/>"),
		"top level not a dict": strings.NewReplacer("<dict>", "<array>", "</dict>", "</array>").Replace(job),
		"unpaired key":         broken("</dict>", "<key>Extra</key></dict>"),
		"value where a key":    broken("<dict>", "<dict><string>a</string><string>b</string>"),
		"duplicate key":        broken("</dict>", "<key>RunAtLoad</key><false/></dict>"),
		"unknown value type":   broken("</dict>", "<key>Nice</key><integer>1</integer></dict>"),
		"array of non-strings": broken("<string>run</string>", "<string>run</string><integer>1</integer><integer>2</integer>"),
		"not a run command":    broken("<string>run</string>", "<string>update</string>"),
		"odd arguments":        string(renderPlist(append(append([]string{}, good...), "--x"), "/l")),
		"flag twice":           string(renderPlist(append(append([]string{}, good...), "--socket", "/t"), "/l")),
		"flag missing":         string(renderPlist(good[:len(good)-2], "/l")),
		"uid not a number":     string(renderPlist(append(append([]string{}, good[:5]...), append([]string{"x"}, good[6:]...)...), "/l")),
	} {
		t.Run(name, func(t *testing.T) {
			m := newFakeMac(t)
			if err := os.WriteFile(m.host.plistPath(), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			if s, err := m.host.installedService(); err == nil {
				t.Fatalf("read %+v", s)
			}
		})
	}
	m := newFakeMac(t)
	os.WriteFile(m.host.plistPath(), renderPlist(good, "/l"), 0o644)
	s, err := m.host.installedService()
	if want := (installedService{worker: Cred{UID: 501, GID: 20, Home: "/Users/jerry"}, cli: "/c", socket: "/s"}); err != nil || s != want {
		t.Fatalf("installedService = %+v, %v; want %+v", s, err, want)
	}
}

func TestPlistEscapesItsStrings(t *testing.T) {
	args := []string{"/a b/helper", "run", "--worker-home", "/Users/<&\">"}
	got, err := programArguments(renderPlist(args, filepath.Join("/tmp", "x&y.log")))
	if err != nil || !reflect.DeepEqual(got, args) {
		t.Fatalf("round trip %q (%v), want %q", got, err, args)
	}
}
