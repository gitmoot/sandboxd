//go:build linux

package vm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The KVM tests boot real microVMs. They need root, /dev/kvm and the
// artifacts installed by docs/firecracker.md, and run only when
// SANDBOXD_FC_KVM=1. SANDBOXD_FC_ROOT (default /var/lib/sandboxd-fc) selects
// the install; imageEnv (a rootfs path) overrides the one image in
// <root>/images matching imageGlob. Beside a running sandboxd, set
// SANDBOXD_FC_INSTANCE, SANDBOXD_FC_UID_BASE and a separate root (#50).
func newKVMFirecracker(t *testing.T, imageEnv, imageGlob string, hostPort int) (*FirecrackerDriver, string, context.Context) {
	t.Helper()
	if os.Getenv("SANDBOXD_FC_KVM") != "1" {
		t.Skip("set SANDBOXD_FC_KVM=1 to boot real Firecracker VMs")
	}
	root := os.Getenv("SANDBOXD_FC_ROOT")
	if root == "" {
		root = "/var/lib/sandboxd-fc"
	}
	image := os.Getenv(imageEnv)
	if image == "" {
		matches, _ := filepath.Glob(filepath.Join(root, "images", imageGlob))
		if len(matches) != 1 {
			t.Fatalf("set %s; found images %v", imageEnv, matches)
		}
		image = matches[0]
	}
	kernels, _ := filepath.Glob(filepath.Join(root, "kernel", "vmlinux-*"))
	if len(kernels) != 1 {
		t.Fatalf("expected one kernel, found %v", kernels)
	}
	uidBase := 2900000
	if base := os.Getenv("SANDBOXD_FC_UID_BASE"); base != "" {
		var err error
		if uidBase, err = strconv.Atoi(base); err != nil {
			t.Fatal(err)
		}
	}
	d, err := NewFirecrackerDriver(FirecrackerConfig{
		Instance: os.Getenv("SANDBOXD_FC_INSTANCE"),
		Root:     root, Firecracker: filepath.Join(root, "bin", "firecracker"), Jailer: filepath.Join(root, "bin", "jailer"),
		Kernel: kernels[0], Images: []string{image}, Slots: FirecrackerSlotNames(2),
		UIDBase: uidBase, HomeDiskMiB: 1024, DiskFloorMiB: 4096, BootTimeout: 60 * time.Second,
		ConsoleLog: os.Getenv("SANDBOXD_FC_CONSOLE") == "1",
		// 10.1/16 overlaps 10/8 on purpose: the real tables must accept it.
		// 1.0.0.1 is public: a configured deny must hold even for the internet.
		DenyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("1.0.0.1/32")},
		HostPort:  hostPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	if err := d.Arm(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if err := d.CleanupGuests(cleanup); err != nil {
			t.Error(err)
		}
		if err := d.Disarm(cleanup); err != nil {
			t.Error(err)
		}
	})
	return d, image, ctx
}

// kvmRun runs args in guest id and returns its exit code and output.
func kvmRun(ctx context.Context, t *testing.T, d *FirecrackerDriver, id string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, err := d.Run(ctx, id, Command{Args: args}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("%s %v: %v", id, args, err)
	}
	return code, stdout.String(), stderr.String()
}

// kvmProbe reports whether guest id can open a TCP connection to target.
func kvmProbe(ctx context.Context, t *testing.T, d *FirecrackerDriver, id, target string) string {
	t.Helper()
	_, out, _ := kvmRun(ctx, t, d, id, "/bin/bash", "-c", `timeout 3 bash -c 'exec 3<>"/dev/tcp/${1%:*}/${1#*:}"' probe "$0" 2>/dev/null && echo open || echo closed`, target)
	return strings.TrimSpace(out)
}

// kvmListen accepts and closes TCP connections on addr until the test ends.
func kvmListen(t *testing.T, addr string) int {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// kvmHostAddrs are the host's non-loopback IPv4 addresses.
func kvmHostAddrs(t *testing.T) []string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, addr := range addrs {
		if ip := addr.(*net.IPNet).IP.To4(); ip != nil && !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}
	return out
}

func TestFirecrackerKVM(t *testing.T) {
	d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0)
	ids := []string{"sandboxd-0000000000000000000000000000kvm1", "sandboxd-0000000000000000000000000000kvm2"}
	for i, id := range ids {
		instance, err := d.Create(ctx, Spec{ID: id, Image: image, Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512})
		if err != nil {
			t.Fatal(err)
		}
		if !instance.Running || instance.Network != FirecrackerSlotNames(2)[i] {
			t.Fatalf("instance = %+v", instance)
		}
	}
	run := func(id string, args ...string) (int, string, string) {
		t.Helper()
		return kvmRun(ctx, t, d, id, args...)
	}
	code, out, _ := run(ids[0], "/bin/sh", "-c", "id -u; id -g; pwd; touch / 2>/dev/null || echo ro; uname -m")
	if code != 0 || out != "1000\n1000\n/home/user\nro\nx86_64\n" {
		t.Fatalf("identity: code=%d out=%q", code, out)
	}
	if code, _, _ := run(ids[0], "/bin/sh", "-c", "exit 7"); code != 7 {
		t.Fatalf("exit code = %d", code)
	}
	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, []byte("payload-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyIn(ctx, ids[0], src, "/home/user/.gitmoot/credential-gateway/p"); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(ids[0], "/bin/sh", "-c", "cat ~/.gitmoot/credential-gateway/p; stat -c '%a %u' ~/.gitmoot ~/.gitmoot/credential-gateway/p")
	if code != 0 || out != "payload-1\n700 1000\n600 1000\n" {
		t.Fatalf("copy-in: code=%d out=%q", code, out)
	}
	// The second guest sees neither the file nor the first guest.
	code, out, _ = run(ids[1], "/bin/sh", "-c", "test -e ~/.gitmoot && echo leaked; echo ok")
	if code != 0 || out != "ok\n" {
		t.Fatalf("isolation: code=%d out=%q", code, out)
	}
	// A host listener on every interface: the guest must not reach it on any
	// host address, through the NAT's host alias, or on loopback.
	port := strconv.Itoa(kvmListen(t, ":0"))
	targets := []string{"10.200.0.1:22", "10.0.2.2:" + port, "10.0.2.2:22", "10.0.2.3:53", "127.0.0.1:" + port, "169.254.169.254:80", "192.168.0.1:80",
		"168.63.129.16:80", "1.0.0.1:443"}
	for _, addr := range kvmHostAddrs(t) {
		targets = append(targets, addr+":"+port)
	}
	probe := func(target string) string { return kvmProbe(ctx, t, d, ids[1], target) }
	if got := probe("1.1.1.1:443"); got != "open" {
		t.Fatalf("probe control 1.1.1.1:443 = %q", got)
	}
	for _, target := range targets {
		if got := probe(target); got != "closed" {
			t.Errorf("guest reached %s: %q", target, got)
		}
	}
	code, out, _ = run(ids[1], "/usr/bin/curl", "-sS", "-m", "15", "-o", "/dev/null", "-w", "%{http_code}", "https://github.com/")
	if code != 0 || out != "200" {
		t.Errorf("internet: code=%d out=%q", code, out)
	}
	list, err := d.List(ctx)
	if err != nil || len(list) != 2 || !list[0].Running || !list[1].Running {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, id := range ids {
		if err := d.Destroy(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if list, err := d.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("after destroy: %+v, %v", list, err)
	}
}

// TestFirecrackerKVMHostPort boots guests behind -fc-host-port. Two host
// listeners on every interface: guests reach the allowed one only at
// 10.0.2.2:<allowed>, and nothing else on the host, including the other
// listener, SSH, and the allowed port on the host's own addresses.
func TestFirecrackerKVMHostPort(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_KVM") != "1" {
		t.Skip("set SANDBOXD_FC_KVM=1 to boot real Firecracker VMs")
	}
	allowed := kvmListen(t, ":0")
	other := strconv.Itoa(kvmListen(t, ":0"))
	d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", allowed)
	ids := []string{"sandboxd-0000000000000000000000000000kvm3", "sandboxd-0000000000000000000000000000kvm4"}
	for i, id := range ids {
		if _, err := d.Create(ctx, Spec{ID: id, Image: image, Network: FirecrackerSlotNames(2)[i], CPUs: 1, MemoryMiB: 512}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(allowed)
	for _, id := range ids {
		if got := kvmProbe(ctx, t, d, id, "10.0.2.2:"+port); got != "open" {
			t.Errorf("%s did not reach the host port 10.0.2.2:%s: %q", id, port, got)
		}
	}
	targets := []string{"10.0.2.2:" + other, "10.0.2.2:22", "10.200.0.1:22", "10.200.0.1:" + port, "10.0.2.3:53",
		"127.0.0.1:" + port, "169.254.169.254:80", "192.168.0.1:80", "1.0.0.1:443"}
	for _, addr := range kvmHostAddrs(t) {
		targets = append(targets, addr+":"+port, addr+":"+other, addr+":22")
	}
	for _, target := range targets {
		if got := kvmProbe(ctx, t, d, ids[1], target); got != "closed" {
			t.Errorf("guest reached %s: %q", target, got)
		}
	}
	// UDP to the alias stays dropped, even with a host UDP echo on the
	// allowed port's number.
	udp, err := net.ListenPacket("udp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], from)
		}
	}()
	if code, out, _ := kvmRun(ctx, t, d, ids[1], "/bin/bash", "-c",
		`timeout 3 bash -c 'exec 3<>/dev/udp/10.0.2.2/'"$0"'; printf x >&3; read -t 2 -n 1 <&3' 2>/dev/null && echo open || echo closed`, port); code != 0 || strings.TrimSpace(out) != "closed" {
		t.Errorf("udp to 10.0.2.2:%s: code=%d out=%q", port, code, out)
	}
	if got := kvmProbe(ctx, t, d, ids[1], "1.1.1.1:443"); got != "open" {
		t.Errorf("internet control 1.1.1.1:443 = %q", got)
	}
}

// TestFirecrackerKVMGoImage boots the review-go126 image and builds a tiny
// module offline. SANDBOXD_FC_GO_IMAGE overrides the one
// <root>/images/review-go126-amd64-*.ext4.
func TestFirecrackerKVMGoImage(t *testing.T) {
	d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_GO_IMAGE", "review-go126-amd64-*.ext4", 0)
	id := "sandboxd-0000000000000000000000000000kvm5"
	if _, err := d.Create(ctx, Spec{ID: id, Image: image, Network: "sbx0", CPUs: 2, MemoryMiB: 2048}); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := kvmRun(ctx, t, d, id, "/bin/bash", "-lc", `set -e
go version
command -v git >/dev/null
test -s /etc/ssl/certs/ca-certificates.crt
mkdir -p ~/hello && cd ~/hello
printf 'module example.com/hello\n\ngo 1.26\n' > go.mod
printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hello from go") }\n' > main.go
GOPROXY=off go build -o hello .
./hello
# gitmoot/gitmoot's dependencies come from the image's module cache alone.
mkdir -p ~/yaml && cd ~/yaml
printf 'module example.com/yaml\n\ngo 1.26\n\nrequire gopkg.in/yaml.v3 v3.0.1\n' > go.mod
printf 'package main\n\nimport (\n\t"fmt"\n\n\t"gopkg.in/yaml.v3"\n)\n\nfunc main() {\n\tvar v map[string]int\n\t_ = yaml.Unmarshal([]byte("a: 1"), &v)\n\tfmt.Println("yaml", v["a"])\n}\n' > main.go
export GOPROXY=file:///opt/gomodcache/cache/download GOSUMDB=off GOFLAGS=-mod=mod
go mod download modernc.org/sqlite@v1.50.1 github.com/gitmoot/gitmoot-dashboard@v0.0.0-20260917155835-418f6270eb7a
go build -o yaml . && ./yaml`)
	if code != 0 || !strings.HasPrefix(out, "go version go1.26.") || !strings.Contains(out, "linux/amd64\n") ||
		!strings.HasSuffix(out, "hello from go\nyaml 1\n") {
		t.Fatalf("go: code=%d out=%q stderr=%q", code, out, stderr)
	}
	t.Logf("%s", out)
}

// A host-table change reaches a guest running a long command through the
// nftables event path alone (polls an hour apart): the guest is destroyed
// and the loss reported. The latency is logged; the poll-only baseline is
// up to a poll interval plus one tolerated failure.
func TestFirecrackerKVMFirewallEvent(t *testing.T) {
	for _, change := range []string{"delete table", "flush table"} {
		t.Run(strings.ReplaceAll(change, " ", "-"), func(t *testing.T) {
			d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0)
			d.firewallEvery = time.Hour
			id := "sandboxd-kvm-firewall-event"
			if _, err := d.Create(ctx, Spec{ID: id, Image: image, Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
				t.Fatal(err)
			}
			events, stop := context.WithCancel(ctx)
			defer stop()
			go d.WatchFirewallEvents(events)
			waitForMonitor(t)
			done := make(chan error, 1)
			go func() {
				_, err := d.Run(ctx, id, Command{Args: []string{"sleep", "120"}}, io.Discard, io.Discard)
				done <- err
			}()
			time.Sleep(500 * time.Millisecond) // the command is under way
			start := time.Now()
			if out, err := exec.Command("nft", change, "inet", d.HostTable()).CombinedOutput(); err != nil {
				t.Fatalf("nft %s: %v %s", change, err, out)
			}
			select {
			case err := <-d.FirewallLost():
				t.Logf("%s: loss reported %v after the change (%v)", change, time.Since(start), err)
			case <-time.After(10 * time.Second):
				t.Fatal("no loss reported")
			}
			select {
			case err := <-done:
				t.Logf("%s: command ended %v after the change: %v", change, time.Since(start), err)
			case <-time.After(10 * time.Second):
				t.Fatal("the command outlived the firewall change")
			}
			if _, found, err := d.lookup(id); err != nil || found {
				t.Fatalf("guest still present: %t %v", found, err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Errorf("event path took %v; want well under the 1s poll", elapsed)
			}
			// Re-arm so cleanup's Disarm finds the table it removes.
			if err := d.Arm(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A killed `nft monitor` is restarted (one tolerated failure); the poll
// still catches a deleted table on its own.
func TestFirecrackerKVMFirewallEventMonitorKilled(t *testing.T) {
	d, _, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0)
	events, stop := context.WithCancel(ctx)
	defer stop()
	go d.WatchFirewallEvents(events)
	first := waitForMonitor(t)
	if err := syscall.Kill(first, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if pid := monitorPID(); pid != 0 && pid != first {
			t.Logf("nft monitor restarted: pid %d -> %d", first, pid)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nft monitor was not restarted")
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-d.FirewallLost():
		t.Fatalf("one killed monitor reported a loss: %v", err)
	default:
	}
	stop() // events off: only the poll is left
	if out, err := exec.Command("nft", "delete", "table", "inet", d.HostTable()).CombinedOutput(); err != nil {
		t.Fatalf("nft delete: %v %s", err, out)
	}
	start := time.Now()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := d.Ready(waitCtx); errors.Is(err, errFirewallLost) {
			t.Logf("poll caught the deleted table after %v", time.Since(start))
			break
		}
		if waitCtx.Err() != nil {
			t.Fatal("the poll did not catch the deleted table")
		}
		time.Sleep(d.firewallEvery)
	}
	if err := d.Arm(ctx); err != nil {
		t.Fatal(err)
	}
}

// monitorPID finds this process's `nft monitor` child, or 0.
func monitorPID() int {
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid()), "-f", "^/[^ ]*nft monitor$").Output()
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0
	}
	pid, _ := strconv.Atoi(fields[0])
	return pid
}

func waitForMonitor(t *testing.T) int {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if pid := monitorPID(); pid != 0 {
			// The subscription is live once nft has opened its socket; give
			// it a moment after exec.
			time.Sleep(200 * time.Millisecond)
			return pid
		}
	}
	t.Fatal("nft monitor did not start")
	return 0
}
