//go:build linux

package vm

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFirecrackerKVM boots real microVMs. It needs root, /dev/kvm and the
// artifacts installed by docs/firecracker.md, and runs only when
// SANDBOXD_FC_KVM=1. SANDBOXD_FC_ROOT (default /var/lib/sandboxd-fc) and
// SANDBOXD_FC_IMAGE (the rootfs path) select the install.
func TestFirecrackerKVM(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_KVM") != "1" {
		t.Skip("set SANDBOXD_FC_KVM=1 to boot real Firecracker VMs")
	}
	root := os.Getenv("SANDBOXD_FC_ROOT")
	if root == "" {
		root = "/var/lib/sandboxd-fc"
	}
	image := os.Getenv("SANDBOXD_FC_IMAGE")
	if image == "" {
		matches, _ := filepath.Glob(filepath.Join(root, "images", "review-amd64-*.ext4"))
		if len(matches) != 1 {
			t.Fatalf("set SANDBOXD_FC_IMAGE; found images %v", matches)
		}
		image = matches[0]
	}
	kernels, _ := filepath.Glob(filepath.Join(root, "kernel", "vmlinux-*"))
	if len(kernels) != 1 {
		t.Fatalf("expected one kernel, found %v", kernels)
	}
	d, err := NewFirecrackerDriver(FirecrackerConfig{
		Root: root, Firecracker: filepath.Join(root, "bin", "firecracker"), Jailer: filepath.Join(root, "bin", "jailer"),
		Kernel: kernels[0], Images: []string{image}, Slots: FirecrackerSlotNames(2),
		UIDBase: 2900000, HomeDiskMiB: 1024, DiskFloorMiB: 4096, BootTimeout: 60 * time.Second,
		ConsoleLog: os.Getenv("SANDBOXD_FC_CONSOLE") == "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
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
		var stdout, stderr bytes.Buffer
		code, err := d.Run(ctx, id, Command{Args: args}, &stdout, &stderr)
		if err != nil {
			t.Fatalf("%s %v: %v", id, args, err)
		}
		return code, stdout.String(), stderr.String()
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
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	targets := []string{"10.200.0.1:22", "10.0.2.2:" + port, "10.0.2.3:53", "127.0.0.1:" + port, "169.254.169.254:80", "192.168.0.1:80"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if ip := addr.(*net.IPNet).IP.To4(); ip != nil && !ip.IsLoopback() {
			targets = append(targets, ip.String()+":"+port)
		}
	}
	probe := func(target string) string {
		_, out, _ := run(ids[1], "/bin/bash", "-c", `timeout 3 bash -c 'exec 3<>"/dev/tcp/${1%:*}/${1#*:}"' probe "$0" 2>/dev/null && echo open || echo closed`, target)
		return strings.TrimSpace(out)
	}
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
