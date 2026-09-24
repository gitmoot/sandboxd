package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

const testMainRules = "anchor \"com.apple/*\" all\n"
const testPinImage = "example/pin@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testNetworkJSON = `[{"configuration":{"name":"sandboxd-internal","mode":"hostOnly","plugin":"container-network-vmnet","labels":{"gitmoot.sandboxd.network":"apple-v1"}},"status":{"ipv4Gateway":"192.168.128.1","ipv4Subnet":"192.168.128.0/24","ipv6Subnet":"fd1e:68b8:2ef4:5d5a::/64"}}]`
const testPinJSON = `[{"configuration":{"id":"sandboxd-pin-3c00d0a9d4c2eb08","labels":{"gitmoot.sandboxd.pin":"apple-v1","gitmoot.sandboxd.worker":"mac-local"},"image":{"reference":"` + testPinImage + `"},"networks":[{"network":"sandboxd-internal"}],"initProcess":{"executable":"/bin/sleep","arguments":["2147483647"],"user":{"id":{"uid":1000,"gid":1000}}},"readOnly":true,"capDrop":["ALL"],"capAdd":[],"mounts":[],"publishedPorts":[],"publishedSockets":[],"dns":null,"resources":{"cpus":1,"memoryInBytes":268435456}},"status":{"state":"running"}}]`

func testMainHash() string {
	hash := sha256.Sum256([]byte(testMainRules))
	return hex.EncodeToString(hash[:])
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		SocketPath: filepath.Join(t.TempDir(), "helper.sock"), WorkerUID: 501, WorkerGID: 20,
		WorkerHome: "/Users/jerry", WorkerID: "mac-local", ContainerCLI: "/usr/local/bin/container",
		Network: "sandboxd-internal", PinImage: testPinImage,
		GatewayIPv4: "192.168.128.1", IPv4Subnet: "192.168.128.0/24",
		IPv6Prefix:      "fd1e:68b8:2ef4:5d5a::/64",
		MainRulesSHA256: testMainHash(),
	}
}

func testContainer(s *Server) *bool {
	pinPresent := true
	s.container = func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "network inspect sandboxd-internal":
			return []byte(testNetworkJSON), nil
		case "list --all --format json":
			if pinPresent {
				return []byte(testPinJSON), nil
			}
			return []byte("[]"), nil
		}
		return nil, fmt.Errorf("unexpected Apple container command %v", args)
	}
	return &pinPresent
}

func TestFirewallGateRequiresExactPinnedBridgeAndRules(t *testing.T) {
	s, err := NewServer(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	pinPresent := testContainer(s)
	bridge := "bridge102"
	s.interfaces = func() ([]net.Interface, error) {
		if bridge == "" {
			return nil, nil
		}
		return []net.Interface{{Name: bridge, Flags: net.FlagUp}}, nil
	}
	s.addrs = func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.128.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd1e:68b8:2ef4:5d5a::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	enabled := true
	skipped := false
	var loaded string
	stateFlushes := 0
	s.pf = func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-s info":
			if enabled {
				return []byte("Status: Enabled for 0 days\n"), nil
			}
			return []byte("Status: Disabled\n"), nil
		case "-sr":
			return []byte("anchor \"com.apple/*\" all\n"), nil
		case "-s Interfaces -v -i bridge102":
			if skipped {
				return []byte("bridge102 (skip)\n"), nil
			}
			return []byte("bridge102\n"), nil
		case "-a " + anchor + " -sr":
			return []byte(loaded), nil
		case "-a " + anchor + " -F rules":
			loaded = ""
			return []byte("rules cleared\n"), nil
		case "-F states -i bridge102":
			stateFlushes++
			return nil, nil
		}
		if len(args) == 4 && args[0] == "-a" && args[1] == anchor &&
			(args[2] == "-nf" || args[2] == "-f") {
			if args[2] == "-f" {
				loaded = canonicalPolicy(bridge)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected PF command %v", args)
	}
	ctx := context.Background()
	if err := s.disarm(ctx); err == nil {
		t.Fatal("cleared anchor while the bridge was present")
	}
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted a missing policy")
	}
	if got, err := s.arm(ctx); err != nil || got != "bridge102" {
		t.Fatalf("failed to install exact bridge policy: %q %v", got, err)
	}
	if stateFlushes != 1 {
		t.Fatalf("arm did not flush stale bridge states: %d", stateFlushes)
	}
	originalContainer := s.container
	s.container = func(ctx context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "list --all --format json" {
			return []byte(strings.TrimSuffix(testPinJSON, "]") + `,{"configuration":{"id":"foreign","networks":[{"network":"sandboxd-internal"}]}}]`), nil
		}
		return originalContainer(ctx, args...)
	}
	if _, err := s.arm(ctx); err == nil {
		t.Fatal("armed while another VM was attached before protection")
	}
	s.container = originalContainer
	if got, err := s.arm(ctx); err != nil || got != "bridge102" || stateFlushes != 2 {
		t.Fatalf("rearm did not clear old bridge states: %q %v, flushes=%d", got, err, stateFlushes)
	}
	if _, err := s.check(ctx); err != nil {
		t.Fatalf("rejected installed policy: %v", err)
	}
	s.container = func(ctx context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "list --all --format json" {
			return []byte(strings.Replace(testPinJSON, `"mounts":[]`, `"mounts":[{"source":"/Users/jerry","destination":"/host"}]`, 1)), nil
		}
		return originalContainer(ctx, args...)
	}
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted a trusted pin with a host mount")
	}
	s.container = originalContainer
	skipped = true
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted a deny anchor on a PF-skipped bridge")
	}
	skipped = false
	*pinPresent = false
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted firewall policy without the trusted pin VM")
	}
	*pinPresent = true
	enabled = false
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted policy with PF disabled")
	}
	enabled = true
	s.mainHash[0] ^= 1
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted an unreviewed Mac PF main ruleset")
	}
	s.mainHash[0] ^= 1
	loaded = "pass in quick on bridge102 inet all"
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted altered policy")
	}
	if _, err := s.arm(ctx); err == nil {
		t.Fatal("overwrote unexpected existing policy")
	}
	loaded = canonicalPolicy("bridge102")
	bridge = ""
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted policy after bridge vanished")
	}
	if err := s.disarm(ctx); err == nil {
		t.Fatal("cleared PF while trusted pin still uses the network")
	}
	*pinPresent = false
	if err := s.disarm(ctx); err != nil || loaded != "" {
		t.Fatalf("failed to clear owned anchor after bridge disappeared: %q %v", loaded, err)
	}
}

func TestFirewallBridgeAmbiguityFailsClosed(t *testing.T) {
	s, err := NewServer(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "bridge102", Flags: net.FlagUp}, {Name: "bridge103", Flags: net.FlagUp}}, nil
	}
	s.addrs = func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.128.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd1e:68b8:2ef4:5d5a::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	if _, err := s.discover(); err == nil {
		t.Fatal("accepted ambiguous guest bridge identity")
	}
}
