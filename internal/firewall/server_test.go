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
const testSlot = "name=sandboxd-internal,ipv4=192.168.128.0/24,gw=192.168.128.1,ipv6=fd1e:68b8:2ef4:5d5a::/64"

var testNetworkJSON = networkJSON("sandboxd-internal", "192.168.128.1", "192.168.128.0/24", "fd1e:68b8:2ef4:5d5a::/64")
var testPinJSON = "[" + pinJSON("sandboxd-internal") + "]"

func networkJSON(name, gateway, ipv4, ipv6 string) string {
	return `[{"configuration":{"name":"` + name + `","mode":"hostOnly","plugin":"container-network-vmnet","labels":{"gitmoot.sandboxd.network":"apple-v1"}},"status":{"ipv4Gateway":"` + gateway + `","ipv4Subnet":"` + ipv4 + `","ipv6Subnet":"` + ipv6 + `"}}]`
}

// pinJSON is one slot's trusted pin VM, without the surrounding list.
func pinJSON(network string) string {
	return `{"configuration":{"id":"` + PinID("mac-local", network) + `","labels":{"gitmoot.sandboxd.pin":"apple-v1","gitmoot.sandboxd.worker":"mac-local"},"image":{"reference":"` + testPinImage + `"},"networks":[{"network":"` + network + `"}],"initProcess":{"executable":"/bin/sleep","arguments":["2147483647"],"user":{"id":{"uid":1000,"gid":1000}}},"readOnly":true,"capDrop":["ALL"],"capAdd":[],"mounts":[],"publishedPorts":[],"publishedSockets":[],"dns":null,"resources":{"cpus":1,"memoryInBytes":268435456}},"status":{"state":"running"}}`
}

func testMainHash() string {
	hash := sha256.Sum256([]byte(testMainRules))
	return hex.EncodeToString(hash[:])
}

func mustSlots(t *testing.T, values ...string) []Slot {
	t.Helper()
	slots := make([]Slot, len(values))
	for i, value := range values {
		slot, err := ParseSlot(value)
		if err != nil {
			t.Fatal(err)
		}
		slots[i] = slot
	}
	return slots
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		SocketPath: filepath.Join(t.TempDir(), "helper.sock"), WorkerUID: 501, WorkerGID: 20,
		WorkerHome: "/Users/jerry", WorkerID: "mac-local", ContainerCLI: "/usr/local/bin/container",
		Slots: mustSlots(t, testSlot), PinImage: testPinImage,
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

// oneSlotHost points s at a fake Mac with one slot bridge (bridge102) and
// returns the switches the tests flip.
func oneSlotHost(s *Server) (pinPresent *bool, bridge *string, pf *fakePF) {
	pinPresent = testContainer(s)
	name := "bridge102"
	s.interfaces = func() ([]net.Interface, error) {
		if name == "" {
			return nil, nil
		}
		return []net.Interface{{Name: name, Flags: net.FlagUp}}, nil
	}
	s.addrs = func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.128.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd1e:68b8:2ef4:5d5a::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	return pinPresent, &name, newFakePF().attach(s)
}

func TestFirewallGateRequiresExactPinnedBridgeAndRules(t *testing.T) {
	s, err := NewServer(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	pinPresent, bridge, pf := oneSlotHost(s)
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
	if pf.flushes["bridge102"] != 1 {
		t.Fatalf("arm did not flush stale bridge states: %d", pf.flushes["bridge102"])
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
	if got, err := s.arm(ctx); err != nil || got != "bridge102" || pf.flushes["bridge102"] != 2 {
		t.Fatalf("rearm did not clear old bridge states: %q %v, flushes=%d", got, err, pf.flushes["bridge102"])
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
	pf.skipped["bridge102"] = true
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted a deny anchor on a PF-skipped bridge")
	}
	pf.skipped["bridge102"] = false
	*pinPresent = false
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted firewall policy without the trusted pin VM")
	}
	*pinPresent = true
	pf.enabled = false
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted policy with PF disabled")
	}
	pf.enabled = true
	s.mainHash[0] ^= 1
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted an unreviewed Mac PF main ruleset")
	}
	s.mainHash[0] ^= 1
	armed, armedNAT, tables := pf.filter, pf.nat, pf.tables
	pf.setLoaded("pass in quick on bridge102 inet all", "")
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted altered policy")
	}
	if _, err := s.arm(ctx); err == nil {
		t.Fatal("overwrote unexpected existing policy")
	}
	pf.filter, pf.nat, pf.tables = armed, armedNAT, tables
	*bridge = ""
	if _, err := s.check(ctx); err == nil {
		t.Fatal("accepted policy after bridge vanished")
	}
	if err := s.disarm(ctx); err == nil {
		t.Fatal("cleared PF while trusted pin still uses the network")
	}
	*pinPresent = false
	if err := s.disarm(ctx); err != nil || pf.filter != "" || pf.nat != "" {
		t.Fatalf("failed to clear owned anchor after bridge disappeared: %q %v", pf.filter, err)
	}
}

func TestModelRelayPolicyOnlyPassesPinnedGateway(t *testing.T) {
	cfg := testConfig(t)
	for _, port := range []int{-1, 1, 65536} {
		cfg.ModelRelayPort = port
		if _, err := NewServer(cfg); err == nil {
			t.Fatalf("accepted unsafe model relay port %d", port)
		}
	}
	cfg.ModelRelayPort = 8443
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pinPresent, bridge, pf := oneSlotHost(s)
	ctx := context.Background()
	if got, err := s.arm(ctx); err != nil || got != "bridge102" {
		t.Fatalf("failed to arm narrowly scoped model policy: %q %v", got, err)
	}
	const relay = "pass in quick on bridge102 inet proto tcp from 192.168.128.0/24 to 192.168.128.1 port 8443\n"
	if len(pf.loadedText) != 1 || !strings.Contains(pf.loadedText[0], relay) || strings.Count(pf.loadedText[0], " proto tcp ") != 1 {
		t.Fatalf("model exception is not confined to the fixed guest gateway:\n%s", pf.loadedText)
	}
	// The relay pass comes before the host deny: every other Mac port stays denied.
	if relayAt, hostAt := strings.Index(pf.filter, "port = 8443"), strings.Index(pf.filter, "<sandboxd_host>"); relayAt < 0 || hostAt < relayAt {
		t.Fatalf("relay pass does not precede the host deny:\n%s", pf.filter)
	}
	if _, err := s.check(ctx); err != nil {
		t.Fatalf("rejected exact model policy: %v", err)
	}
	armed := pf.filter
	pf.filter = strings.Replace(armed, "to 192.168.128.1 port = 8443", "to any port = 8443", 1)
	if _, err := s.check(ctx); err == nil {
		t.Fatal("admitted a broadened model pass")
	}
	*pinPresent = false
	*bridge = ""
	if err := s.disarm(ctx); err == nil || pf.filter == "" {
		t.Fatal("cleared an anchor whose model pass was broadened")
	}
	pf.filter = armed
	if err := s.disarm(ctx); err != nil || pf.filter != "" || pf.nat != "" {
		t.Fatalf("failed to clear exact owned model policy after bridge drain: %v", err)
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
