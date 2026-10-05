package firewall

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/egress"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

// threeSlotServer is the Mac Studio's shape: three slots, the model relay
// on the first slot's gateway (192.168.128.1:43181).
func threeSlotServer(t *testing.T, deny ...netip.Prefix) *Server {
	t.Helper()
	cfg := testConfig(t)
	cfg.Slots = mustSlots(t,
		"name=sandboxd-internal,ipv4=192.168.128.0/24,gw=192.168.128.1,ipv6=fd1e:68b8:2ef4:5d00::/64",
		"name=sandboxd-slot-2,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d02::/64",
		"name=sandboxd-slot-3,ipv4=192.168.131.0/24,gw=192.168.131.1,ipv6=fd1e:68b8:2ef4:5d03::/64")
	cfg.ModelRelayPort = 43181
	cfg.DenyCIDRs = deny
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	threeBridges = []string{"bridge102", "bridge103", "bridge104"}
	// macHost is every address of a Mac like the Mac Studio: loopback, LAN,
	// Tailscale and the three slot gateways.
	macHost = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("100.111.92.43/32"),
		netip.MustParsePrefix("192.168.1.20/32"), netip.MustParsePrefix("192.168.128.1/32"),
		netip.MustParsePrefix("192.168.130.1/32"), netip.MustParsePrefix("192.168.131.1/32"),
		netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fd7a:115c:a1e0::4e01:5c2b/128"),
	}
)

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from the generated ruleset (go test -run %s -update to accept):\n%s", path, t.Name(), got)
	}
}

func TestThreeSlotEgressRulesetGolden(t *testing.T) {
	s := threeSlotServer(t)
	p := s.policyFor(threeBridges, "en0", 43181, macHost)
	golden(t, "egress-3slot.pf", p.Load)
	golden(t, "egress-3slot.readback", "# pfctl -a "+anchor+" -sr\n"+p.Filter+"\n# pfctl -a "+anchor+" -sn\n"+p.NAT+"\n")

	// The helper's prediction of pfctl's readback is what the pfctl model
	// prints for the loaded text, with and without the optimizer off.
	filter, nat, tables, err := pfctlLoad(p.Load, false)
	if err != nil {
		t.Fatal(err)
	}
	if filter != p.Filter || nat != p.NAT {
		t.Fatalf("readback prediction differs from pfctl:\n%s\n%s", filter, nat)
	}
	if !samePrefixes(tables[denyTable], s.deny) || !samePrefixes(tables[hostTable], macHost) ||
		!samePrefixes(tables[guestsTable], s.subnets()) {
		t.Fatalf("loaded tables differ: %v", tables)
	}
	if optimized, _, _, _ := pfctlLoad(p.Load, true); optimized == p.Filter {
		t.Fatal("the pfctl model no longer reorders inet6 rules; -o none is untested")
	}
}

// Every range the owner listed, every configured extra and every Mac address
// is denied on every bridge before that bridge's internet pass; guest IPv6
// is dropped whole; other guests are denied both ways.
func TestEveryDeniedRangeAndHostAddressIsInTheAnchor(t *testing.T) {
	extra := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	s := threeSlotServer(t, extra...)
	p := s.policyFor(threeBridges, "en0", 43181, macHost)
	_, _, tables, err := pfctlLoad(p.Load, false)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
		"127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/3", "168.63.129.16/32", "fc00::/7", "fe80::/10", "ff00::/8",
		"::/127", "203.0.113.0/24", "2001:db8::/32"}
	for _, prefix := range required {
		if !slices.Contains(tables[denyTable], netip.MustParsePrefix(prefix)) {
			t.Errorf("deny table lacks %s", prefix)
		}
	}
	// ::1 (loopback) is in ::/127.
	if !slices.ContainsFunc(tables[denyTable], func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr("::1")) }) {
		t.Error("deny table does not cover ::1")
	}
	for _, addr := range macHost {
		if !slices.Contains(tables[hostTable], addr) {
			t.Errorf("host table lacks Mac address %s", addr)
		}
	}
	lines := strings.Split(p.Filter, "\n")
	index := func(line string) int { return slices.Index(lines, line) }
	for i, bridge := range threeBridges {
		subnet := s.config.Slots[i].IPv4.String()
		on := "in quick on " + bridge + " inet"
		relay := index("pass " + on + " proto tcp from " + subnet + " to 192.168.128.1 port = 43181 flags S/SA keep state")
		deny := index("block drop " + on + " from any to <" + denyTable + ">")
		host := index("block drop " + on + " from any to <" + hostTable + ">")
		internet := index("pass " + on + " from " + subnet + " to any flags S/SA keep state")
		dropAll := index("block drop " + on + " all")
		drop6 := index("block drop " + on + "6 all")
		if relay < 0 || deny <= relay || host <= deny || internet <= host || dropAll <= internet || drop6 <= dropAll {
			t.Errorf("%s rules missing or out of order: relay %d deny %d host %d internet %d drop %d drop6 %d",
				bridge, relay, deny, host, internet, dropAll, drop6)
		}
		if !strings.Contains(p.NAT, "nat on en0 inet from "+subnet+" to any -> (en0) round-robin") {
			t.Errorf("%s is not NATed out of en0", subnet)
		}
		// Other guests: every slot subnet is a denied private range, so no
		// bridge reaches another, and no other interface reaches a guest.
		for _, other := range s.config.Slots {
			if !slices.ContainsFunc(tables[denyTable], func(p netip.Prefix) bool { return p.Contains(other.IPv4.Addr()) }) {
				t.Errorf("guest subnet %s is not denied to other guests", other.IPv4)
			}
			if !slices.Contains(tables[guestsTable], other.IPv4) {
				t.Errorf("guest table lacks %s", other.IPv4)
			}
		}
	}
	if lines[len(lines)-1] != "block drop in quick inet from any to <"+guestsTable+">" {
		t.Errorf("guest subnets are reachable from other interfaces:\n%s", p.Filter)
	}
	if strings.Contains(p.Filter, "pass in quick on bridge102 inet6") || strings.Count(p.Filter, "inet6") != len(threeBridges) {
		t.Errorf("guest IPv6 is not dropped whole:\n%s", p.Filter)
	}
}

// One Go list is the deny set of both drivers; internal/vm's Firecracker
// test checks its side.
func TestHelperDeniesTheSharedEgressList(t *testing.T) {
	extra := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	s := threeSlotServer(t, extra...)
	deny4, deny6, err := egress.Deny(extra)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.deny, append(deny4, deny6...)) {
		t.Fatalf("helper deny set %v is not internal/egress's %v %v", s.deny, deny4, deny6)
	}
	cfg := s.config
	cfg.DenyCIDRs = []netip.Prefix{netip.MustParsePrefix("203.0.113.7/24")}
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("accepted a deny CIDR that is not a network prefix")
	}
}

// The hook for allow_internet_access:false: a slot without internet keeps
// only the relay exception, with no NAT and no internet pass.
func TestDenyAllSlotKeepsOnlyTheRelay(t *testing.T) {
	s := threeSlotServer(t)
	slots := []slotRules{
		{Bridge: "bridge102", Subnet: s.config.Slots[0].IPv4, Internet: true},
		{Bridge: "bridge103", Subnet: s.config.Slots[1].IPv4},
		{Bridge: "bridge104", Subnet: s.config.Slots[2].IPv4, Internet: true},
	}
	p := render(policyInput{Slots: slots, RelayAddr: s.relayAddress(), RelayPort: 43181, Egress: "en0", Deny: s.deny, Host: macHost})
	const closed = "pass in quick on bridge103 inet proto tcp from 192.168.130.0/24 to 192.168.128.1 port = 43181 flags S/SA keep state\n" +
		"block drop in quick on bridge103 inet all\n" +
		"block drop in quick on bridge103 inet6 all\n"
	if !strings.Contains(p.Filter, closed) || strings.Contains(p.NAT, "192.168.130.0/24") ||
		strings.Count(p.NAT, "\n") != 1 || strings.Count(p.Filter, " to any flags S/SA keep state") != 2 {
		t.Fatalf("deny-all slot is not closed:\n%s\n%s", p.Filter, p.NAT)
	}
	if bridges, ok := filterBridges(p.Filter, 3); !ok || !slices.Equal(bridges, []string{"bridge102", "bridge103", "bridge104"}) {
		t.Fatalf("mixed anchor's bridges are not recoverable: %v", bridges)
	}
}
