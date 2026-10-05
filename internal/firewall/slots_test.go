package firewall

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	testSlot1 = "name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64"
	testSlot2 = "name=sandboxd-slot-2,ipv4=192.168.131.0/24,gw=192.168.131.1,ipv6=fd1e:68b8:2ef4:5d02::/64"
)

func slotAddrs(gateway, ula string) []net.Addr {
	return []net.Addr{
		&net.IPNet{IP: net.ParseIP(gateway), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP(ula), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}
}

var (
	slot1Addrs = slotAddrs("192.168.130.1", "fd1e:68b8:2ef4:5d01::1")
	slot2Addrs = slotAddrs("192.168.131.1", "fd1e:68b8:2ef4:5d02::1")
)

// twoSlotHost is a fake Mac with two slot networks, their pins and bridges,
// and its other interfaces (loopback, LAN, Tailscale).
type twoSlotHost struct {
	s *Server
	*fakePF
	bridges  map[string][]net.Addr // up interfaces and their addresses
	extraVMs []string              // additional Apple inventory items
	pins     map[string]bool       // slot network -> pin present
	network2 string                // inspect JSON for slot 2
}

func ipNet(cidr string) *net.IPNet {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	network.IP = ip
	return network
}

func newTwoSlotHost(t *testing.T, relayPort int) *twoSlotHost {
	t.Helper()
	cfg := testConfig(t)
	cfg.Slots = mustSlots(t, testSlot1, testSlot2)
	cfg.ModelRelayPort = relayPort
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &twoSlotHost{
		s:      s,
		fakePF: newFakePF().attach(s),
		bridges: map[string][]net.Addr{
			"bridge110": slot1Addrs, "bridge111": slot2Addrs,
			"lo0":   {ipNet("127.0.0.1/8"), ipNet("::1/128"), ipNet("fe80::1/64")},
			"en0":   {ipNet("192.168.1.20/24"), ipNet("2001:db8:1::20/64"), ipNet("fe80::1c2a:5ff:fe3b:1/64")},
			"utun3": {ipNet("100.111.92.43/32"), ipNet("fd7a:115c:a1e0::4e01:5c2b/128")},
		},
		pins:     map[string]bool{"sandboxd-slot-1": true, "sandboxd-slot-2": true},
		network2: networkJSON("sandboxd-slot-2", "192.168.131.1", "192.168.131.0/24", "fd1e:68b8:2ef4:5d02::/64"),
	}
	s.interfaces = func() ([]net.Interface, error) {
		var out []net.Interface
		for _, name := range []string{"lo0", "en0", "utun3", "bridge100", "bridge110", "bridge111", "bridge112"} {
			if _, ok := h.bridges[name]; ok {
				out = append(out, net.Interface{Name: name, Flags: net.FlagUp})
			}
		}
		return out, nil
	}
	s.addrs = func(iface net.Interface) ([]net.Addr, error) { return h.bridges[iface.Name], nil }
	s.container = func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "network inspect sandboxd-slot-1":
			return []byte(networkJSON("sandboxd-slot-1", "192.168.130.1", "192.168.130.0/24", "fd1e:68b8:2ef4:5d01::/64")), nil
		case "network inspect sandboxd-slot-2":
			return []byte(h.network2), nil
		case "list --all --format json":
			items := append([]string(nil), h.extraVMs...)
			for _, network := range []string{"sandboxd-slot-1", "sandboxd-slot-2"} {
				if h.pins[network] {
					items = append(items, pinJSON(network))
				}
			}
			return []byte("[" + strings.Join(items, ",") + "]"), nil
		}
		return nil, fmt.Errorf("unexpected Apple container command %v", args)
	}
	return h
}
func guestJSON(id string, networks ...string) string {
	var attached []string
	for _, network := range networks {
		attached = append(attached, `{"network":"`+network+`"}`)
	}
	return `{"configuration":{"id":"` + id + `","networks":[` + strings.Join(attached, ",") + `]},"status":{"state":"running"}}`
}

func TestTwoSlotsArmExactMultiBridgePolicy(t *testing.T) {
	h := newTwoSlotHost(t, 8443)
	ctx := context.Background()
	got, err := h.s.arm(ctx)
	if err != nil || got != "bridge110,bridge111" {
		t.Fatalf("did not arm both slot bridges: %q %v", got, err)
	}
	host, err := h.s.hostAddrs()
	if err != nil {
		t.Fatal(err)
	}
	want := h.s.policyFor([]string{"bridge110", "bridge111"}, "en0", 8443, host, true)
	if len(h.loadedText) != 1 || h.loadedText[0] != want.Load {
		t.Fatalf("loaded policy is not the exact two-slot egress policy:\n%q", h.loadedText)
	}
	if h.filter != want.Filter || h.nat != want.NAT {
		t.Fatalf("pfctl's readback differs from the helper's prediction:\n%s\n%s", h.filter, h.nat)
	}
	// Every slot passes the relay only to the first slot's gateway, and
	// reaches the internet only from its own subnet, NATed out of en0.
	for _, rule := range []string{
		"pass in quick on bridge110 inet proto tcp from 192.168.130.0/24 to 192.168.130.1 port = 8443 flags S/SA keep state",
		"pass in quick on bridge111 inet proto tcp from 192.168.131.0/24 to 192.168.130.1 port = 8443 flags S/SA keep state",
		"pass in quick on bridge110 inet from 192.168.130.0/24 to any flags S/SA keep state",
		"pass in quick on bridge111 inet from 192.168.131.0/24 to any flags S/SA keep state",
		"nat on en0 inet from 192.168.130.0/24 to any -> (en0) round-robin",
		"nat on en0 inet from 192.168.131.0/24 to any -> (en0) round-robin",
	} {
		if !strings.Contains(h.filter+"\n"+h.nat, rule) {
			t.Errorf("anchor lacks %q", rule)
		}
	}
	if !h.forwarding {
		t.Fatal("arm did not enable IPv4 forwarding for guest NAT")
	}
	if h.flushes["bridge110"] != 1 || h.flushes["bridge111"] != 1 || h.flushes["bridge100"] != 0 {
		t.Fatalf("arm did not flush exactly the slot bridges' states: %v", h.flushes)
	}
	if got, err := h.s.check(ctx); err != nil || got != "bridge110,bridge111" {
		t.Fatalf("rejected exact two-slot policy: %q %v", got, err)
	}
	// Re-arm adopts the identical policy and flushes both bridges again.
	if _, err := h.s.arm(ctx); err != nil || h.flushes["bridge111"] != 2 || len(h.loadedText) != 1 {
		t.Fatalf("rearm did not adopt the exact policy: %v %v", err, h.flushes)
	}

	readback, nat := h.filter, h.nat
	for name, filter := range map[string]string{
		"model pass crossing slots": strings.Replace(readback, "from 192.168.131.0/24", "from 192.168.130.0/24", 1),
		"model pass to slot 2's own gateway": strings.Replace(readback,
			"from 192.168.131.0/24 to 192.168.130.1", "from 192.168.131.0/24 to 192.168.131.1", 1),
		"internet pass for any source": strings.Replace(readback,
			"pass in quick on bridge111 inet from 192.168.131.0/24 to any", "pass in quick on bridge111 inet all", 1),
		"host deny missing": strings.Replace(readback,
			"block drop in quick on bridge111 inet from any to <sandboxd_host>\n", "", 1),
		"private deny missing": strings.Replace(readback,
			"block drop in quick on bridge110 inet from any to <sandboxd_deny>\n", "", 1),
		"guest subnets open from other interfaces": strings.Replace(readback, "\nblock drop in quick inet from any to <sandboxd_guests>", "", 1),
		"LAN forwarding open":                      strings.Replace(readback, "\nblock drop in quick on ! lo0 inet from any to ! <sandboxd_host>", "", 1),
		"forwarding block on lo0 only": strings.Replace(readback, "block drop in quick on ! lo0 inet from any to ! <sandboxd_host>",
			"block drop in quick on lo0 inet from any to ! <sandboxd_host>", 1),
		"one slot only": h.s.policyFor([]string{"bridge110"}, "en0", 8443, nil, true).Filter,
	} {
		h.filter = filter
		if _, err := h.s.check(ctx); err == nil {
			t.Errorf("%s: check accepted it", name)
		}
	}
	h.filter = h.s.policyFor([]string{"bridge110"}, "en0", 8443, nil, true).Filter
	if _, err := h.s.arm(ctx); err == nil || !strings.Contains(err.Error(), "unexpected firewall policy") {
		t.Fatalf("replaced an unexpected partial anchor: %v", err)
	}
	h.filter = readback
	h.nat = strings.Split(nat, "\n")[0]
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted NAT for slot 1 only")
	}
	h.nat = nat

	h.skipped["bridge111"] = true
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a PF-skipped slot 2 bridge")
	}
	h.skipped["bridge111"] = false
	h.mainNAT = "rdr-anchor \"com.apple/*\" all\n"
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted main rules that never evaluate the helper's NAT anchor")
	}
	h.mainNAT = testMainNAT
	if _, err := h.s.check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEgressTablesAreExactAndHostTableFollowsTheMac(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	hostTableHas := func(addr string) bool {
		return slices.Contains(h.tables[hostTable], netip.MustParsePrefix(addr))
	}
	// Every Mac address on every interface: loopback, LAN, Tailscale, the
	// slot gateways and other bridges. Link-local IPv6 is left out (guest
	// IPv6 is dropped whole).
	for _, addr := range []string{"127.0.0.1/32", "::1/128", "192.168.1.20/32", "2001:db8:1::20/128",
		"100.111.92.43/32", "fd7a:115c:a1e0::4e01:5c2b/128", "192.168.130.1/32", "192.168.131.1/32",
		"fd1e:68b8:2ef4:5d01::1/128"} {
		if !hostTableHas(addr) {
			t.Errorf("host table lacks Mac address %s: %v", addr, h.tables[hostTable])
		}
	}
	if hostTableHas("fe80::1/128") {
		t.Error("host table holds a scoped link-local address")
	}
	// The Mac's own broadcast and multicast destinations stay reachable on
	// its LAN under the forwarding block.
	for _, addr := range []string{"192.168.1.255/32", "255.255.255.255/32", "224.0.0.0/4", "127.255.255.255/32"} {
		if !hostTableHas(addr) {
			t.Errorf("host table lacks local destination %s", addr)
		}
	}
	if hostTableHas("100.111.92.43/31") || hostTableHas("8.8.8.8/32") {
		t.Error("host table holds a destination that is not the Mac")
	}

	// A new Mac address (DHCP, a public address) is denied within one check.
	h.bridges["en0"] = append(slices.Clone(h.bridges["en0"]), &net.IPNet{IP: net.ParseIP("203.0.113.9"), Mask: net.CIDRMask(24, 32)})
	if _, err := h.s.check(ctx); err != nil {
		t.Fatal(err)
	}
	if !hostTableHas("203.0.113.9/32") {
		t.Fatalf("check did not add the Mac's new address: %v", h.tables[hostTable])
	}
	if len(h.loadedText) != 1 {
		t.Fatal("refreshing the host table reloaded the anchor")
	}

	deny := slices.Clone(h.tables[denyTable])
	h.tables[denyTable] = deny[1:]
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a deny table missing a range")
	}
	// Arm restores the exact tables in one reload.
	if _, err := h.s.arm(ctx); err != nil || len(h.loadedText) != 2 || !samePrefixes(h.tables[denyTable], deny) {
		t.Fatalf("arm did not restore the deny table: %v", err)
	}
	h.tables[guestsTable] = h.tables[guestsTable][:1]
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a guest table missing slot 2")
	}
	delete(h.tables, hostTable)
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted an anchor without its host table")
	}
}

func TestEgressNeedsANATInterface(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	h.route = ""
	if _, err := h.s.arm(ctx); err == nil || len(h.loadedText) != 0 || h.forwarding {
		t.Fatalf("armed without a default route for guest NAT: %v", err)
	}
	h.route = "bridge100"
	if _, err := h.s.arm(ctx); err == nil || len(h.loadedText) != 0 {
		t.Fatalf("NATed guests out of a bridge: %v", err)
	}
	h.route = "en7"
	if _, err := h.s.arm(ctx); err != nil || !strings.Contains(h.nat, "nat on en7 inet from 192.168.130.0/24 to any -> (en7)") {
		t.Fatalf("did not NAT out of the default route interface: %v\n%s", err, h.nat)
	}
	// A configured interface wins over the default route; a moved default
	// route is followed on the next arm.
	cfg := h.s.config
	cfg.EgressInterface = "en1"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.interfaces, s.addrs, s.container = h.s.interfaces, h.s.addrs, h.s.container
	h.s = s
	h.attach(s)
	if _, err := h.s.arm(ctx); err != nil || !strings.Contains(h.nat, "nat on en1 ") || strings.Contains(h.nat, "en7") {
		t.Fatalf("did not replace the NAT interface: %v\n%s", err, h.nat)
	}
	for _, name := range []string{"bridge100", "lo0", "en", "en0;", "../en0"} {
		cfg.EgressInterface = name
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("accepted egress interface %q", name)
		}
	}
}

func TestMissingOrChangedSlotBridgeRefusesArmAndCheck(t *testing.T) {
	ctx := context.Background()

	// Slot 2's bridge has not come up yet: arm refuses with the retryable text
	// and loads nothing.
	h := newTwoSlotHost(t, 0)
	delete(h.bridges, "bridge111")
	if _, err := h.s.arm(ctx); err == nil || !strings.Contains(err.Error(), bridgeNotReady) || !strings.Contains(err.Error(), "sandboxd-slot-2") {
		t.Fatalf("armed without slot 2's bridge or lost the retryable refusal: %v", err)
	}
	if len(h.loadedText) != 0 || h.filter != "" || h.forwarding {
		t.Fatalf("loaded a policy before every slot bridge was attested: %q", h.loadedText)
	}

	h = newTwoSlotHost(t, 0)
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	// Slot 2's bridge vanishes after arming.
	saved := h.bridges["bridge111"]
	delete(h.bridges, "bridge111")
	if _, err := h.s.check(ctx); err == nil || !strings.Contains(err.Error(), bridgeNotReady) {
		t.Fatalf("accepted policy after slot 2's bridge vanished: %v", err)
	}
	// Apple recreated slot 2 on a different bridge: the anchor no longer guards it.
	h.bridges["bridge112"] = saved
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted policy naming the old slot 2 bridge")
	}
	if _, err := h.s.arm(ctx); err == nil {
		t.Fatal("rewrote the anchor for a changed slot bridge")
	}
	delete(h.bridges, "bridge112")
	h.bridges["bridge111"] = saved

	// One bridge carrying both slots' addresses cannot be attributed.
	delete(h.bridges, "bridge110")
	h.bridges["bridge111"] = append(append([]net.Addr(nil), slot1Addrs[:2]...), slot2Addrs...)
	if _, err := h.s.check(ctx); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("accepted a bridge matching two slots: %v", err)
	}
	h.bridges["bridge110"] = slot1Addrs
	h.bridges["bridge111"] = saved

	// Two bridges both claiming slot 1.
	h.bridges["bridge112"] = slot1Addrs
	if _, err := h.s.check(ctx); err == nil || !strings.Contains(err.Error(), "multiple bridges") {
		t.Fatalf("accepted two bridges for one slot: %v", err)
	}
	delete(h.bridges, "bridge112")

	// Slot 2's Apple network was recreated with another subnet.
	h.network2 = networkJSON("sandboxd-slot-2", "192.168.132.1", "192.168.132.0/24", "fd1e:68b8:2ef4:5d02::/64")
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a changed slot 2 network identity")
	}
	h.network2 = networkJSON("sandboxd-slot-2", "192.168.131.1", "192.168.131.0/24", "fd1e:68b8:2ef4:5d02::/64")

	h.pins["sandboxd-slot-2"] = false
	if _, err := h.s.check(ctx); err == nil || !strings.Contains(err.Error(), "sandboxd-slot-2") {
		t.Fatalf("accepted policy without slot 2's pin: %v", err)
	}
	h.pins["sandboxd-slot-2"] = true
	if _, err := h.s.check(ctx); err != nil {
		t.Fatal(err)
	}
}

// legacyDenyAll and legacyRelay are what helpers before guest egress
// (v0.1.x) left in the anchor for the two-slot host's bridges.
const legacyDenyAll = "block drop in quick on bridge110 inet all\n" +
	"block drop in quick on bridge110 inet6 all\n" +
	"block drop in quick on bridge111 inet all\n" +
	"block drop in quick on bridge111 inet6 all"

const legacyRelay = "pass in quick on bridge110 inet proto tcp from 192.168.130.0/24 to 192.168.130.1 port = 43181 flags S/SA keep state\n" +
	"block drop in quick on bridge110 inet all\n" +
	"block drop in quick on bridge110 inet6 all\n" +
	"pass in quick on bridge111 inet proto tcp from 192.168.131.0/24 to 192.168.130.1 port = 43181 flags S/SA keep state\n" +
	"block drop in quick on bridge111 inet all\n" +
	"block drop in quick on bridge111 inet6 all"

func TestArmReplacesOnlyThisHelpersAnchors(t *testing.T) {
	ctx := context.Background()
	bridges := []string{"bridge110", "bridge111"}
	other := newTwoSlotHost(t, 8080).s
	current := newTwoSlotHost(t, 43181).s
	for name, loaded := range map[string][2]string{
		"bridges swapped":       {strings.NewReplacer("bridge110", "bridge111", "bridge111", "bridge110").Replace(legacyDenyAll), ""},
		"another bridge":        {strings.ReplaceAll(legacyDenyAll, "bridge111", "bridge112"), ""},
		"one slot only":         {"block drop in quick on bridge110 inet all\nblock drop in quick on bridge110 inet6 all", ""},
		"foreign rule appended": {legacyDenyAll + "\npass in quick on bridge111 inet all", ""},
		"foreign rule first":    {"pass in quick on bridge110 inet proto tcp from any to any port = 22 flags S/SA keep state\n" + legacyDenyAll, ""},
		"optimizer order": {"block drop in quick on bridge110 inet all\nblock drop in quick on bridge111 inet all\n" +
			"block drop in quick on bridge110 inet6 all\nblock drop in quick on bridge111 inet6 all", ""},
		"legacy relay on another port":  {legacyFilter(bridges, other.relayAddress(), other.subnets(), 8080), ""},
		"egress relay on another port":  {other.policyFor(bridges, "en0", 8080, nil, true).Filter, other.policyFor(bridges, "en0", 8080, nil, true).NAT},
		"legacy anchor with a NAT rule": {legacyDenyAll, "nat on en0 inet from any to any -> (en0) round-robin"},
		"egress anchor without NAT":     {current.policyFor(bridges, "en0", 43181, nil, true).Filter, ""},
		"egress anchor with foreign NAT": {current.policyFor(bridges, "en0", 43181, nil, true).Filter,
			"nat on en0 inet from any to any -> (en0) round-robin\nnat on en0 inet from any to any -> (en0) round-robin"},
	} {
		h := newTwoSlotHost(t, 43181)
		h.setLoaded(loaded[0], loaded[1])
		if _, err := h.s.arm(ctx); err == nil || !strings.Contains(err.Error(), "unexpected firewall policy") {
			t.Errorf("%s: replaced an anchor that is not this helper's: %v", name, err)
		}
		if h.filter != loaded[0] || h.nat != loaded[1] || len(h.loadedText) != 0 || len(h.flushes) != 0 || h.forwarding {
			t.Errorf("%s: touched PF while refusing: %q %v", name, h.loadedText, h.flushes)
		}
	}

	for name, loaded := range map[string][2]string{
		"pre-egress deny-all":    {legacyDenyAll, ""},
		"pre-egress relay":       {legacyRelay, ""},
		"egress with relay off":  {current.policyFor(bridges, "en0", 0, nil, true).Filter, current.policyFor(bridges, "en0", 0, nil, true).NAT},
		"egress out of en1":      {current.policyFor(bridges, "en1", 43181, nil, true).Filter, current.policyFor(bridges, "en1", 43181, nil, true).NAT},
		"egress with old tables": {current.policyFor(bridges, "en0", 43181, nil, true).Filter, current.policyFor(bridges, "en0", 43181, nil, true).NAT},
		"egress without the forwarding guard": {current.policyFor(bridges, "en0", 43181, nil, false).Filter,
			current.policyFor(bridges, "en0", 43181, nil, false).NAT},
	} {
		h := newTwoSlotHost(t, 43181)
		h.setLoaded(loaded[0], loaded[1])
		// Check reconciles this helper's other forwarding shape in place;
		// everything else it refuses until arm replaces it.
		if _, err := h.s.check(ctx); (err == nil) != (name == "egress without the forwarding guard") {
			t.Errorf("%s: check returned %v", name, err)
		}
		if got, err := h.s.arm(ctx); err != nil || got != "bridge110,bridge111" {
			t.Errorf("%s: did not replace it: %q %v", name, got, err)
			continue
		}
		want := h.s.policyFor(bridges, "en0", 43181, nil, true)
		if len(h.loadedText) != 1 || h.filter != want.Filter || h.nat != want.NAT || !strings.Contains(h.filter, "to 192.168.130.1 port = 43181") {
			t.Errorf("%s: not replaced by the egress policy:\n%s\n%s", name, h.filter, h.nat)
		}
		if h.flushes["bridge110"] != 1 || h.flushes["bridge111"] != 1 || !h.forwarding {
			t.Errorf("%s: upgrade did not route and flush both slot bridges' states: %v", name, h.flushes)
		}
	}
}

func TestSlotsAreNeverShared(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	h.extraVMs = []string{guestJSON("sandboxd-a", "sandboxd-slot-2")}
	if _, err := h.s.arm(ctx); err == nil {
		t.Fatal("armed while a guest was already attached to slot 2")
	}
	h.extraVMs = nil
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	h.extraVMs = []string{guestJSON("sandboxd-a", "sandboxd-slot-1"), guestJSON("sandboxd-b", "sandboxd-slot-2")}
	if _, err := h.s.check(ctx); err != nil {
		t.Fatalf("rejected one guest per slot: %v", err)
	}
	h.extraVMs = []string{guestJSON("sandboxd-a", "sandboxd-slot-1"), guestJSON("sandboxd-b", "sandboxd-slot-1")}
	if _, err := h.s.check(ctx); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("accepted two guests sharing slot 1: %v", err)
	}
	h.extraVMs = []string{guestJSON("sandboxd-a", "sandboxd-slot-1", "sandboxd-slot-2")}
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a guest bridging two slots")
	}
	h.extraVMs = []string{guestJSON("sandboxd-a", "sandboxd-slot-1", "default")}
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a slot guest also attached to another network")
	}
}

func TestDisarmClearsOnlyTheExactMultiSlotAnchor(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	armed, armedNAT := h.filter, h.nat
	h.pins["sandboxd-slot-1"] = false
	if err := h.s.disarm(ctx); err == nil || h.filter != armed {
		t.Fatal("cleared PF while slot 2's pin still uses its network")
	}
	h.pins["sandboxd-slot-2"] = false
	delete(h.bridges, "bridge110")
	if err := h.s.disarm(ctx); err == nil || h.filter != armed {
		t.Fatal("cleared PF while slot 2's bridge is present")
	}
	delete(h.bridges, "bridge111")
	h.filter = armed + "\npass in quick on bridge111 inet all"
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an unexpected anchor")
	}
	h.filter = h.s.policyFor([]string{"bridge110"}, "en0", 0, nil, true).Filter
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an anchor in a foreign shape")
	}
	h.filter, h.nat = armed, ""
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an egress anchor without its NAT rules")
	}
	h.nat = "nat on en0 inet from any to any -> (en0) round-robin"
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an anchor with a foreign NAT rule")
	}
	h.nat = armedNAT
	if err := h.s.disarm(ctx); err != nil || h.filter != "" || h.nat != "" || len(h.tables) != 0 {
		t.Fatalf("failed to clear the exact drained two-slot anchor: %v", err)
	}
	// The deny-all anchor of helpers before guest egress is cleared too.
	h.setLoaded(legacyDenyAll, "")
	if err := h.s.disarm(ctx); err != nil || h.filter != "" {
		t.Fatalf("failed to clear a pre-egress helper's anchor: %v", err)
	}
}

func TestSlotConfigurationIsStrict(t *testing.T) {
	for _, value := range []string{
		"",
		"name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1",
		testSlot1 + ",ipv4=192.168.130.0/24",
		testSlot1 + ",mtu=1500",
		"name=default,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64",
		"name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.131.1,ipv6=fd1e:68b8:2ef4:5d01::/64",
		"name=sandboxd-slot-1,ipv4=192.168.130.7/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64",
		"name=sandboxd-slot-1,ipv4=8.8.8.0/24,gw=8.8.8.1,ipv6=fd1e:68b8:2ef4:5d01::/64",
		"name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=2001:db8::/64",
		// Wider than /24: the model relay only admits a /24-or-narrower
		// guest subnet, so such a slot would fail at startup with the relay on.
		"name=sandboxd-slot-1,ipv4=192.168.128.0/23,gw=192.168.128.1,ipv6=fd1e:68b8:2ef4:5d01::/64",
	} {
		if _, err := ParseSlot(value); err == nil {
			t.Errorf("accepted slot %q", value)
		}
	}
	for _, slots := range [][]string{
		{testSlot1, testSlot1},
		{testSlot1, strings.Replace(testSlot2, "192.168.131", "192.168.130", 2)},
		{testSlot1, strings.Replace(testSlot2, "5d02", "5d01", 1)},
		{testSlot1, strings.Replace(testSlot2, "sandboxd-slot-2", "sandboxd-slot-1", 1)},
	} {
		cfg := testConfig(t)
		cfg.Slots = mustSlots(t, slots...)
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("accepted overlapping or duplicate slots %q", slots)
		}
	}
	cfg := testConfig(t)
	cfg.Slots = nil
	if _, err := NewServer(cfg); err == nil {
		t.Error("accepted a helper with no slots")
	}
}

// Apple's container API server is a per-user launchd agent, so the helper's
// system daemon must enter the worker's bootstrap (launchctl asuser, as root)
// and only then drop to the worker (sudo -u #uid -g #gid).
func TestContainerRunsAsTheWorkerInItsLaunchdSession(t *testing.T) {
	name, argv := workerContainerCommand(501, 20, "/usr/local/bin/container", []string{"list", "--all"})
	want := []string{"asuser", "501", "/usr/bin/sudo", "-n", "-H", "-u", "#501", "-g", "#20", "--", "/usr/local/bin/container", "list", "--all"}
	if name != "/bin/launchctl" || strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("command = %s %q, want /bin/launchctl %q", name, argv, want)
	}
}

// Arm records forwarding's previous value once, in the helper's state beside
// its socket; disarm restores it and never turns off a forwarding that was
// already on.
func TestDisarmRestoresIPForwarding(t *testing.T) {
	ctx := context.Background()
	for _, before := range []bool{false, true} {
		h := newTwoSlotHost(t, 0)
		h.forwarding = before
		if _, err := h.s.arm(ctx); err != nil || !h.forwarding {
			t.Fatalf("before=%v: arm did not leave forwarding on: %v", before, err)
		}
		// Only forwarding the helper turned on is guarded; an exit node's or
		// OrbStack's routing is left alone.
		if guarded := strings.Contains(h.filter, "on ! lo0 inet from any to ! <sandboxd_host>"); guarded == before {
			t.Fatalf("before=%v: forwarding guard present=%v", before, guarded)
		}
		if _, err := h.s.check(ctx); err != nil {
			t.Fatalf("before=%v: check refused the recorded shape: %v", before, err)
		}
		// The other forwarding shape of this helper's anchor is reconciled
		// back to the recorded one by check itself.
		armed := h.filter
		h.filter = h.s.policyFor([]string{"bridge110", "bridge111"}, "en0", 0, nil, before).Filter
		if _, err := h.s.check(ctx); err != nil || h.filter != armed {
			t.Fatalf("before=%v: check did not restore the recorded forwarding shape: %v\n%s", before, err, h.filter)
		}
		if before && h.forwardingWrites != 0 {
			t.Fatalf("before=%v: arm rewrote a forwarding that was already on", before)
		}
		// Re-arm and a helper restart (update) keep the first recorded value.
		if _, err := h.s.arm(ctx); err != nil {
			t.Fatal(err)
		}
		restarted, err := NewServer(h.s.config)
		if err != nil {
			t.Fatal(err)
		}
		restarted.interfaces, restarted.addrs, restarted.container = h.s.interfaces, h.s.addrs, h.s.container
		h.s = restarted
		h.attach(restarted)
		if _, err := h.s.arm(ctx); err != nil {
			t.Fatal(err)
		}
		h.pins = map[string]bool{}
		delete(h.bridges, "bridge110")
		delete(h.bridges, "bridge111")
		if err := h.s.disarm(ctx); err != nil {
			t.Fatal(err)
		}
		if h.forwarding != before {
			t.Fatalf("disarm left forwarding %v, was %v before the first arm", h.forwarding, before)
		}
		if _, err := os.Stat(h.s.forwardingState()); !os.IsNotExist(err) {
			t.Fatalf("before=%v: forwarding state not removed: %v", before, err)
		}
		// A second disarm with nothing recorded leaves forwarding alone.
		writes := h.forwardingWrites
		if err := h.s.disarm(ctx); err != nil || h.forwarding != before || h.forwardingWrites != writes {
			t.Fatalf("before=%v: disarm without a record changed forwarding: %v", before, err)
		}
	}
}

func TestDisarmLeavesForwardingThatWasOnBeforeArm(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	h.forwarding = true // e.g. Internet Sharing
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	// The anchor was flushed by hand; disarm still settles forwarding.
	h.setLoaded("", "")
	h.pins = map[string]bool{}
	delete(h.bridges, "bridge110")
	delete(h.bridges, "bridge111")
	if err := h.s.disarm(ctx); err != nil || !h.forwarding || h.forwardingWrites != 0 {
		t.Fatalf("disarm turned off forwarding someone else had on: %v writes=%d", err, h.forwardingWrites)
	}
	if err := os.WriteFile(h.s.forwardingState(), []byte("maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.s.disarm(ctx); err == nil || !h.forwarding {
		t.Fatal("acted on an unreadable forwarding record")
	}
}

func TestBackgroundRefreshKeepsTheMacReachable(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	h.s.refresh(ctx) // no anchor: nothing to do
	if len(h.tables) != 0 {
		t.Fatal("refresh created a host table without an anchor")
	}
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	h.bridges["en0"] = []net.Addr{ipNet("192.168.7.40/24")}
	h.s.refresh(ctx)
	for _, addr := range []string{"192.168.7.40/32", "192.168.7.255/32"} {
		if !slices.Contains(h.tables[hostTable], netip.MustParsePrefix(addr)) {
			t.Errorf("refresh did not admit the Mac's new destination %s", addr)
		}
	}
	if slices.Contains(h.tables[hostTable], netip.MustParsePrefix("192.168.1.20/32")) {
		t.Error("refresh kept the Mac's old address")
	}
}

const guardRule = "block drop in quick on ! lo0 inet from any to ! <sandboxd_host>"

func (h *twoSlotHost) guarded() bool { return strings.Contains(h.filter, guardRule) }

func (h *twoSlotHost) drain() {
	h.pins = map[string]bool{}
	delete(h.bridges, "bridge110")
	delete(h.bridges, "bridge111")
}

// A record of 1 goes stale when the operator stops routing while armed:
// once the helper has to turn forwarding on, it owns it, guards it and
// restores it, both on the next arm and at the next refresh.
func TestHelperOwnsForwardingItHadToTurnOn(t *testing.T) {
	ctx := context.Background()
	for _, via := range []string{"arm", "refresh", "check"} {
		h := newTwoSlotHost(t, 0)
		h.forwarding = true // e.g. a Tailscale exit node
		if _, err := h.s.arm(ctx); err != nil || h.guarded() {
			t.Fatalf("%s: armed with a guard over the operator's routing: %v", via, err)
		}
		h.forwarding = false // the operator stops routing
		switch via {
		case "arm":
			_, err := h.s.arm(ctx)
			if err != nil {
				t.Fatal(err)
			}
		case "refresh":
			h.s.refresh(ctx)
		case "check":
			if _, err := h.s.check(ctx); err != nil {
				t.Fatalf("check refused while taking over forwarding: %v", err)
			}
		}
		if before, err := h.s.forwardingBefore(); err != nil || before != "0" || !h.forwarding || !h.guarded() {
			t.Fatalf("%s: did not take over forwarding: record %q forwarding=%v guard=%v %v", via, before, h.forwarding, h.guarded(), err)
		}
		if _, err := h.s.check(ctx); err != nil {
			t.Fatalf("%s: %v", via, err)
		}
		h.drain()
		if err := h.s.disarm(ctx); err != nil || h.forwarding {
			t.Fatalf("%s: disarm did not restore forwarding the helper turned on: %v", via, err)
		}
	}
}

// Another forwarder that starts after the first arm keeps working: with
// evidence of it (a translation rule outside the helper's anchor) the guard
// drops at the next check or refresh, comes back when it leaves, and disarm
// leaves forwarding on while it runs.
func TestAnotherForwardingUserKeepsForwarding(t *testing.T) {
	ctx := context.Background()
	const shareNAT = "nat on en0 inet from 192.168.2.0/24 to any -> (en0) round-robin\n"
	users := map[string]func(h *twoSlotHost, on bool){
		// vmnet shared mode and Internet Sharing NAT through an anchor
		// under com.apple (bridge100 alone proves nothing).
		"vmnet shared network": func(h *twoSlotHost, on bool) {
			h.anchors = nil
			delete(h.bridges, "bridge100")
			if on {
				h.bridges["bridge100"] = slotAddrs("192.168.64.1", "fd9a::1")
				h.anchors = map[string]string{"com.apple/internet-sharing/base_v4": shareNAT}
			}
		},
		"PF NAT in the main ruleset": func(h *twoSlotHost, on bool) {
			h.mainNAT = testMainNAT
			if on {
				h.mainNAT += shareNAT
			}
		},
		"PF NAT in another top-level anchor": func(h *twoSlotHost, on bool) {
			h.mainNAT, h.anchors = testMainNAT, nil
			if on {
				h.mainNAT += "nat-anchor \"vpn\" all\n"
				h.anchors = map[string]string{"vpn": shareNAT}
			}
		},
	}
	for name, use := range users {
		h := newTwoSlotHost(t, 0)
		if _, err := h.s.arm(ctx); err != nil || !h.guarded() {
			t.Fatalf("%s: helper-owned forwarding is not guarded: %v", name, err)
		}
		use(h, true)
		// Check reconciles itself, so sandboxd never sees a gap.
		if _, err := h.s.check(ctx); err != nil || h.guarded() {
			t.Fatalf("%s: guard not dropped for another forwarding user: %v", name, err)
		}
		use(h, false)
		h.s.refresh(ctx)
		if !h.guarded() {
			t.Fatalf("%s: guard not restored once the other user left", name)
		}
		use(h, true)
		h.s.refresh(ctx)
		if h.guarded() {
			t.Fatalf("%s: refresh kept the guard over another forwarding user", name)
		}
		// Arm also decides with the other user present.
		if _, err := h.s.arm(ctx); err != nil || h.guarded() {
			t.Fatalf("%s: re-arm guarded another forwarding user: %v", name, err)
		}
		h.drain()
		writes := h.forwardingWrites
		if err := h.s.disarm(ctx); err != nil || !h.forwarding || h.forwardingWrites != writes {
			t.Fatalf("%s: disarm turned off forwarding another service uses: %v", name, err)
		}
		if _, err := os.Stat(h.s.forwardingState()); !os.IsNotExist(err) {
			t.Fatalf("%s: forwarding record left behind: %v", name, err)
		}
	}
}

// A vmnet host-only bridge with an IPv4 address (Apple container's
// host-only networks, OrbStack's bridge without NAT) is no evidence of a
// forwarder: the guard stays and disarm turns forwarding back off. So do
// anchors that only filter or that cannot be read.
func TestHostOnlyBridgeKeepsTheGuard(t *testing.T) {
	ctx := context.Background()
	h := newTwoSlotHost(t, 0)
	h.bridges["bridge100"] = slotAddrs("192.168.64.1", "fd9a::1")
	h.bridges["bridge101"] = slotAddrs("192.168.139.1", "fd9b::1")
	h.anchors = map[string]string{"com.apple/250.ApplicationFirewall": "", "com.apple/200.AirDrop/Bonjour": "\n"}
	if _, err := h.s.arm(ctx); err != nil || !h.guarded() {
		t.Fatalf("a host-only bridge dropped the guard: %v", err)
	}
	h.s.refresh(ctx)
	if _, err := h.s.check(ctx); err != nil || !h.guarded() {
		t.Fatalf("check or refresh dropped the guard for a host-only bridge: %v", err)
	}
	h.drain()
	if err := h.s.disarm(ctx); err != nil || h.forwarding {
		t.Fatalf("disarm left the helper's forwarding on for a host-only bridge: %v", err)
	}
}

// Forwarding is never turned on while PF does not enforce the anchor, and
// forwarding the helper owns is turned off as soon as PF stops enforcing it.
func TestForwardingFollowsPFEnforcement(t *testing.T) {
	ctx := context.Background()
	stops := map[string]func(h *twoSlotHost, stop bool){
		"PF disabled": func(h *twoSlotHost, stop bool) { h.enabled = !stop },
		"main rules no longer call the NAT anchor": func(h *twoSlotHost, stop bool) {
			h.mainNAT = testMainNAT
			if stop {
				h.mainNAT = "rdr-anchor \"com.apple/*\" all\n"
			}
		},
		"anchor flushed": func(h *twoSlotHost, stop bool) {
			if stop {
				h.filter = ""
			}
		},
	}
	for name, stop := range stops {
		for _, via := range []string{"refresh", "check"} {
			h := newTwoSlotHost(t, 0)
			if _, err := h.s.arm(ctx); err != nil || !h.forwarding {
				t.Fatal(err)
			}
			armed := h.filter
			stop(h, true)
			if via == "refresh" {
				h.s.refresh(ctx)
			} else if _, err := h.s.check(ctx); err == nil {
				t.Fatalf("%s: check accepted an unenforced anchor", name)
			}
			if h.forwarding {
				t.Fatalf("%s via %s: forwarding the helper owns stayed on without PF enforcement", name, via)
			}
			// Something turns forwarding off and on again: still nothing
			// until PF enforces the anchor again.
			h.s.refresh(ctx)
			if _, err := h.s.check(ctx); err == nil || h.forwarding {
				t.Fatalf("%s via %s: forwarding turned on without PF enforcement: %v", name, via, err)
			}
			stop(h, false)
			h.filter = armed
			if _, err := h.s.check(ctx); err != nil || !h.forwarding {
				t.Fatalf("%s via %s: forwarding not back once PF enforces again: %v", name, via, err)
			}
		}
	}
	// The operator's own forwarding (record 1) is never turned off.
	h := newTwoSlotHost(t, 0)
	h.forwarding = true
	if _, err := h.s.arm(ctx); err != nil {
		t.Fatal(err)
	}
	h.enabled = false
	h.s.refresh(ctx)
	if !h.forwarding || h.forwardingWrites != 0 {
		t.Fatal("turned off the operator's forwarding")
	}
	// Arm refuses to turn forwarding on when the load did not take.
	h = newTwoSlotHost(t, 0)
	h.mainNAT = "rdr-anchor \"com.apple/*\" all\n"
	if _, err := h.s.arm(ctx); err == nil || h.forwarding {
		t.Fatalf("armed forwarding without the NAT anchor: %v", err)
	}
}
