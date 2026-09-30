package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
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

// twoSlotHost is a fake Mac with two slot networks, their pins and bridges.
type twoSlotHost struct {
	s          *Server
	bridges    map[string][]net.Addr // up bridge interfaces and their addresses
	extraVMs   []string              // additional Apple inventory items
	pins       map[string]bool       // slot network -> pin present
	network2   string                // inspect JSON for slot 2
	skipped    map[string]bool       // PF-skipped interfaces
	loaded     string                // anchor readback
	flushes    map[string]int        // per-bridge state flushes
	loadedText []string              // policy files handed to pfctl -f
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
		s:        s,
		bridges:  map[string][]net.Addr{"bridge110": slot1Addrs, "bridge111": slot2Addrs, "bridge100": slotAddrs("192.168.64.1", "fd9a::1")},
		pins:     map[string]bool{"sandboxd-slot-1": true, "sandboxd-slot-2": true},
		network2: networkJSON("sandboxd-slot-2", "192.168.131.1", "192.168.131.0/24", "fd1e:68b8:2ef4:5d02::/64"),
		skipped:  map[string]bool{},
		flushes:  map[string]int{},
	}
	s.interfaces = func() ([]net.Interface, error) {
		var out []net.Interface
		for _, name := range []string{"bridge100", "bridge110", "bridge111", "bridge112"} {
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
	s.pf = func(_ context.Context, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch {
		case command == "-s info":
			return []byte("Status: Enabled for 0 days\n"), nil
		case command == "-sr":
			return []byte(testMainRules), nil
		case strings.HasPrefix(command, "-s Interfaces -v -i "):
			name := args[4]
			if h.skipped[name] {
				return []byte(name + " (skip)\n"), nil
			}
			return []byte(name + "\n"), nil
		case command == "-a "+anchor+" -sr":
			return []byte(h.loaded), nil
		case command == "-a "+anchor+" -F rules":
			h.loaded = ""
			return nil, nil
		case strings.HasPrefix(command, "-F states -i "):
			h.flushes[args[3]]++
			return nil, nil
		case len(args) == 4 && args[0] == "-a" && args[1] == anchor && (args[2] == "-nf" || args[2] == "-f"):
			input, err := os.ReadFile(args[3])
			if err != nil {
				return nil, err
			}
			if args[2] == "-f" {
				h.loadedText = append(h.loadedText, string(input))
				// The readback of what the helper just loaded, for the bridges it named.
				h.loaded = s.canonicalPolicy(strings.Fields(bridgesIn(string(input))))
			}
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected PF command %v", args)
	}
	return h
}

// bridgesIn returns the bridge named by each slot's inet deny rule, in order.
func bridgesIn(policy string) string {
	var bridges []string
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(line, "block in quick on ") && strings.HasSuffix(line, " inet from any to any") {
			bridges = append(bridges, strings.TrimSuffix(strings.TrimPrefix(line, "block in quick on "), " inet from any to any"))
		}
	}
	return strings.Join(bridges, " ")
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
	const policy = "pass in quick on bridge110 inet proto tcp from 192.168.130.0/24 to 192.168.130.1 port 8443\n" +
		"block in quick on bridge110 inet from any to any\n" +
		"block in quick on bridge110 inet6 from any to any\n" +
		"pass in quick on bridge111 inet proto tcp from 192.168.131.0/24 to 192.168.131.1 port 8443\n" +
		"block in quick on bridge111 inet from any to any\n" +
		"block in quick on bridge111 inet6 from any to any\n"
	if len(h.loadedText) != 1 || h.loadedText[0] != policy {
		t.Fatalf("loaded policy is not the exact two-slot deny policy:\n%q", h.loadedText)
	}
	const readback = "pass in quick on bridge110 inet proto tcp from 192.168.130.0/24 to 192.168.130.1 port = 8443 flags S/SA keep state\n" +
		"block drop in quick on bridge110 inet all\n" +
		"block drop in quick on bridge110 inet6 all\n" +
		"pass in quick on bridge111 inet proto tcp from 192.168.131.0/24 to 192.168.131.1 port = 8443 flags S/SA keep state\n" +
		"block drop in quick on bridge111 inet all\n" +
		"block drop in quick on bridge111 inet6 all"
	if h.loaded != readback {
		t.Fatalf("unexpected two-slot readback:\n%s", h.loaded)
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

	// A slot-2 gateway exception granted to slot 1's subnet is a broadening.
	h.loaded = strings.Replace(readback, "from 192.168.131.0/24", "from 192.168.130.0/24", 1)
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a model pass crossing slots")
	}
	// Only one slot's rules loaded.
	h.loaded = h.s.canonicalPolicy([]string{"bridge110"})
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted an anchor that leaves slot 2 unguarded")
	}
	if _, err := h.s.arm(ctx); err == nil || !strings.Contains(err.Error(), "unexpected firewall policy") {
		t.Fatalf("replaced an unexpected partial anchor: %v", err)
	}
	h.loaded = readback

	h.skipped["bridge111"] = true
	if _, err := h.s.check(ctx); err == nil {
		t.Fatal("accepted a PF-skipped slot 2 bridge")
	}
	h.skipped["bridge111"] = false
	if _, err := h.s.check(ctx); err != nil {
		t.Fatal(err)
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
	if len(h.loadedText) != 0 || h.loaded != "" {
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
	armed := h.loaded
	h.pins["sandboxd-slot-1"] = false
	if err := h.s.disarm(ctx); err == nil || h.loaded != armed {
		t.Fatal("cleared PF while slot 2's pin still uses its network")
	}
	h.pins["sandboxd-slot-2"] = false
	delete(h.bridges, "bridge110")
	if err := h.s.disarm(ctx); err == nil || h.loaded != armed {
		t.Fatal("cleared PF while slot 2's bridge is present")
	}
	delete(h.bridges, "bridge111")
	h.loaded = armed + "\npass in quick on bridge111 inet all"
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an unexpected anchor")
	}
	h.loaded = h.s.canonicalPolicy([]string{"bridge110"})
	if err := h.s.disarm(ctx); err == nil {
		t.Fatal("cleared an anchor in a foreign shape")
	}
	h.loaded = armed
	if err := h.s.disarm(ctx); err != nil || h.loaded != "" {
		t.Fatalf("failed to clear the exact drained two-slot anchor: %v", err)
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
