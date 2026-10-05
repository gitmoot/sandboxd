package firewall

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Tables in the helper's anchor. The deny and guest tables are const; the
// host table follows the Mac's addresses (syncHostTable).
const (
	denyTable   = "sandboxd_deny"
	hostTable   = "sandboxd_host"
	guestsTable = "sandboxd_guests"
)

// egressName is a NAT interface: a plain macOS interface name, never a
// guest bridge or loopback.
var egressName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

func validEgress(name string) bool {
	return egressName.MatchString(name) && !bridgeName.MatchString(name) && !strings.HasPrefix(name, "lo")
}

// slotRules is one slot's share of the anchor. Internet false is the
// per-slot deny-all mode kept for allow_internet_access:false (M4): such a
// slot keeps only the model relay exception.
type slotRules struct {
	Bridge   string
	Subnet   netip.Prefix
	Internet bool
}

type policyInput struct {
	Slots     []slotRules
	RelayAddr netip.Addr
	// RelayPort zero means no relay exception.
	RelayPort int
	// Egress is the NAT interface, required when any slot has Internet.
	Egress string
	Deny   []netip.Prefix
	Host   []netip.Prefix
}

// pfPolicy is the anchor file the helper loads and pfctl's readback of it:
// Filter is `pfctl -a <anchor> -sr`, NAT is `pfctl -a <anchor> -sn`.
type pfPolicy struct {
	Load, Filter, NAT string
}

// render builds the guest egress policy. On each slot bridge, in order:
// the relay port on the first slot's gateway; deny the shared private and
// special ranges (internal/egress) and every Mac address; pass the slot's
// own subnet to the rest of the internet, NATed out of Egress; drop all
// other IPv4 and all IPv6. Every slot bridge packet stops there. Then,
// for every other interface: nothing reaches a guest subnet, and IPv4 that
// is not for the Mac itself (the host table) is dropped, so the IP
// forwarding guest NAT needs never routes a LAN or VPN host through the Mac.
// Loopback is left alone. Guests on another slot are in the private ranges,
// so they are denied in both directions by each bridge's own rules.
func render(in policyInput) pfPolicy {
	var load, filter, nat []string
	guests := make([]netip.Prefix, len(in.Slots))
	for i, slot := range in.Slots {
		guests[i] = slot.Subnet
	}
	load = append(load,
		"table <"+denyTable+"> const persist"+tableList(in.Deny),
		"table <"+hostTable+"> persist"+tableList(in.Host),
		"table <"+guestsTable+"> const persist"+tableList(guests))
	for _, slot := range in.Slots {
		if slot.Internet {
			rule := "nat on " + in.Egress + " inet from " + slot.Subnet.String() + " to any -> (" + in.Egress + ")"
			load = append(load, rule)
			nat = append(nat, rule+" round-robin")
		}
	}
	for _, slot := range in.Slots {
		on := " quick on " + slot.Bridge
		if in.RelayPort != 0 {
			relay := " inet proto tcp from " + slot.Subnet.String() + " to " + in.RelayAddr.String() + " port "
			load = append(load, "pass in"+on+relay+strconv.Itoa(in.RelayPort))
			filter = append(filter, "pass in"+on+relay+"= "+strconv.Itoa(in.RelayPort)+" flags S/SA keep state")
		}
		if slot.Internet {
			load = append(load,
				"block in"+on+" inet from any to <"+denyTable+">",
				"block in"+on+" inet from any to <"+hostTable+">",
				"pass in"+on+" inet from "+slot.Subnet.String()+" to any")
			filter = append(filter,
				"block drop in"+on+" inet from any to <"+denyTable+">",
				"block drop in"+on+" inet from any to <"+hostTable+">",
				"pass in"+on+" inet from "+slot.Subnet.String()+" to any flags S/SA keep state")
		}
		load = append(load, "block in"+on+" inet from any to any", "block in"+on+" inet6 from any to any")
		filter = append(filter, "block drop in"+on+" inet all", "block drop in"+on+" inet6 all")
	}
	load = append(load, "block in quick inet from any to <"+guestsTable+">",
		"block in quick on ! lo0 inet from any to ! <"+hostTable+">")
	filter = append(filter, "block drop in quick inet from any to <"+guestsTable+">",
		"block drop in quick on ! lo0 inet from any to ! <"+hostTable+">")
	return pfPolicy{Load: strings.Join(load, "\n") + "\n", Filter: strings.Join(filter, "\n"), NAT: strings.Join(nat, "\n")}
}

func tableList(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return ""
	}
	items := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		items[i] = prefixText(prefix)
	}
	return " { " + strings.Join(items, ", ") + " }"
}

// prefixText writes a single address without its full-length mask, as
// pfctl -T show prints it.
func prefixText(prefix netip.Prefix) string {
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}
	return prefix.String()
}

// legacyFilter is pfctl's readback of the deny-all anchor that helpers
// before guest egress (v0.1.x) loaded: no tables and no NAT. Arm replaces
// it and disarm clears it, so an update needs no manual PF flush.
func legacyFilter(bridges []string, relayAddr netip.Addr, subnets []netip.Prefix, relayPort int) string {
	var lines []string
	for i, bridge := range bridges {
		if relayPort != 0 {
			lines = append(lines, "pass in quick on "+bridge+" inet proto tcp from "+subnets[i].String()+
				" to "+relayAddr.String()+" port = "+strconv.Itoa(relayPort)+" flags S/SA keep state")
		}
		lines = append(lines, "block drop in quick on "+bridge+" inet all", "block drop in quick on "+bridge+" inet6 all")
	}
	return strings.Join(lines, "\n")
}

// filterBridges recovers the bridges, in slot order, of an anchor in any
// shape this helper loads (each slot ends with its IPv4 drop-all rule).
// Callers still require an exact match against one of those shapes.
func filterBridges(filter string, slots int) ([]string, bool) {
	var bridges []string
	for _, line := range strings.Split(filter, "\n") {
		bridge, prefixed := strings.CutPrefix(line, "block drop in quick on ")
		bridge, suffixed := strings.CutSuffix(bridge, " inet all")
		if prefixed && suffixed {
			if !bridgeName.MatchString(bridge) || slices.Contains(bridges, bridge) {
				return nil, false
			}
			bridges = append(bridges, bridge)
		}
	}
	return bridges, len(bridges) == slots
}

// natEgress recovers the NAT interface from pfctl's readback of this
// helper's NAT rules; "" for none.
func natEgress(nat string) (string, bool) {
	if nat == "" {
		return "", true
	}
	first, _, _ := strings.Cut(nat, "\n")
	rest, ok := strings.CutPrefix(first, "nat on ")
	name, _, found := strings.Cut(rest, " ")
	if !ok || !found || !validEgress(name) {
		return "", false
	}
	return name, true
}

// parseTable reads `pfctl -t <table> -T show` output as a set of prefixes.
func parseTable(out string) ([]netip.Prefix, bool) {
	var prefixes []netip.Prefix
	for _, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			addr, err := netip.ParseAddr(text)
			if err != nil {
				return nil, false
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, true
}

// samePrefixes compares two prefix sets regardless of order.
func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	sorted := func(p []netip.Prefix) []netip.Prefix {
		p = slices.Clone(p)
		slices.SortFunc(p, func(x, y netip.Prefix) int {
			if c := x.Addr().Compare(y.Addr()); c != 0 {
				return c
			}
			return x.Bits() - y.Bits()
		})
		return p
	}
	return slices.Equal(sorted(a), sorted(b))
}
