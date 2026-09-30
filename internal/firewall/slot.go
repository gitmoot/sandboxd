package firewall

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
)

// MaxSlots bounds the helper's per-request work: every Check inspects each
// slot network and PF interface within one request timeout.
const MaxSlots = 16

// Slot is one root-configured Apple host-only network reserved for at most
// one guest at a time. Guests on one Apple network can reach each other and
// PF cannot see that bridge-internal traffic; separate host-only networks
// cannot, so concurrency is bounded by the number of slots.
type Slot struct {
	Network string
	IPv4    netip.Prefix
	Gateway netip.Addr
	IPv6    netip.Prefix
}

// ParseSlot accepts exactly
// name=<network>,ipv4=<subnet>,gw=<gateway>,ipv6=<ula-prefix>
// with each key once, in any order.
func ParseSlot(value string) (Slot, error) {
	fields := make(map[string]string, 4)
	for _, part := range strings.Split(value, ",") {
		key, field, ok := strings.Cut(part, "=")
		if !ok || field == "" {
			return Slot{}, fmt.Errorf("slot %q: expected key=value fields", value)
		}
		switch key {
		case "name", "ipv4", "gw", "ipv6":
		default:
			return Slot{}, fmt.Errorf("slot %q: unknown field %q", value, key)
		}
		if _, duplicate := fields[key]; duplicate {
			return Slot{}, fmt.Errorf("slot %q: duplicate field %q", value, key)
		}
		fields[key] = field
	}
	if len(fields) != 4 {
		return Slot{}, fmt.Errorf("slot %q: name, ipv4, gw and ipv6 are all required", value)
	}
	slot := Slot{Network: fields["name"]}
	if !ownedName.MatchString(slot.Network) || slot.Network == "default" {
		return Slot{}, fmt.Errorf("slot %q: invalid owned Apple network name", value)
	}
	var err error
	slot.Gateway, err = netip.ParseAddr(fields["gw"])
	if err != nil || !slot.Gateway.Is4() || !slot.Gateway.IsPrivate() {
		return Slot{}, fmt.Errorf("slot %q: gateway must be a private IPv4 address", value)
	}
	slot.IPv4, err = netip.ParsePrefix(fields["ipv4"])
	if err != nil || !slot.IPv4.Addr().Is4() || slot.IPv4.Masked() != slot.IPv4 ||
		!slot.IPv4.Contains(slot.Gateway) || slot.IPv4.Bits() < 24 || slot.IPv4.Bits() > 30 {
		return Slot{}, fmt.Errorf("slot %q: IPv4 subnet must be a canonical /16 to /30 containing the gateway", value)
	}
	slot.IPv6, err = netip.ParsePrefix(fields["ipv6"])
	if err != nil || !slot.IPv6.Addr().Is6() || slot.IPv6.Bits() < 48 || slot.IPv6.Bits() > 64 ||
		slot.IPv6.Masked() != slot.IPv6 || !slot.IPv6.Addr().IsPrivate() {
		return Slot{}, fmt.Errorf("slot %q: IPv6 network must be a canonical private /48 to /64 prefix", value)
	}
	return slot, nil
}

func (s Slot) String() string {
	return "name=" + s.Network + ",ipv4=" + s.IPv4.String() + ",gw=" + s.Gateway.String() + ",ipv6=" + s.IPv6.String()
}

// ValidateSlots requires distinct networks whose address ranges never
// overlap, so each bridge is attributable to exactly one slot.
func ValidateSlots(slots []Slot) error {
	if len(slots) == 0 || len(slots) > MaxSlots {
		return fmt.Errorf("between 1 and %d network slots are required", MaxSlots)
	}
	for i, a := range slots {
		if !ownedName.MatchString(a.Network) || a.Network == "default" || !a.IPv4.IsValid() || !a.IPv6.IsValid() || !a.Gateway.IsValid() {
			return fmt.Errorf("slot %d is not a parsed network slot", i+1)
		}
		for _, b := range slots[:i] {
			if a.Network == b.Network {
				return fmt.Errorf("network slot %q is configured twice", a.Network)
			}
			if a.IPv4.Overlaps(b.IPv4) || a.IPv6.Overlaps(b.IPv6) {
				return fmt.Errorf("network slots %q and %q overlap", b.Network, a.Network)
			}
		}
	}
	return nil
}

// SlotFlags is a repeatable --slot flag value.
type SlotFlags []Slot

func (f *SlotFlags) String() string {
	if f == nil {
		return ""
	}
	parts := make([]string, len(*f))
	for i, slot := range *f {
		parts[i] = slot.String()
	}
	return strings.Join(parts, " ")
}

func (f *SlotFlags) Set(value string) error {
	slot, err := ParseSlot(value)
	if err != nil {
		return err
	}
	*f = append(*f, slot)
	return nil
}

// Networks returns the slot network names in configured order.
func (f SlotFlags) Networks() []string {
	names := make([]string, len(f))
	for i, slot := range f {
		names[i] = slot.Network
	}
	return names
}

// PinID names the trusted pin VM that keeps one slot's bridge alive. The
// helper and the driver derive it identically; neither accepts it from input.
func PinID(workerID, network string) string {
	hash := sha256.Sum256([]byte(workerID + "/" + network))
	return fmt.Sprintf("sandboxd-pin-%x", hash[:8])
}
