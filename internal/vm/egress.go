package vm

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// maxEgressTargets bounds Allow and Deny: each entry is an nftables set
// element, and E2B clients send short lists.
const maxEgressTargets = 64

// EgressPolicy is a sandbox's public egress, on top of the always-denied set.
// AllowInternet false = deny all public egress (E2B allow_internet_access:false ≡ denyOut 0.0.0.0/0).
// A destination is reachable iff not always-denied AND (in Allow OR (AllowInternet AND not in Deny)).
// Allow/Deny are IPv4 prefixes only (guests have no IPv6), canonical (Masked), deduplicated, sorted, at most 64 each.
// The JSON names are those of the Firecracker ownership record.
type EgressPolicy struct {
	AllowInternet bool           `json:"allowInternet"`
	Allow         []netip.Prefix `json:"allow,omitempty"`
	Deny          []netip.Prefix `json:"deny,omitempty"`
}

// DefaultEgress is what a sandbox without a policy has: {AllowInternet: true}.
func DefaultEgress() EgressPolicy { return EgressPolicy{AllowInternet: true} }

// Equal reports whether p and q enforce the same policy (both canonical).
func (p EgressPolicy) Equal(q EgressPolicy) bool {
	return p.AllowInternet == q.AllowInternet && slices.Equal(p.Allow, q.Allow) && slices.Equal(p.Deny, q.Deny)
}

// EgressUpdate changes only the fields that are non-nil; omitted fields keep the current value
// (sandboxd deliberately differs from E2B, whose update clears omitted fields: an update must never silently reopen the internet).
type EgressUpdate struct {
	AllowInternet *bool
	Allow, Deny   *[]netip.Prefix
}

// Apply returns p with u's set fields replaced, Allow and Deny canonical
// (masked, sorted, deduplicated, nil when empty) and never sharing memory
// with p or u.
func (p EgressPolicy) Apply(u EgressUpdate) EgressPolicy {
	out := EgressPolicy{AllowInternet: p.AllowInternet, Allow: canonicalPrefixes(p.Allow), Deny: canonicalPrefixes(p.Deny)}
	if u.AllowInternet != nil {
		out.AllowInternet = *u.AllowInternet
	}
	if u.Allow != nil {
		out.Allow = canonicalPrefixes(*u.Allow)
	}
	if u.Deny != nil {
		out.Deny = canonicalPrefixes(*u.Deny)
	}
	return out
}

func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.Masked()
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return slices.Compact(out)
}

// validEgress reports whether p is a policy a driver may enforce: IPv4
// prefixes only, each list canonical and within the limit. Drivers check
// every policy they install or read back from their own records.
func validEgress(p EgressPolicy) error {
	for _, list := range [][]netip.Prefix{p.Allow, p.Deny} {
		if len(list) > maxEgressTargets {
			return fmt.Errorf("egress policy lists at most %d prefixes", maxEgressTargets)
		}
		for i, prefix := range list {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return fmt.Errorf("egress policy prefix %q is not a canonical IPv4 prefix", prefix)
			}
			if i > 0 && list[i-1].Compare(prefix) >= 0 {
				return errors.New("egress policy prefixes are not sorted and unique")
			}
		}
	}
	return nil
}

// ParseEgressTargets parses E2B allowOut/denyOut entries: IPv4 address or IPv4 CIDR. Hostnames, IPv6, >64 entries -> error with a client-facing message.
// An address is its /32; a CIDR's host bits are cleared (1.2.3.4/24 is
// 1.2.3.0/24). The result is canonical (sorted, deduplicated). Messages
// name the entry but not the field, so callers prefix it ("allowOut ").
func ParseEgressTargets(entries []string) ([]netip.Prefix, error) {
	if len(entries) > maxEgressTargets {
		return nil, fmt.Errorf("at most %d entries are supported, got %d", maxEgressTargets, len(entries))
	}
	out := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := parseEgressTarget(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", entry, err)
		}
		out = append(out, prefix)
	}
	return canonicalPrefixes(out), nil
}

func parseEgressTarget(entry string) (netip.Prefix, error) {
	if entry == "" {
		return netip.Prefix{}, errors.New("empty entry")
	}
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		switch {
		case err == nil && prefix.Addr().Is4():
			return prefix.Masked(), nil
		case err == nil || strings.Contains(entry, ":"):
			return netip.Prefix{}, errors.New("IPv6 is not supported (sandboxes have no IPv6)")
		case isIPv4ish(entry[:strings.IndexByte(entry, '/')]):
			return netip.Prefix{}, errors.New("not a valid IPv4 CIDR")
		}
		return netip.Prefix{}, errors.New("only IPv4 addresses and CIDRs are supported (hostnames are not)")
	}
	addr, err := netip.ParseAddr(entry)
	switch {
	case err == nil && addr.Is4():
		return netip.PrefixFrom(addr, 32), nil
	case err == nil || strings.Contains(entry, ":"):
		return netip.Prefix{}, errors.New("IPv6 is not supported (sandboxes have no IPv6)")
	case isIPv4ish(entry):
		return netip.Prefix{}, errors.New("not a valid IPv4 address")
	}
	return netip.Prefix{}, errors.New("only IPv4 addresses and CIDRs are supported (hostnames are not)")
}

// isIPv4ish is a malformed address rather than a hostname: digits and dots
// only (300.1.2.3, 1.2.3).
func isIPv4ish(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.") == ""
}

// ErrEgressUnsupported refuses a Spec.Egress on a driver or worker that
// cannot enforce it: a policy is never silently ignored.
var ErrEgressUnsupported = errors.New("per-sandbox egress policy is not supported by this worker")

// ErrNoVM is wrapped by EgressPolicies for an unknown sandbox ID.
var ErrNoVM = errors.New("VM not found")

// EgressPolicies is implemented by drivers that enforce per-sandbox egress (Firecracker only).
type EgressPolicies interface {
	// Egress returns the sandbox's current policy (DefaultEgress for one created without).
	Egress(ctx context.Context, id string) (EgressPolicy, error)
	// UpdateEgress atomically merges u into the current policy, enforces it, records it, and returns the result.
	UpdateEgress(ctx context.Context, id string, u EgressUpdate) (EgressPolicy, error)
}
