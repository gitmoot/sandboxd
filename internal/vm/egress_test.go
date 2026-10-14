package vm

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestParseEgressTargets(t *testing.T) {
	got, err := ParseEgressTargets([]string{"8.8.8.8", "1.2.3.4/24", "1.2.3.0/24", "8.8.8.8/32", "0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	// Masked, sorted, deduplicated; an address is its /32.
	if want := prefixes(t, "0.0.0.0/0", "1.2.3.0/24", "8.8.8.8/32"); !slices.Equal(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	if got, err := ParseEgressTargets(nil); err != nil || len(got) != 0 {
		t.Fatalf("no entries parsed as %v, %v", got, err)
	}
	for entry, message := range map[string]string{
		"example.com":    `entry "example.com": only IPv4 addresses and CIDRs are supported (hostnames are not)`,
		"example.com/24": `entry "example.com/24": only IPv4 addresses and CIDRs are supported (hostnames are not)`,
		"*.example.com":  "hostnames are not",
		"2001:db8::1":    `entry "2001:db8::1": IPv6 is not supported`,
		"2001:db8::/32":  "IPv6 is not supported",
		"::ffff:1.2.3.4": "IPv6 is not supported",
		"":               `entry "": empty entry`,
		"300.1.2.3":      "not a valid IPv4 address",
		"1.2.3":          "not a valid IPv4 address",
		"1.2.3.4/33":     "not a valid IPv4 CIDR",
		" 1.2.3.4":       "hostnames are not",
	} {
		_, err := ParseEgressTargets([]string{"1.1.1.1", entry})
		if err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("entry %q: error %v, want one containing %q", entry, err, message)
		}
	}
	many := make([]string, maxEgressTargets+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.%d.1", i)
	}
	if _, err := ParseEgressTargets(many[:maxEgressTargets]); err != nil {
		t.Fatalf("%d entries refused: %v", maxEgressTargets, err)
	}
	if _, err := ParseEgressTargets(many); err == nil || !strings.Contains(err.Error(), "at most 64 entries") {
		t.Fatalf("%d entries: %v", len(many), err)
	}
}

func TestEgressPolicyApply(t *testing.T) {
	no, yes := false, true
	allow := prefixes(t, "9.9.9.9/32", "1.2.3.4/24", "1.2.3.0/24")
	deny := prefixes(t, "8.8.8.8/32")
	base := DefaultEgress()
	if !base.AllowInternet || base.Allow != nil || base.Deny != nil {
		t.Fatalf("default egress %+v", base)
	}
	if got := base.Apply(EgressUpdate{}); !egressEqual(got, base) {
		t.Fatalf("empty update changed %+v to %+v", base, got)
	}
	p := base.Apply(EgressUpdate{Allow: &allow})
	if !p.AllowInternet || !slices.Equal(p.Allow, prefixes(t, "1.2.3.0/24", "9.9.9.9/32")) || p.Deny != nil {
		t.Fatalf("allow update: %+v", p)
	}
	if allow[0] != netip.MustParsePrefix("9.9.9.9/32") {
		t.Fatal("Apply reordered the caller's slice")
	}
	// Omitted fields keep their value: no update silently reopens anything.
	p = p.Apply(EgressUpdate{AllowInternet: &no})
	if p.AllowInternet || len(p.Allow) != 2 {
		t.Fatalf("internet update dropped allow: %+v", p)
	}
	p = p.Apply(EgressUpdate{Deny: &deny})
	if p.AllowInternet || len(p.Allow) != 2 || !slices.Equal(p.Deny, deny) {
		t.Fatalf("deny update: %+v", p)
	}
	// An explicitly empty list clears it.
	empty := []netip.Prefix{}
	p = p.Apply(EgressUpdate{AllowInternet: &yes, Allow: &empty})
	if !p.AllowInternet || p.Allow != nil || !slices.Equal(p.Deny, deny) {
		t.Fatalf("clearing update: %+v", p)
	}
	if err := validEgress(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidEgress(t *testing.T) {
	for name, policy := range map[string]EgressPolicy{
		"unmasked":  {Allow: prefixes(t, "1.2.3.4/24")},
		"ipv6":      {Deny: prefixes(t, "2001:db8::/32")},
		"unsorted":  {Allow: prefixes(t, "9.9.9.9/32", "1.1.1.1/32")},
		"duplicate": {Deny: prefixes(t, "1.1.1.1/32", "1.1.1.1/32")},
		"invalid":   {Allow: []netip.Prefix{{}}},
		"too many":  {Allow: make([]netip.Prefix, maxEgressTargets+1)},
	} {
		if validEgress(policy) == nil {
			t.Errorf("%s policy accepted", name)
		}
	}
}

func egressEqual(a, b EgressPolicy) bool {
	return a.AllowInternet == b.AllowInternet && slices.Equal(a.Allow, b.Allow) && slices.Equal(a.Deny, b.Deny)
}
