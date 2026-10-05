// Package egress is the guest egress policy shared by every worker driver:
// the Linux Firecracker nftables tables and the Mac PF helper's anchor.
// Guests reach the public internet; the prefixes here never.
package egress

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// denyIPv4 and denyIPv6 are private, carrier-grade NAT (and Tailscale),
// link-local, loopback and non-unicast ranges, plus the one well-known cloud
// metadata service on a public address (Azure WireServer). Each driver denies
// the host's own addresses separately. Other providers' public metadata
// endpoints are added per deployment (-fc-deny-cidr, the helper's -deny-cidr).
var denyIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

var denyIPv6 = []netip.Prefix{
	netip.MustParsePrefix("::/127"),
	netip.MustParsePrefix("::ffff:0.0.0.0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// PublicResolvers are the guests' DNS servers, reached through the NAT like
// any other internet host. Host resolvers stay unreachable on every worker.
// images/linux-amd64-fc/build.sh writes the same pair into the Firecracker
// image's /etc/resolv.conf.
var PublicResolvers = [...]string{"1.1.1.1", "8.8.8.8"}

// Deny returns the always-denied prefixes by address family, followed by
// extra (each a valid network prefix), without duplicates.
func Deny(extra []netip.Prefix) (ipv4, ipv6 []netip.Prefix, err error) {
	ipv4 = slices.Clone(denyIPv4)
	ipv6 = slices.Clone(denyIPv6)
	for _, prefix := range extra {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return nil, nil, fmt.Errorf("deny CIDR %q is not a network prefix", prefix)
		}
		into := &ipv6
		if prefix.Addr().Is4() {
			into = &ipv4
		}
		if !slices.Contains(*into, prefix) {
			*into = append(*into, prefix)
		}
	}
	return ipv4, ipv6, nil
}

// PrefixFlags is a repeatable network prefix flag (-fc-deny-cidr, -deny-cidr).
type PrefixFlags []netip.Prefix

func (p *PrefixFlags) String() string {
	if p == nil {
		return ""
	}
	values := make([]string, len(*p))
	for i, prefix := range *p {
		values[i] = prefix.String()
	}
	return strings.Join(values, ",")
}

func (p *PrefixFlags) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	if prefix != prefix.Masked() {
		return fmt.Errorf("%s is not a network prefix (want %s)", value, prefix.Masked())
	}
	*p = append(*p, prefix)
	return nil
}
