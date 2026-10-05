package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/egress"
)

const anchor = "com.apple/gitmoot-sandboxd"

var bridgeName = regexp.MustCompile(`^bridge[0-9]+$`)
var ownedName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var imageDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// Config is supplied by root-owned launchd configuration, never by the worker.
// Each slot pins one dedicated host-only network's bridge addresses and ULA prefix.
type Config struct {
	SocketPath   string
	WorkerUID    int
	WorkerGID    int
	WorkerHome   string
	WorkerID     string
	ContainerCLI string
	Slots        []Slot
	PinImage     string
	// ModelRelayPort enables only a fixed IPv4 TCP exception from each slot's
	// subnet to the first slot's gateway (the one relay address). Zero keeps
	// the anchor deny-only until the mTLS broker and lease are ready.
	ModelRelayPort  int
	MainRulesSHA256 string
	// DenyCIDRs extends the shared guest deny list (internal/egress), for
	// example with a provider's metadata endpoint on a public address.
	DenyCIDRs []netip.Prefix
	// EgressInterface is the interface guest traffic is NATed out of; empty
	// means the Mac's default route interface when sandboxd arms.
	EgressInterface string
}

type Server struct {
	config     Config
	mainHash   [sha256.Size]byte
	deny       []netip.Prefix
	interfaces func() ([]net.Interface, error)
	addrs      func(net.Interface) ([]net.Addr, error)
	pf         func(context.Context, ...string) ([]byte, error)
	container  func(context.Context, ...string) ([]byte, error)
	// run executes a fixed system tool (route, sysctl).
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// mu serializes requests with the background host table refresh.
	mu sync.Mutex
}

func NewServer(cfg Config) (*Server, error) {
	if !filepath.IsAbs(cfg.SocketPath) || filepath.Clean(cfg.SocketPath) != cfg.SocketPath ||
		strings.ContainsRune(cfg.SocketPath, 0) || cfg.WorkerUID <= 0 || cfg.WorkerGID < 0 {
		return nil, fmt.Errorf("invalid firewall helper socket or worker identity")
	}
	if !filepath.IsAbs(cfg.WorkerHome) || filepath.Clean(cfg.WorkerHome) != cfg.WorkerHome ||
		!filepath.IsAbs(cfg.ContainerCLI) || filepath.Clean(cfg.ContainerCLI) != cfg.ContainerCLI ||
		!ownedName.MatchString(cfg.WorkerID) || !imageDigest.MatchString(cfg.PinImage) {
		return nil, fmt.Errorf("invalid root-configured worker or trusted pin image")
	}
	if err := ValidateSlots(cfg.Slots); err != nil {
		return nil, err
	}
	if cfg.ModelRelayPort != 0 && (cfg.ModelRelayPort < 1024 || cfg.ModelRelayPort > 65535) {
		return nil, fmt.Errorf("model relay port must be 1024-65535 or zero to deny all")
	}
	rawHash, err := hex.DecodeString(cfg.MainRulesSHA256)
	if err != nil || len(rawHash) != sha256.Size {
		return nil, fmt.Errorf("root-configured PF main rules SHA-256 is required")
	}
	deny4, deny6, err := egress.Deny(cfg.DenyCIDRs)
	if err != nil {
		return nil, err
	}
	if cfg.EgressInterface != "" && !validEgress(cfg.EgressInterface) {
		return nil, fmt.Errorf("egress interface %q must be a Mac interface name other than a bridge or loopback", cfg.EgressInterface)
	}
	cfg.Slots = append([]Slot(nil), cfg.Slots...)
	cfg.DenyCIDRs = append([]netip.Prefix(nil), cfg.DenyCIDRs...)
	s := &Server{config: cfg, deny: append(deny4, deny6...), interfaces: net.Interfaces,
		addrs: func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }}
	copy(s.mainHash[:], rawHash)
	s.pf = func(ctx context.Context, args ...string) ([]byte, error) { return runTool(ctx, "/sbin/pfctl", args...) }
	s.container = s.runContainer
	s.run = runTool
	return s, nil
}

func runTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("%s %s: %w", filepath.Base(name), strings.Join(args, " "), err)
	}
	return out, nil
}

// discover attributes each up bridge to at most one slot by that slot's exact
// IPv4 gateway, ULA prefix and a link-local address. The result has one entry
// per slot in configured order; "" means that slot's bridge is absent.
func (s *Server) discover() ([]string, error) {
	interfaces, err := s.interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate Mac interfaces: %w", err)
	}
	found := make([]string, len(s.config.Slots))
	for _, iface := range interfaces {
		if !bridgeName.MatchString(iface.Name) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := s.addrs(iface)
		if err != nil {
			return nil, fmt.Errorf("read %s addresses: %w", iface.Name, err)
		}
		var prefixes []netip.Prefix
		var linkLocal bool
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			prefixes = append(prefixes, prefix)
			linkLocal = linkLocal || prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast()
		}
		if !linkLocal {
			continue
		}
		matched := false
		for i, slot := range s.config.Slots {
			var ipv4, ula bool
			for _, prefix := range prefixes {
				ip := prefix.Addr()
				ipv4 = ipv4 || ip == slot.Gateway && prefix.Masked() == slot.IPv4
				ula = ula || ip.Is6() && prefix.Masked() == slot.IPv6
			}
			if !ipv4 || !ula {
				continue
			}
			if matched {
				return nil, fmt.Errorf("bridge %s matches more than one sandbox network slot", iface.Name)
			}
			if found[i] != "" {
				return nil, fmt.Errorf("multiple bridges match sandbox network %s", slot.Network)
			}
			matched = true
			found[i] = iface.Name
		}
	}
	return found, nil
}

// attested requires a discovered bridge for every slot.
func (s *Server) attested() ([]string, error) {
	bridges, err := s.discover()
	if err != nil {
		return nil, err
	}
	for i, bridge := range bridges {
		if bridge == "" {
			return nil, fmt.Errorf("%s for network %s", bridgeNotReady, s.config.Slots[i].Network)
		}
	}
	return bridges, nil
}

// relayAddress is the one Mac address every slot's guests may reach on the
// model relay port: the first slot's gateway. Gitmoot advertises a single
// credential gateway URL whose certificate names one IP, so guests on other
// slots reach it through their own gateway and the Mac delivers it locally.
func (s *Server) relayAddress() netip.Addr {
	return s.config.Slots[0].Gateway
}

func (s *Server) subnets() []netip.Prefix {
	subnets := make([]netip.Prefix, len(s.config.Slots))
	for i, slot := range s.config.Slots {
		subnets[i] = slot.IPv4
	}
	return subnets
}

// policyFor is the anchor for bridges, one per slot in slot order. Every
// slot has internet egress; render's per-slot deny-all mode is not wired to
// sandboxes yet. host only fills the loaded host table: the readback does
// not depend on it. guard adds the forwarding guard (guardForwarding).
func (s *Server) policyFor(bridges []string, egress string, relayPort int, host []netip.Prefix, guard bool) pfPolicy {
	slots := make([]slotRules, len(bridges))
	for i, bridge := range bridges {
		slots[i] = slotRules{Bridge: bridge, Subnet: s.config.Slots[i].IPv4, Internet: true}
	}
	return render(policyInput{Slots: slots, RelayAddr: s.relayAddress(), RelayPort: relayPort,
		Egress: egress, Deny: s.deny, Host: host, GuardForwarding: guard})
}

// known reports whether the loaded anchor is, for bridges, one this helper
// loads (any egress interface) or the deny-all anchor of helpers before
// guest egress, with the relay off or on the configured port. Arm replaces
// such an anchor in one pfctl transaction, so the bridges are never
// unguarded; disarm clears it. Anything else stays.
func (s *Server) known(bridges []string, filter, nat string) bool {
	egress, ok := natEgress(nat)
	if !ok {
		return false
	}
	for _, port := range []int{0, s.config.ModelRelayPort} {
		if nat == "" && filter == legacyFilter(bridges, s.relayAddress(), s.subnets(), port) {
			return true
		}
		if egress != "" {
			for _, guard := range []bool{true, false} {
				if p := s.policyFor(bridges, egress, port, nil, guard); filter == p.Filter && nat == p.NAT {
					return true
				}
			}
		}
	}
	return false
}

// egressInterface is the interface guest traffic is NATed out of: the
// configured one, or the Mac's default route interface at arm time.
func (s *Server) egressInterface(ctx context.Context) (string, error) {
	if s.config.EgressInterface != "" {
		return s.config.EgressInterface, nil
	}
	out, err := s.run(ctx, "/sbin/route", "-n", "get", "default")
	if err != nil {
		return "", fmt.Errorf("find the Mac's default route for guest NAT (or set --egress-interface): %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			name = strings.TrimSpace(name)
			if !validEgress(name) {
				return "", fmt.Errorf("the Mac's default route uses %q, not a NAT interface; set --egress-interface", name)
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("the Mac has no default route interface for guest NAT; set --egress-interface")
}

// hostAddrs is every IPv4 and IPv6 destination the Mac itself receives on:
// each address on every interface (LAN, Tailscale, bridges, loopback,
// public) as a single-address prefix, each IPv4 subnet's broadcast address,
// 255.255.255.255 and IPv4 multicast. Guests are denied all of it; on every
// other interface IPv4 may reach only it, so forwarding serves only guests.
// IPv6 link-local addresses are scoped and left out: guest IPv6 is dropped
// whole and the helper never enables IPv6 forwarding.
func (s *Server) hostAddrs() ([]netip.Prefix, error) {
	interfaces, err := s.interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate Mac interfaces: %w", err)
	}
	addrs := []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}
	add := func(prefix netip.Prefix) {
		if !slices.Contains(addrs, prefix) {
			addrs = append(addrs, prefix)
		}
	}
	for _, iface := range interfaces {
		ifaceAddrs, err := s.addrs(iface)
		if err != nil {
			return nil, fmt.Errorf("read %s addresses: %w", iface.Name, err)
		}
		for _, addr := range ifaceAddrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is6() && ip.IsLinkLocalUnicast() {
				continue
			}
			add(netip.PrefixFrom(ip, ip.BitLen()))
			if ip.Is4() && prefix.Bits() < 31 {
				broadcast := prefix.Masked().Addr().As4()
				for i := prefix.Bits(); i < 32; i++ {
					broadcast[i/8] |= 0x80 >> (i % 8)
				}
				add(netip.PrefixFrom(netip.AddrFrom4(broadcast), 32))
			}
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return addrs, nil
}

func (s *Server) table(ctx context.Context, name string) ([]netip.Prefix, error) {
	out, err := s.pf(ctx, "-a", anchor, "-t", name, "-T", "show")
	if err != nil {
		return nil, err
	}
	prefixes, ok := parseTable(string(out))
	if !ok {
		return nil, fmt.Errorf("unreadable PF table %s: %q", name, truncate(string(out), 200))
	}
	return prefixes, nil
}

// constTablesExact reports whether the deny and guest tables hold exactly
// the configured prefixes.
func (s *Server) constTablesExact(ctx context.Context) (bool, error) {
	for _, t := range []struct {
		name string
		want []netip.Prefix
	}{{denyTable, s.deny}, {guestsTable, s.subnets()}} {
		got, err := s.table(ctx, t.name)
		if err != nil {
			return false, err
		}
		if !samePrefixes(got, t.want) {
			return false, nil
		}
	}
	return true, nil
}

// verifyTables requires the exact deny and guest tables and brings the host
// table up to date: a new Mac address (DHCP, Tailscale) is denied to guests
// within one check.
func (s *Server) verifyTables(ctx context.Context) error {
	exact, err := s.constTablesExact(ctx)
	if err != nil {
		return err
	}
	if !exact {
		return fmt.Errorf("PF tables %s and %s do not hold exactly the configured prefixes", denyTable, guestsTable)
	}
	return s.syncHostTable(ctx)
}

// syncHostTable replaces the host table when the Mac's addresses changed.
// The anchor's last rule only lets IPv4 in for the addresses in it, so a
// stale table would also refuse the Mac's own new address.
func (s *Server) syncHostTable(ctx context.Context) error {
	want, err := s.hostAddrs()
	if err != nil {
		return err
	}
	got, err := s.table(ctx, hostTable)
	if err != nil {
		return err
	}
	if samePrefixes(got, want) {
		return nil
	}
	args := []string{"-a", anchor, "-t", hostTable, "-T", "replace"}
	for _, prefix := range want {
		args = append(args, prefixText(prefix))
	}
	if _, err := s.pf(ctx, args...); err != nil {
		return err
	}
	if got, err = s.table(ctx, hostTable); err != nil {
		return err
	}
	if !samePrefixes(got, want) {
		return fmt.Errorf("PF table %s does not hold the Mac's addresses after replace", hostTable)
	}
	return nil
}

func (s *Server) pfReady(ctx context.Context, bridges []string) error {
	info, err := s.pf(ctx, "-s", "info")
	if err != nil {
		return err
	}
	var enabled bool
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Status: Enabled") {
			enabled = true
			break
		}
	}
	if !enabled {
		return fmt.Errorf("Mac PF is disabled")
	}
	main, err := s.pf(ctx, "-sr")
	if err != nil {
		return err
	}
	if !strings.Contains(string(main), `anchor "com.apple/*"`) {
		return fmt.Errorf("Mac PF main rules do not call the helper anchor")
	}
	if sha256.Sum256(main) != s.mainHash {
		return fmt.Errorf("Mac PF main rules changed from the reviewed baseline")
	}
	nat, err := s.pf(ctx, "-sn")
	if err != nil {
		return err
	}
	if !strings.Contains(string(nat), `nat-anchor "com.apple/*"`) {
		return fmt.Errorf("Mac PF main rules do not call the helper's NAT anchor")
	}
	for _, bridge := range bridges {
		iface, err := s.pf(ctx, "-s", "Interfaces", "-v", "-i", bridge)
		if err != nil {
			return err
		}
		if !strings.Contains(string(iface), bridge) || strings.Contains(strings.ToLower(string(iface)), "skip") {
			return fmt.Errorf("PF does not confirm filtering on %s", bridge)
		}
	}
	return nil
}

// loaded is the anchor's filter (-sr) and NAT (-sn) rules.
func (s *Server) loaded(ctx context.Context) (filter, nat string, err error) {
	var out [2]string
	for i, show := range []string{"-sr", "-sn"} {
		text, err := s.pf(ctx, "-a", anchor, show)
		if err != nil {
			// macOS reports an anchor that has never been loaded as DIOCGETRULES.
			// This is not accepted by Check; Arm may create it from root-owned rules.
			if strings.Contains(err.Error(), "DIOCGETRULES: Invalid argument") {
				continue
			}
			return "", "", err
		}
		out[i] = strings.TrimSpace(string(text))
	}
	return out[0], out[1], nil
}

// check attests every slot and returns their bridges, comma-separated in slot order.
func (s *Server) check(ctx context.Context) (string, error) {
	if err := s.verifyNetwork(ctx); err != nil {
		return "", err
	}
	bridges, err := s.attested()
	if err != nil {
		return "", err
	}
	if err := s.pfReady(ctx, bridges); err != nil {
		return "", err
	}
	filter, nat, err := s.loaded(ctx)
	if err != nil {
		return "", err
	}
	guard, err := s.guardForwarding()
	if err != nil {
		return "", err
	}
	egress, ok := natEgress(nat)
	want := s.policyFor(bridges, egress, s.config.ModelRelayPort, nil, guard)
	if !ok || filter != want.Filter || nat != want.NAT {
		return "", fmt.Errorf("firewall anchor does not contain the exact scoped policy for %s; pfctl reports %q and NAT %q",
			strings.Join(bridges, ","), truncate(filter, 600), truncate(nat, 300))
	}
	if err := s.verifyTables(ctx); err != nil {
		return "", err
	}
	return strings.Join(bridges, ","), nil
}

func (s *Server) arm(ctx context.Context) (string, error) {
	if err := s.verifyNetwork(ctx); err != nil {
		return "", err
	}
	if err := s.attached(ctx, true); err != nil {
		return "", err
	}
	bridges, err := s.attested()
	if err != nil {
		return "", err
	}
	if err := s.pfReady(ctx, bridges); err != nil {
		return "", err
	}
	egress, err := s.egressInterface(ctx)
	if err != nil {
		return "", err
	}
	host, err := s.hostAddrs()
	if err != nil {
		return "", err
	}
	guard, err := s.recordForwarding(ctx)
	if err != nil {
		return "", err
	}
	want := s.policyFor(bridges, egress, s.config.ModelRelayPort, host, guard)
	filter, nat, err := s.loaded(ctx)
	if err != nil {
		return "", err
	}
	if filter == want.Filter && nat == want.NAT {
		// The same rules with other deny prefixes (a changed --deny-cidr)
		// are reloaded below.
		if exact, err := s.constTablesExact(ctx); err == nil && exact {
			return s.route(ctx, bridges)
		}
	}
	if (filter != "" || nat != "") && !s.known(bridges, filter, nat) {
		return "", fmt.Errorf("refusing to replace an unexpected firewall policy")
	}
	file, err := os.CreateTemp(filepath.Dir(s.config.SocketPath), "policy-*.pf")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	if _, err := io.WriteString(file, want.Load); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	// -o none: pfctl's default "basic" optimizer reorders rules on load, so
	// with several slots the readback no longer matched the policy text and
	// check refused it (seen on the Mac Studio with 3 slots, 2026-09-30).
	if _, err := s.pf(ctx, "-a", anchor, "-o", "none", "-nf", file.Name()); err != nil {
		return "", err
	}
	if _, err := s.pf(ctx, "-a", anchor, "-o", "none", "-f", file.Name()); err != nil {
		return "", err
	}
	return s.route(ctx, bridges)
}

// forwardingSysctl must be on for guest NAT, as Apple's own vmnet NAT
// networks need.
const forwardingSysctl = "net.inet.ip.forwarding"

// forwardingState records the value forwarding had before this helper first
// armed, so disarm restores it and the anchor knows whether to guard it. It
// lives beside the socket under /var/run, which macOS clears at boot just
// as it resets the sysctl.
func (s *Server) forwardingState() string {
	return filepath.Join(filepath.Dir(s.config.SocketPath), "ip-forwarding-before-arm")
}

// forwardingBefore is the recorded value, "0" or "1".
func (s *Server) forwardingBefore() (string, error) {
	data, err := os.ReadFile(s.forwardingState())
	if err != nil {
		return "", err
	}
	before := strings.TrimSpace(string(data))
	if before != "0" && before != "1" {
		return "", fmt.Errorf("unreadable IPv4 forwarding state in %s", s.forwardingState())
	}
	return before, nil
}

func (s *Server) currentForwarding(ctx context.Context) (string, error) {
	out, err := s.run(ctx, "/usr/sbin/sysctl", "-n", forwardingSysctl)
	if err != nil {
		return "", fmt.Errorf("read IPv4 forwarding: %w", err)
	}
	current := strings.TrimSpace(string(out))
	if current != "0" && current != "1" {
		return "", fmt.Errorf("unexpected %s value %q", forwardingSysctl, current)
	}
	return current, nil
}

// guardForwarding reports whether the anchor must keep non-guest traffic
// from being forwarded: only when this helper turned forwarding on. If it
// was already on (a Tailscale exit node, OrbStack, Internet Sharing), the
// operator routes on purpose and that routing is left as it was.
func (s *Server) guardForwarding() (bool, error) {
	before, err := s.forwardingBefore()
	if err != nil {
		return false, fmt.Errorf("no usable record of IPv4 forwarding before arm: %w", err)
	}
	return before == "0", nil
}

// recordForwarding records forwarding's current value unless an earlier arm
// (before a helper restart, too) already did, and returns guardForwarding.
func (s *Server) recordForwarding(ctx context.Context) (bool, error) {
	if _, err := s.forwardingBefore(); errors.Is(err, os.ErrNotExist) {
		current, err := s.currentForwarding(ctx)
		if err != nil {
			return false, err
		}
		if err := writeState(s.forwardingState(), current+"\n"); err != nil {
			return false, fmt.Errorf("record IPv4 forwarding before arm: %w", err)
		}
	}
	return s.guardForwarding()
}

// route turns on IPv4 forwarding once the anchor is loaded, then clears the
// bridges' states and checks.
func (s *Server) route(ctx context.Context, bridges []string) (string, error) {
	current, err := s.currentForwarding(ctx)
	if err != nil {
		return "", err
	}
	if current == "0" {
		if _, err := s.run(ctx, "/usr/sbin/sysctl", "-w", forwardingSysctl+"=1"); err != nil {
			return "", fmt.Errorf("enable IPv4 forwarding for guest NAT: %w", err)
		}
	}
	return s.clearBridgeStates(ctx, bridges)
}

// restoreForwarding turns forwarding off again only if it was off before
// this helper's first arm; if someone else had it on, it stays on.
func (s *Server) restoreForwarding(ctx context.Context) error {
	before, err := s.forwardingBefore()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if before == "0" {
		if _, err := s.run(ctx, "/usr/sbin/sysctl", "-w", forwardingSysctl+"=0"); err != nil {
			return fmt.Errorf("restore IPv4 forwarding: %w", err)
		}
	}
	return os.Remove(s.forwardingState())
}

// writeState writes a root-only file by rename, so a crash never leaves it
// partly written.
func writeState(path, text string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := io.WriteString(file, text); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Arm clears only states on the attested slot bridges. An old state can
// bypass newly installed filter rules even when their text is correct.
func (s *Server) clearBridgeStates(ctx context.Context, bridges []string) (string, error) {
	for _, bridge := range bridges {
		if _, err := s.pf(ctx, "-F", "states", "-i", bridge); err != nil {
			return "", err
		}
	}
	return s.check(ctx)
}

func (s *Server) disarm(ctx context.Context) error {
	if err := s.drained(ctx); err != nil {
		return err
	}
	bridges, err := s.discover()
	if err != nil {
		return err
	}
	for i, bridge := range bridges {
		if bridge != "" {
			return fmt.Errorf("refusing to clear PF while the bridge for sandbox network %s is present", s.config.Slots[i].Network)
		}
	}
	filter, nat, err := s.loaded(ctx)
	if err != nil {
		return err
	}
	if filter == "" && nat == "" {
		return s.restoreForwarding(ctx)
	}
	loaded, ok := filterBridges(filter, len(s.config.Slots))
	if !ok || !s.known(loaded, filter, nat) {
		return fmt.Errorf("refusing to clear an unexpected PF anchor")
	}
	// Drained guests need no forwarding; turn it back off while the anchor
	// still guards every interface.
	if err := s.restoreForwarding(ctx); err != nil {
		return err
	}
	for _, what := range []string{"rules", "nat", "Tables"} {
		if _, err := s.pf(ctx, "-a", anchor, "-F", what); err != nil {
			return err
		}
	}
	if filter, nat, err = s.loaded(ctx); err != nil {
		return err
	}
	if filter != "" || nat != "" {
		return fmt.Errorf("firewall anchor is not empty after cleanup")
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	var req request
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: "invalid helper request"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	var bridge string
	var err error
	switch req.Action {
	case "arm":
		bridge, err = s.arm(ctx)
	case "check":
		bridge, err = s.check(ctx)
	case "disarm":
		err = s.disarm(ctx)
	default:
		err = fmt.Errorf("unknown helper action")
	}
	if err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(response{Bridge: bridge})
}

// Serve accepts only the configured host worker UID. It never removes the PF
// anchor on process exit: losing a helper must not open the guest network.
func (s *Server) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("firewall helper must run as root")
	}
	if err := s.verifyContainerBinary(); err != nil {
		return err
	}
	parent := filepath.Dir(s.config.SocketPath)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("firewall socket directory must be root-owned and not group/world writable")
	}
	if old, err := os.Lstat(s.config.SocketPath); err == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace a non-socket helper path")
		}
		if conn, err := net.DialTimeout("unix", s.config.SocketPath, time.Second); err == nil {
			conn.Close()
			return fmt.Errorf("firewall helper is already running")
		}
		if err := os.Remove(s.config.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Chown/Chmod after Listen would leave a window where other local users
	// could connect. No other goroutine creates files during this operation.
	previousUmask := syscall.Umask(0o177)
	listener, err := net.Listen("unix", s.config.SocketPath)
	syscall.Umask(previousUmask)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(s.config.SocketPath)
	if err := os.Chown(s.config.SocketPath, s.config.WorkerUID, s.config.WorkerGID); err != nil {
		return err
	}
	if err := os.Chmod(s.config.SocketPath, 0o600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	go func() {
		// The Mac's addresses can change while sandboxd is down; keep the
		// loaded host table current so the Mac stays reachable on them.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				s.refreshHostTable(ctx)
				s.mu.Unlock()
			}
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.handle(conn)
		s.mu.Unlock()
	}
}

// refreshHostTable syncs the host table if the anchor holds one.
func (s *Server) refreshHostTable(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if _, err := s.table(ctx, hostTable); err != nil {
		return
	}
	if err := s.syncHostTable(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "refresh PF table %s: %v\n", hostTable, err)
	}
}

// truncate bounds rule text quoted in an error.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
