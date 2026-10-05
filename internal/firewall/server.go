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
// not depend on it.
func (s *Server) policyFor(bridges []string, egress string, relayPort int, host []netip.Prefix) pfPolicy {
	slots := make([]slotRules, len(bridges))
	for i, bridge := range bridges {
		slots[i] = slotRules{Bridge: bridge, Subnet: s.config.Slots[i].IPv4, Internet: true}
	}
	return render(policyInput{Slots: slots, RelayAddr: s.relayAddress(), RelayPort: relayPort,
		Egress: egress, Deny: s.deny, Host: host})
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
			if p := s.policyFor(bridges, egress, port, nil); filter == p.Filter && nat == p.NAT {
				return true
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

// hostAddrs is every address of the Mac on every interface (LAN, Tailscale,
// bridges, loopback, public), each as a single-address prefix. IPv6
// link-local addresses are scoped and left out: guest IPv6 is dropped whole.
func (s *Server) hostAddrs() ([]netip.Prefix, error) {
	interfaces, err := s.interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate Mac interfaces: %w", err)
	}
	var addrs []netip.Prefix
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
			host := netip.PrefixFrom(ip, ip.BitLen())
			if !slices.Contains(addrs, host) {
				addrs = append(addrs, host)
			}
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
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
	egress, ok := natEgress(nat)
	want := s.policyFor(bridges, egress, s.config.ModelRelayPort, nil)
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
	want := s.policyFor(bridges, egress, s.config.ModelRelayPort, host)
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

// route turns on IPv4 forwarding, which guest NAT needs (as Apple's own
// vmnet NAT networks do), once the anchor is loaded: from then on its last
// rule keeps guest subnets unreachable from every other interface. Then it
// clears the bridges' states and checks.
func (s *Server) route(ctx context.Context, bridges []string) (string, error) {
	if _, err := s.run(ctx, "/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return "", fmt.Errorf("enable IPv4 forwarding for guest NAT: %w", err)
	}
	return s.clearBridgeStates(ctx, bridges)
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
		return nil
	}
	loaded, ok := filterBridges(filter, len(s.config.Slots))
	if !ok || !s.known(loaded, filter, nat) {
		return fmt.Errorf("refusing to clear an unexpected PF anchor")
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
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.handle(conn)
	}
}

// truncate bounds rule text quoted in an error.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
