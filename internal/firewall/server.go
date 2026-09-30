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
	"strconv"
	"strings"
	"syscall"
	"time"
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
	// ModelRelayPort enables only a fixed IPv4 guest-to-gateway TCP exception
	// per slot. Zero keeps the anchor deny-only until the mTLS broker and lease are ready.
	ModelRelayPort  int
	MainRulesSHA256 string
}

type Server struct {
	config     Config
	mainHash   [sha256.Size]byte
	interfaces func() ([]net.Interface, error)
	addrs      func(net.Interface) ([]net.Addr, error)
	pf         func(context.Context, ...string) ([]byte, error)
	container  func(context.Context, ...string) ([]byte, error)
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
	cfg.Slots = append([]Slot(nil), cfg.Slots...)
	s := &Server{config: cfg, interfaces: net.Interfaces,
		addrs: func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }}
	copy(s.mainHash[:], rawHash)
	s.pf = s.runPF
	s.container = s.runContainer
	return s, nil
}

func (s *Server) runPF(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("pfctl %s: %w", strings.Join(args, " "), err)
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

// policy is the anchor text loaded for bridges, one per slot in slot order.
func (s *Server) policy(bridges []string) string {
	var rules strings.Builder
	for i, bridge := range bridges {
		if s.config.ModelRelayPort != 0 {
			slot := s.config.Slots[i]
			rules.WriteString("pass in quick on " + bridge + " inet proto tcp from " + slot.IPv4.String() +
				" to " + slot.Gateway.String() + " port " + strconv.Itoa(s.config.ModelRelayPort) + "\n")
		}
		rules.WriteString("block in quick on " + bridge + " inet from any to any\n" +
			"block in quick on " + bridge + " inet6 from any to any\n")
	}
	return rules.String()
}

// canonicalPolicy is pfctl's exact readback of policy(bridges).
func (s *Server) canonicalPolicy(bridges []string) string {
	lines := make([]string, 0, 3*len(bridges))
	for i, bridge := range bridges {
		if s.config.ModelRelayPort != 0 {
			slot := s.config.Slots[i]
			lines = append(lines, "pass in quick on "+bridge+" inet proto tcp from "+slot.IPv4.String()+
				" to "+slot.Gateway.String()+" port = "+strconv.Itoa(s.config.ModelRelayPort)+" flags S/SA keep state")
		}
		lines = append(lines, "block drop in quick on "+bridge+" inet all", "block drop in quick on "+bridge+" inet6 all")
	}
	return strings.Join(lines, "\n")
}

// loadedBridges recovers the per-slot bridges named by an anchor in this
// helper's shape. Callers still require an exact canonical match.
func (s *Server) loadedBridges(rules string) ([]string, bool) {
	perSlot := 2
	if s.config.ModelRelayPort != 0 {
		perSlot = 3
	}
	lines := strings.Split(rules, "\n")
	if len(lines) != perSlot*len(s.config.Slots) {
		return nil, false
	}
	bridges := make([]string, len(s.config.Slots))
	for i := range bridges {
		bridge, prefixed := strings.CutPrefix(lines[(i+1)*perSlot-2], "block drop in quick on ")
		bridge, suffixed := strings.CutSuffix(bridge, " inet all")
		if !prefixed || !suffixed || !bridgeName.MatchString(bridge) {
			return nil, false
		}
		bridges[i] = bridge
	}
	return bridges, true
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

func (s *Server) rules(ctx context.Context) (string, error) {
	out, err := s.pf(ctx, "-a", anchor, "-sr")
	if err != nil {
		// macOS reports an anchor that has never been loaded as DIOCGETRULES.
		// This is not accepted by Check; Arm may create it from root-owned rules.
		if strings.Contains(err.Error(), "DIOCGETRULES: Invalid argument") {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
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
	rules, err := s.rules(ctx)
	if err != nil {
		return "", err
	}
	if rules != s.canonicalPolicy(bridges) {
		return "", fmt.Errorf("firewall anchor does not contain the exact scoped policy for %s; pfctl reports %q", strings.Join(bridges, ","), truncate(rules, 600))
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
	rules, err := s.rules(ctx)
	if err != nil {
		return "", err
	}
	if rules == s.canonicalPolicy(bridges) {
		return s.clearBridgeStates(ctx, bridges)
	}
	if rules != "" {
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
	if _, err := io.WriteString(file, s.policy(bridges)); err != nil {
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
	rules, err := s.rules(ctx)
	if err != nil {
		return err
	}
	if rules == "" {
		return nil
	}
	loaded, ok := s.loadedBridges(rules)
	if !ok || rules != s.canonicalPolicy(loaded) {
		return fmt.Errorf("refusing to clear an unexpected PF anchor")
	}
	if _, err := s.pf(ctx, "-a", anchor, "-F", "rules"); err != nil {
		return err
	}
	remaining, err := s.rules(ctx)
	if err != nil {
		return err
	}
	if remaining != "" {
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
