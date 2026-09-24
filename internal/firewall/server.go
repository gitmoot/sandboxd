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
	"strings"
	"syscall"
	"time"
)

const anchor = "com.apple/gitmoot-sandboxd"

var bridgeName = regexp.MustCompile(`^bridge[0-9]+$`)
var ownedName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var imageDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// Config is supplied by root-owned launchd configuration, never by the worker.
// The bridge address and ULA prefix are pinned to the dedicated host-only network.
type Config struct {
	SocketPath      string
	WorkerUID       int
	WorkerGID       int
	WorkerHome      string
	WorkerID        string
	ContainerCLI    string
	Network         string
	PinImage        string
	GatewayIPv4     string
	IPv4Subnet      string
	IPv6Prefix      string
	MainRulesSHA256 string
}

type Server struct {
	config     Config
	gateway    netip.Addr
	ipv4       netip.Prefix
	ipv6       netip.Prefix
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
		!ownedName.MatchString(cfg.WorkerID) || !ownedName.MatchString(cfg.Network) ||
		cfg.Network == "default" || !imageDigest.MatchString(cfg.PinImage) {
		return nil, fmt.Errorf("invalid root-configured worker, network, or trusted pin image")
	}
	gateway, err := netip.ParseAddr(cfg.GatewayIPv4)
	if err != nil || !gateway.Is4() || !gateway.IsPrivate() {
		return nil, fmt.Errorf("firewall gateway must be a private IPv4 address")
	}
	ipv4, err := netip.ParsePrefix(cfg.IPv4Subnet)
	if err != nil || !ipv4.Addr().Is4() || ipv4.Masked() != ipv4 ||
		!ipv4.Contains(gateway) || ipv4.Bits() < 16 || ipv4.Bits() > 30 {
		return nil, fmt.Errorf("firewall IPv4 subnet must contain the gateway")
	}
	prefix, err := netip.ParsePrefix(cfg.IPv6Prefix)
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() < 48 || prefix.Bits() > 64 ||
		prefix.Masked() != prefix || !prefix.Addr().IsPrivate() {
		return nil, fmt.Errorf("firewall IPv6 network must be a canonical private /48 to /64 prefix")
	}
	rawHash, err := hex.DecodeString(cfg.MainRulesSHA256)
	if err != nil || len(rawHash) != sha256.Size {
		return nil, fmt.Errorf("root-configured PF main rules SHA-256 is required")
	}
	s := &Server{config: cfg, gateway: gateway, ipv4: ipv4, ipv6: prefix, interfaces: net.Interfaces,
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

func (s *Server) discover() (string, error) {
	interfaces, err := s.interfaces()
	if err != nil {
		return "", fmt.Errorf("enumerate Mac interfaces: %w", err)
	}
	var found string
	for _, iface := range interfaces {
		if !bridgeName.MatchString(iface.Name) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := s.addrs(iface)
		if err != nil {
			return "", fmt.Errorf("read %s addresses: %w", iface.Name, err)
		}
		var ipv4, ula, linkLocal bool
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr()
			ipv4 = ipv4 || ip == s.gateway && prefix.Masked() == s.ipv4
			ula = ula || ip.Is6() && prefix.Masked() == s.ipv6
			linkLocal = linkLocal || ip.Is6() && ip.IsLinkLocalUnicast()
		}
		if ipv4 && ula && linkLocal {
			if found != "" {
				return "", fmt.Errorf("multiple bridges match the sandbox network")
			}
			found = iface.Name
		}
	}
	if found == "" {
		return "", fmt.Errorf("sandbox bridge is missing or its addresses changed")
	}
	return found, nil
}

func policy(bridge string) string {
	return "block in quick on " + bridge + " inet from any to any\n" +
		"block in quick on " + bridge + " inet6 from any to any\n"
}

func canonicalPolicy(bridge string) string {
	return "block drop in quick on " + bridge + " inet all\n" +
		"block drop in quick on " + bridge + " inet6 all"
}

func (s *Server) pfReady(ctx context.Context, bridge string) error {
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
	iface, err := s.pf(ctx, "-s", "Interfaces", "-v", "-i", bridge)
	if err != nil {
		return err
	}
	if !strings.Contains(string(iface), bridge) || strings.Contains(strings.ToLower(string(iface)), "skip") {
		return fmt.Errorf("PF does not confirm filtering on %s", bridge)
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

func (s *Server) check(ctx context.Context) (string, error) {
	if err := s.verifyNetwork(ctx); err != nil {
		return "", err
	}
	bridge, err := s.discover()
	if err != nil {
		return "", err
	}
	if err := s.pfReady(ctx, bridge); err != nil {
		return "", err
	}
	rules, err := s.rules(ctx)
	if err != nil {
		return "", err
	}
	if rules != canonicalPolicy(bridge) {
		return "", fmt.Errorf("firewall anchor does not contain the exact deny policy for %s", bridge)
	}
	return bridge, nil
}

func (s *Server) arm(ctx context.Context) (string, error) {
	if err := s.verifyNetwork(ctx); err != nil {
		return "", err
	}
	if err := s.attached(ctx, true); err != nil {
		return "", err
	}
	bridge, err := s.discover()
	if err != nil {
		return "", err
	}
	if err := s.pfReady(ctx, bridge); err != nil {
		return "", err
	}
	rules, err := s.rules(ctx)
	if err != nil {
		return "", err
	}
	if rules == canonicalPolicy(bridge) {
		return s.clearBridgeStates(ctx, bridge)
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
	if _, err := io.WriteString(file, policy(bridge)); err != nil {
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
	if _, err := s.pf(ctx, "-a", anchor, "-nf", file.Name()); err != nil {
		return "", err
	}
	if _, err := s.pf(ctx, "-a", anchor, "-f", file.Name()); err != nil {
		return "", err
	}
	return s.clearBridgeStates(ctx, bridge)
}

// Arm clears only states on the attested dedicated bridge. An old state can
// bypass newly installed filter rules even when their text is correct.
func (s *Server) clearBridgeStates(ctx context.Context, bridge string) (string, error) {
	if _, err := s.pf(ctx, "-F", "states", "-i", bridge); err != nil {
		return "", err
	}
	return s.check(ctx)
}

func (s *Server) disarm(ctx context.Context) error {
	if err := s.drained(ctx); err != nil {
		return err
	}
	if _, err := s.discover(); err == nil {
		return fmt.Errorf("refusing to clear PF while the sandbox bridge is present")
	} else if !strings.Contains(err.Error(), "missing or its addresses changed") {
		return err
	}
	rules, err := s.rules(ctx)
	if err != nil {
		return err
	}
	if rules == "" {
		return nil
	}
	parts := strings.Split(rules, "\n")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "block drop in quick on ") {
		return fmt.Errorf("refusing to clear an unexpected PF anchor")
	}
	bridge := strings.TrimSuffix(strings.TrimPrefix(parts[0], "block drop in quick on "), " inet all")
	if !bridgeName.MatchString(bridge) || rules != canonicalPolicy(bridge) {
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
	listener, err := net.Listen("unix", s.config.SocketPath)
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
