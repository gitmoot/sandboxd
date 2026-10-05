package helpersvc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/firewall"
)

// InstallOptions are the helper settings install cannot discover.
type InstallOptions struct {
	WorkerID     string
	PinImage     string
	ContainerCLI string
	// MainRulesSHA256 overrides the hash of the current pfctl -sr output.
	MainRulesSHA256 string
	ModelRelayPort  int
	// DenyCIDRs and EgressInterface become the service's --deny-cidr and
	// --egress-interface flags.
	DenyCIDRs       []netip.Prefix
	EgressInterface string
}

// Install makes this binary the helper's launchd system service. It must run
// as root through sudo from the worker account.
func (h *Host) Install(ctx context.Context, opts InstallOptions, version string) error {
	if err := h.requireRootOnMac("install"); err != nil {
		return err
	}
	worker, err := h.sudoWorker()
	if err != nil {
		return err
	}
	slots, err := h.discoverSlots(ctx, worker, opts.ContainerCLI)
	if err != nil {
		return err
	}
	mainHash := opts.MainRulesSHA256
	if mainHash == "" {
		rules, err := h.Run(ctx, nil, "/sbin/pfctl", "-sr")
		if err != nil {
			return err
		}
		sum := sha256.Sum256(rules)
		mainHash = hex.EncodeToString(sum[:])
	}
	cfg := firewall.Config{
		SocketPath: h.Socket, WorkerUID: worker.UID, WorkerGID: worker.GID,
		WorkerHome: worker.Home, WorkerID: opts.WorkerID, ContainerCLI: opts.ContainerCLI,
		Slots: slots, PinImage: opts.PinImage, MainRulesSHA256: mainHash,
		ModelRelayPort: opts.ModelRelayPort, DenyCIDRs: opts.DenyCIDRs, EgressInterface: opts.EgressInterface,
	}
	if _, err := firewall.NewServer(cfg); err != nil {
		return err
	}
	helper, sandboxd, err := h.sourceBinaries()
	if err != nil {
		return err
	}
	if err := h.ensureTrustedDir(h.Libexec); err != nil {
		return fmt.Errorf("refusing to install into %s: %w", h.Libexec, err)
	}

	if err := h.stopLegacyHelpers(ctx); err != nil {
		return err
	}
	if sandboxd != nil {
		if err := h.writeFile(h.sandboxdPath(), sandboxd, 0o755); err != nil {
			return err
		}
	}
	if err := h.writeFile(h.helperPath(), helper, 0o755); err != nil {
		return err
	}
	if err := h.writeFile(h.plistPath(), renderPlist(h.helperArgs(cfg), h.logPath()), 0o644); err != nil {
		return err
	}
	wrapper := h.installWrapper()
	if err := h.bootstrap(ctx); err != nil {
		return err
	}
	if err := h.waitSocket(h.Socket); err != nil {
		return err
	}

	fmt.Fprintf(h.Stdout, "sandboxd-pf-helper %s runs as launchd job %s (%s)\n", version, Label, h.plistPath())
	fmt.Fprintf(h.Stdout, "socket %s for uid %d gid %d, worker %s\n", h.Socket, worker.UID, worker.GID, opts.WorkerID)
	fmt.Fprintf(h.Stdout, "PF main rules sha256 %s\n", mainHash)
	fmt.Fprintln(h.Stdout, "slots (give sandboxd the same --slot flags, in this order):")
	for _, s := range slots {
		fmt.Fprintf(h.Stdout, "  --slot %s\n", s)
	}
	if sandboxd != nil {
		fmt.Fprintf(h.Stdout, "sandboxd installed at %s\n", h.sandboxdPath())
	}
	fmt.Fprintf(h.Stdout, "log %s\n", h.logPath())
	if wrapper {
		fmt.Fprintf(h.Stdout, "update with: sudo sandboxd-helper-update\n")
	} else {
		fmt.Fprintf(h.Stdout, "note: %s is not root-only; update with: sudo %s update\n", h.Bin, h.helperPath())
	}
	return nil
}

// helperArgs is the service's command line.
func (h *Host) helperArgs(cfg firewall.Config) []string {
	args := []string{h.helperPath(), "run",
		"--socket", cfg.SocketPath,
		"--worker-uid", strconv.Itoa(cfg.WorkerUID),
		"--worker-gid", strconv.Itoa(cfg.WorkerGID),
		"--worker-home", cfg.WorkerHome,
		"--worker-id", cfg.WorkerID,
		"--container-cli", cfg.ContainerCLI,
	}
	for _, s := range cfg.Slots {
		args = append(args, "--slot", s.String())
	}
	args = append(args,
		"--pin-image", cfg.PinImage,
		"--main-rules-sha256", cfg.MainRulesSHA256,
		"--model-relay-port", strconv.Itoa(cfg.ModelRelayPort))
	for _, prefix := range cfg.DenyCIDRs {
		args = append(args, "--deny-cidr", prefix.String())
	}
	if cfg.EgressInterface != "" {
		args = append(args, "--egress-interface", cfg.EgressInterface)
	}
	return args
}

// sourceBinaries reads this executable and, if present, the sandboxd next to
// it. Both must sit in a root-only tree so nobody can swap them mid-install.
func (h *Host) sourceBinaries() (helper, sandboxd []byte, err error) {
	exe, err := h.Executable()
	if err != nil {
		return nil, nil, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, nil, err
	}
	dir := filepath.Dir(exe)
	if err := h.trustedTree(dir); err != nil {
		return nil, nil, fmt.Errorf("refusing to install from %s (unpack the release in a root-only directory): %w", dir, err)
	}
	if err := h.trusted(exe, false); err != nil {
		return nil, nil, fmt.Errorf("refusing to install %s: %w", exe, err)
	}
	if helper, err = os.ReadFile(exe); err != nil {
		return nil, nil, err
	}
	next := filepath.Join(dir, "sandboxd")
	if _, err := h.Lstat(next); errors.Is(err, fs.ErrNotExist) {
		return helper, nil, nil
	}
	if err := h.trusted(next, false); err != nil {
		return nil, nil, fmt.Errorf("refusing to install %s: %w", next, err)
	}
	if sandboxd, err = os.ReadFile(next); err != nil {
		return nil, nil, err
	}
	return helper, sandboxd, nil
}

// stopLegacyHelpers stops helpers started by hand from a Terminal before the
// service existed: sandboxd-pf-helper-<commit>, however the path was spelled
// (absolute, ./, or another directory). A missed one would keep the socket,
// so the new service would crash-loop while install saw the socket and
// reported success.
func (h *Host) stopLegacyHelpers(ctx context.Context) error {
	legacy := regexp.MustCompile(`(^|/)sandboxd-pf-helper-[0-9a-f]{7}$`)
	find := func() ([]int, error) {
		out, err := h.Run(ctx, nil, "/bin/ps", "-axww", "-o", "pid=,command=")
		if err != nil {
			return nil, err
		}
		var pids []int
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 2 || !legacy.MatchString(f[1]) {
				continue
			}
			pid, err := strconv.Atoi(f[0])
			if err != nil || pid <= 1 {
				return nil, fmt.Errorf("process list line %q", sc.Text())
			}
			pids = append(pids, pid)
		}
		return pids, sc.Err()
	}
	pids, err := find()
	if err != nil || len(pids) == 0 {
		return err
	}
	for _, pid := range pids {
		fmt.Fprintf(h.Stdout, "stopping the hand-started helper (pid %d)\n", pid)
		if err := h.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("stop legacy helper pid %d: %w", pid, err)
		}
	}
	for range 40 {
		if pids, err = find(); err != nil || len(pids) == 0 {
			return err
		}
		h.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("legacy helper pid %v did not stop; stop it (Ctrl-C in its Terminal) and rerun install", pids)
}

// installWrapper writes the short update command, but only into a Bin that
// root alone controls up to /; otherwise anyone who could write there could
// replace what the owner runs with sudo.
func (h *Host) installWrapper() bool {
	if err := h.ensureTrustedDir(h.Bin); err != nil {
		return false
	}
	script := "#!/bin/sh\nexec " + h.helperPath() + " update \"$@\"\n"
	return h.writeFile(h.wrapperPath(), []byte(script), 0o755) == nil
}

// bootstrap replaces any loaded job with the installed plist.
func (h *Host) bootstrap(ctx context.Context) error {
	target := "system/" + Label
	if h.launchctl(ctx, "print", target) == nil {
		if err := h.launchctl(ctx, "bootout", target); err != nil {
			return err
		}
		gone := false
		for range 40 {
			if h.launchctl(ctx, "print", target) != nil {
				gone = true
				break
			}
			h.Sleep(250 * time.Millisecond)
		}
		if !gone {
			return fmt.Errorf("launchd job %s is still loaded after bootout", target)
		}
	}
	return h.launchctl(ctx, "bootstrap", "system", h.plistPath())
}
