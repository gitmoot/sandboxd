package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func (s *Server) runContainer(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	name, argv := workerContainerCommand(s.config.WorkerUID, s.config.WorkerGID, s.config.ContainerCLI, args)
	cmd := exec.CommandContext(ctx, name, argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + s.config.WorkerHome}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return nil, fmt.Errorf("Apple container %s: %w: %s", args[0], err, truncate(strings.TrimSpace(string(exit.Stderr)), 300))
		}
		return nil, fmt.Errorf("Apple container %s: %w", args[0], err)
	}
	return out, nil
}

// workerContainerCommand runs the container CLI as the worker inside the
// worker's per-user launchd bootstrap. Apple's container API server is a
// per-user launchd agent (gui/<uid>), so a CLI started from the helper's
// system-domain launchd job cannot find it even with the worker's uid; the
// helper then failed every arm with "exit status 1" (Mac Studio, v0.1.0,
// 2026-09-30). `launchctl asuser` (root only) enters that bootstrap; sudo,
// which root may always run without a password, then drops to the worker.
func workerContainerCommand(uid, gid int, cli string, args []string) (string, []string) {
	argv := []string{"asuser", strconv.Itoa(uid), "/usr/bin/sudo", "-n", "-H",
		"-u", "#" + strconv.Itoa(uid), "-g", "#" + strconv.Itoa(gid), "--", cli}
	return "/bin/launchctl", append(argv, args...)
}

// verifyNetwork attests every slot network, its trusted pin, and that no
// slot is shared: guests on one Apple network can reach each other unseen by PF.
func (s *Server) verifyNetwork(ctx context.Context) error {
	for _, slot := range s.config.Slots {
		if err := s.verifySlotNetwork(ctx, slot); err != nil {
			return err
		}
	}
	out, err := s.container(ctx, "list", "--all", "--format", "json")
	if err != nil {
		return err
	}
	var items []struct {
		Configuration struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
			Image  struct {
				Reference string `json:"reference"`
			} `json:"image"`
			Networks []struct {
				Network string `json:"network"`
			} `json:"networks"`
			ReadOnly         bool              `json:"readOnly"`
			CapDrop          []string          `json:"capDrop"`
			Mounts           []json.RawMessage `json:"mounts"`
			PublishedPorts   []json.RawMessage `json:"publishedPorts"`
			PublishedSockets []json.RawMessage `json:"publishedSockets"`
			DNS              json.RawMessage   `json:"dns"`
			CapAdd           []string          `json:"capAdd"`
			Resources        struct {
				CPUs          int   `json:"cpus"`
				MemoryInBytes int64 `json:"memoryInBytes"`
			} `json:"resources"`
			Init struct {
				Executable string   `json:"executable"`
				Arguments  []string `json:"arguments"`
				User       struct {
					ID struct {
						UID int `json:"uid"`
						GID int `json:"gid"`
					} `json:"id"`
				} `json:"user"`
			} `json:"initProcess"`
		} `json:"configuration"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &items); err != nil || items == nil {
		return fmt.Errorf("Apple pin inventory is incomplete: %w", err)
	}
	slotPins := make(map[string]string, len(s.config.Slots))
	for _, slot := range s.config.Slots {
		pinID := PinID(s.config.WorkerID, slot.Network)
		slotPins[slot.Network] = pinID
		var found bool
		for _, item := range items {
			if item.Configuration.ID != pinID {
				continue
			}
			if found {
				return fmt.Errorf("duplicate trusted pin VM identity for network %s", slot.Network)
			}
			found = true
			cfg := item.Configuration
			if item.Status.State != "running" || cfg.Labels["gitmoot.sandboxd.pin"] != "apple-v1" ||
				cfg.Labels["gitmoot.sandboxd.worker"] != s.config.WorkerID ||
				cfg.Labels["gitmoot.sandboxd.owner"] != "" || cfg.Image.Reference != s.config.PinImage ||
				len(cfg.Networks) != 1 || cfg.Networks[0].Network != slot.Network || !cfg.ReadOnly ||
				cfg.Init.Executable != "/bin/sleep" || len(cfg.Init.Arguments) != 1 ||
				cfg.Init.Arguments[0] != "2147483647" || cfg.Init.User.ID.UID != 1000 ||
				cfg.Init.User.ID.GID != 1000 || len(cfg.Mounts) != 0 ||
				len(cfg.PublishedPorts) != 0 || len(cfg.PublishedSockets) != 0 ||
				len(cfg.CapAdd) != 0 || cfg.Resources.CPUs != 1 ||
				cfg.Resources.MemoryInBytes != 256<<20 ||
				(len(cfg.DNS) != 0 && string(cfg.DNS) != "null") {
				return fmt.Errorf("trusted bridge pin VM identity changed for network %s", slot.Network)
			}
			var dropped bool
			for _, cap := range cfg.CapDrop {
				dropped = dropped || cap == "ALL"
			}
			if !dropped {
				return fmt.Errorf("trusted bridge pin VM capabilities changed for network %s", slot.Network)
			}
		}
		if !found {
			return fmt.Errorf("trusted bridge pin VM is missing for network %s", slot.Network)
		}
	}
	// One guest per slot, attached to nothing else. Stopped VMs count: their
	// configuration rejoins the network when started.
	occupants := make(map[string]string, len(s.config.Slots))
	for _, item := range items {
		for _, network := range item.Configuration.Networks {
			pinID, slot := slotPins[network.Network]
			if !slot || item.Configuration.ID == pinID {
				continue
			}
			if len(item.Configuration.Networks) != 1 {
				return fmt.Errorf("VM %q joins sandbox network %s to another network", item.Configuration.ID, network.Network)
			}
			if other, shared := occupants[network.Network]; shared {
				return fmt.Errorf("VMs %q and %q share sandbox network %s", other, item.Configuration.ID, network.Network)
			}
			occupants[network.Network] = item.Configuration.ID
		}
	}
	return nil
}

func (s *Server) verifySlotNetwork(ctx context.Context, slot Slot) error {
	out, err := s.container(ctx, "network", "inspect", slot.Network)
	if err != nil {
		return err
	}
	var networks []struct {
		Configuration struct {
			Name   string            `json:"name"`
			Mode   string            `json:"mode"`
			Plugin string            `json:"plugin"`
			Labels map[string]string `json:"labels"`
		} `json:"configuration"`
		Status struct {
			IPv4Gateway string `json:"ipv4Gateway"`
			IPv4Subnet  string `json:"ipv4Subnet"`
			IPv6Subnet  string `json:"ipv6Subnet"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &networks); err != nil || len(networks) != 1 {
		return fmt.Errorf("dedicated Apple network %s inspect is incomplete: %w", slot.Network, err)
	}
	network := networks[0]
	if network.Configuration.Name != slot.Network || network.Configuration.Mode != "hostOnly" ||
		network.Configuration.Plugin != "container-network-vmnet" ||
		network.Configuration.Labels["gitmoot.sandboxd.network"] != "apple-v1" ||
		network.Status.IPv4Gateway != slot.Gateway.String() || network.Status.IPv4Subnet != slot.IPv4.String() ||
		network.Status.IPv6Subnet != slot.IPv6.String() {
		return fmt.Errorf("dedicated Apple host-only network %s identity changed", slot.Network)
	}
	return nil
}

func (s *Server) verifyContainerBinary() error {
	info, err := os.Stat(s.config.ContainerCLI)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("container CLI must be root-owned and not group/world writable")
	}
	if strings.ContainsRune(s.config.WorkerHome, 0) || strings.ContainsRune(s.config.ContainerCLI, 0) {
		return fmt.Errorf("invalid worker path")
	}
	return nil
}
