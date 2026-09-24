package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func (s *Server) runContainer(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.config.ContainerCLI, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + s.config.WorkerHome}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(s.config.WorkerUID), Gid: uint32(s.config.WorkerGID),
	}}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Apple container %s: %w", args[0], err)
	}
	return out, nil
}

func (s *Server) pinID() string {
	hash := sha256.Sum256([]byte(s.config.WorkerID))
	return fmt.Sprintf("sandboxd-pin-%x", hash[:8])
}

func (s *Server) verifyNetwork(ctx context.Context) error {
	out, err := s.container(ctx, "network", "inspect", s.config.Network)
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
		return fmt.Errorf("dedicated Apple network inspect is incomplete: %w", err)
	}
	network := networks[0]
	if network.Configuration.Name != s.config.Network || network.Configuration.Mode != "hostOnly" ||
		network.Configuration.Plugin != "container-network-vmnet" ||
		network.Configuration.Labels["gitmoot.sandboxd.network"] != "apple-v1" ||
		network.Status.IPv4Gateway != s.gateway.String() || network.Status.IPv4Subnet != s.ipv4.String() ||
		network.Status.IPv6Subnet != s.ipv6.String() {
		return fmt.Errorf("dedicated Apple host-only network identity changed")
	}
	out, err = s.container(ctx, "list", "--all", "--format", "json")
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
	pinID := s.pinID()
	var found bool
	for _, item := range items {
		if item.Configuration.ID != pinID {
			continue
		}
		if found {
			return fmt.Errorf("duplicate trusted pin VM identity")
		}
		found = true
		cfg := item.Configuration
		if item.Status.State != "running" || cfg.Labels["gitmoot.sandboxd.pin"] != "apple-v1" ||
			cfg.Labels["gitmoot.sandboxd.worker"] != s.config.WorkerID ||
			cfg.Labels["gitmoot.sandboxd.owner"] != "" || cfg.Image.Reference != s.config.PinImage ||
			len(cfg.Networks) != 1 || cfg.Networks[0].Network != s.config.Network || !cfg.ReadOnly ||
			cfg.Init.Executable != "/bin/sleep" || len(cfg.Init.Arguments) != 1 ||
			cfg.Init.Arguments[0] != "2147483647" || cfg.Init.User.ID.UID != 1000 ||
			cfg.Init.User.ID.GID != 1000 || len(cfg.Mounts) != 0 ||
			len(cfg.PublishedPorts) != 0 || len(cfg.PublishedSockets) != 0 ||
			len(cfg.CapAdd) != 0 || cfg.Resources.CPUs != 1 ||
			cfg.Resources.MemoryInBytes != 256<<20 ||
			(len(cfg.DNS) != 0 && string(cfg.DNS) != "null") {
			return fmt.Errorf("trusted bridge pin VM identity changed")
		}
		var dropped bool
		for _, cap := range cfg.CapDrop {
			dropped = dropped || cap == "ALL"
		}
		if !dropped {
			return fmt.Errorf("trusted bridge pin VM capabilities changed")
		}
	}
	if !found {
		return fmt.Errorf("trusted bridge pin VM is missing")
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
