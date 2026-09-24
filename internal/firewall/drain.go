package firewall

import (
	"context"
	"encoding/json"
	"fmt"
)

// attached checks the complete Apple inventory. Arm permits only its trusted
// pin; Disarm requires every VM to be detached before removing the deny rule.
func (s *Server) attached(ctx context.Context, allowPin bool) error {
	out, err := s.container(ctx, "list", "--all", "--format", "json")
	if err != nil {
		return err
	}
	var items []struct {
		Configuration struct {
			ID       string `json:"id"`
			Networks []struct {
				Network string `json:"network"`
			} `json:"networks"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(out, &items); err != nil || items == nil {
		return fmt.Errorf("cannot verify sandbox network is drained: %w", err)
	}
	for _, item := range items {
		for _, network := range item.Configuration.Networks {
			if network.Network == s.config.Network && (!allowPin || item.Configuration.ID != s.pinID()) {
				return fmt.Errorf("VM %q still uses the sandbox network", item.Configuration.ID)
			}
		}
	}
	return nil
}

func (s *Server) drained(ctx context.Context) error {
	return s.attached(ctx, false)
}
