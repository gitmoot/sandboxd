package firewall

import (
	"context"
	"encoding/json"
	"fmt"
)

// attached checks the complete Apple inventory. Arm permits only each slot's
// trusted pin; Disarm requires every VM to be detached from every slot
// network before removing the deny rules.
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
	slotPins := make(map[string]string, len(s.config.Slots))
	for _, slot := range s.config.Slots {
		slotPins[slot.Network] = PinID(s.config.WorkerID, slot.Network)
	}
	for _, item := range items {
		for _, network := range item.Configuration.Networks {
			pinID, slot := slotPins[network.Network]
			if slot && (!allowPin || item.Configuration.ID != pinID) {
				return fmt.Errorf("VM %q still uses sandbox network %s", item.Configuration.ID, network.Network)
			}
		}
	}
	return nil
}

func (s *Server) drained(ctx context.Context) error {
	return s.attached(ctx, false)
}
