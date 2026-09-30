package helpersvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/gitmoot/sandboxd/internal/firewall"
)

const networkLabel = "gitmoot.sandboxd.network"

// sudoWorker is the account that ran sudo: the worker the helper serves. Its
// identity is settled before install runs the container CLI as it.
func (h *Host) sudoWorker() (Cred, error) {
	uidText, gidText, name := h.Getenv("SUDO_UID"), h.Getenv("SUDO_GID"), h.Getenv("SUDO_USER")
	uid, uerr := strconv.Atoi(uidText)
	gid, gerr := strconv.Atoi(gidText)
	if name == "" || uerr != nil || gerr != nil || uid < 0 || gid < 0 {
		return Cred{}, errors.New("run install with sudo from the worker account: SUDO_UID, SUDO_GID and SUDO_USER name the worker")
	}
	if uid == 0 {
		return Cred{}, fmt.Errorf("refusing root as the worker: run install with sudo from the unprivileged worker account, not from a root shell")
	}
	lookedUID, home, err := h.LookupUser(name)
	if err != nil {
		return Cred{}, fmt.Errorf("look up worker %s: %w", name, err)
	}
	if lookedUID != uidText {
		return Cred{}, fmt.Errorf("SUDO_USER %s has uid %s, not SUDO_UID %s", name, lookedUID, uidText)
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return Cred{}, fmt.Errorf("worker %s home %q is not a clean absolute path", name, home)
	}
	return Cred{UID: uid, GID: gid, Home: home}, nil
}

// discoverSlots returns one slot per Apple host-only network labelled
// gitmoot.sandboxd.network=apple-v1, sorted by name, with the addresses
// Apple reports. It refuses if there is none or any is not a valid slot;
// Install's firewall.NewServer then refuses distinct slots that overlap.
func (h *Host) discoverSlots(ctx context.Context, worker Cred, cli string) ([]firewall.Slot, error) {
	out, err := h.Run(ctx, &worker, cli, "network", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var networks []struct {
		ID            string `json:"id"`
		Configuration struct {
			Mode   string            `json:"mode"`
			Labels map[string]string `json:"labels"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(out, &networks); err != nil {
		return nil, fmt.Errorf("incomplete Apple network list: %w", err)
	}
	var names []string
	for _, n := range networks {
		if n.Configuration.Labels[networkLabel] == "apple-v1" && n.Configuration.Mode == "hostOnly" {
			names = append(names, n.ID)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no Apple host-only network is labelled %s=apple-v1; create the slot networks first (docs/compatibility.md)", networkLabel)
	}
	sort.Strings(names)
	slots := make([]firewall.Slot, 0, len(names))
	for _, name := range names {
		slot, err := h.inspectSlot(ctx, worker, cli, name)
		if err != nil {
			return nil, err
		}
		slots = append(slots, slot)
	}
	return slots, nil
}

// inspectSlot reads one network the way the helper verifies it.
func (h *Host) inspectSlot(ctx context.Context, worker Cred, cli, name string) (firewall.Slot, error) {
	out, err := h.Run(ctx, &worker, cli, "network", "inspect", name)
	if err != nil {
		return firewall.Slot{}, err
	}
	var inspected []struct {
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
	if err := json.Unmarshal(out, &inspected); err != nil || len(inspected) != 1 {
		return firewall.Slot{}, fmt.Errorf("Apple network %s inspect is incomplete: %v", name, err)
	}
	n := inspected[0]
	if n.Configuration.Name != name || n.Configuration.Mode != "hostOnly" ||
		n.Configuration.Plugin != "container-network-vmnet" || n.Configuration.Labels[networkLabel] != "apple-v1" {
		return firewall.Slot{}, fmt.Errorf("Apple network %s is not a labelled vmnet host-only network on inspection", name)
	}
	slot, err := firewall.ParseSlot("name=" + name + ",ipv4=" + n.Status.IPv4Subnet + ",gw=" + n.Status.IPv4Gateway + ",ipv6=" + n.Status.IPv6Subnet)
	if err != nil {
		return firewall.Slot{}, fmt.Errorf("Apple network %s cannot be a slot: %w", name, err)
	}
	return slot, nil
}
