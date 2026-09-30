package vm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gitmoot/sandboxd/internal/firewall"
)

const pinOwnerLabel = "gitmoot.sandboxd.pin=apple-v1"

// pinID names the trusted VM that keeps one slot network's bridge alive.
func (d *AppleDriver) pinID(network string) string {
	return firewall.PinID(d.workerID, network)
}

func (d *AppleDriver) pinOwned(item appleContainer, network string) bool {
	return item.Configuration.ID == d.pinID(network) &&
		item.Configuration.Labels["gitmoot.sandboxd.pin"] == "apple-v1" &&
		item.Configuration.Labels[appleWorkerLabel] == d.workerID &&
		item.Configuration.Labels["gitmoot.sandboxd.owner"] == ""
}

func (d *AppleDriver) findPin(items []appleContainer, network string) (appleContainer, bool, error) {
	for _, item := range items {
		if item.Configuration.ID == d.pinID(network) {
			if !d.pinOwned(item, network) {
				return appleContainer{}, false, fmt.Errorf("pin VM name for network %q is held by an unowned container", network)
			}
			return item, true, nil
		}
	}
	return appleContainer{}, false, nil
}

func (d *AppleDriver) lookupPin(ctx context.Context, network string) (appleContainer, bool, error) {
	items, err := d.inventory(ctx)
	if err != nil {
		return appleContainer{}, false, err
	}
	return d.findPin(items, network)
}

func (d *AppleDriver) verifyPin(item appleContainer, network string) error {
	cfg := item.Configuration
	if !d.pinOwned(item, network) || item.Status.State != "running" || cfg.Image.Reference != d.pinImage ||
		len(cfg.Networks) != 1 || cfg.Networks[0].Network != network || !cfg.ReadOnly ||
		cfg.InitProcess.Executable != "/bin/sleep" || len(cfg.InitProcess.Arguments) != 1 ||
		cfg.InitProcess.Arguments[0] != "2147483647" ||
		cfg.InitProcess.User.ID.UID != 1000 || cfg.InitProcess.User.ID.GID != 1000 ||
		len(cfg.Mounts) != 0 || len(cfg.PublishedPorts) != 0 || len(cfg.PublishedSockets) != 0 ||
		len(cfg.CapAdd) != 0 || cfg.Resources.CPUs != 1 ||
		cfg.Resources.MemoryInBytes != 256<<20 ||
		(len(cfg.DNS) != 0 && string(cfg.DNS) != "null") {
		return fmt.Errorf("trusted bridge pin VM for network %q does not match its required configuration", network)
	}
	for _, capability := range cfg.CapDrop {
		if capability == "ALL" {
			return nil
		}
	}
	return fmt.Errorf("trusted bridge pin VM for network %q did not drop all capabilities", network)
}

// runningOnSlots refuses any running VM other than a slot's own pin on any
// slot network.
func (d *AppleDriver) runningOnSlots(items []appleContainer) error {
	for _, item := range items {
		if item.Status.State != "running" {
			continue
		}
		for _, network := range item.Configuration.Networks {
			for _, slot := range d.networks {
				if network.Network == slot && item.Configuration.ID != d.pinID(slot) {
					return fmt.Errorf("VM %q uses sandbox network %q", item.Configuration.ID, slot)
				}
			}
		}
	}
	return nil
}

// StartPin creates or adopts only the exact dedicated, read-only pin VM of
// every slot. It never sets the ordinary VM owner label and never creates a
// writable volume.
func (d *AppleDriver) StartPin(ctx context.Context) error {
	if err := d.checkNetworks(ctx, d.networks...); err != nil {
		return err
	}
	items, err := d.inventory(ctx)
	if err != nil {
		return err
	}
	if err := d.runningOnSlots(items); err != nil {
		return fmt.Errorf("before PF admission: %w", err)
	}
	for _, network := range d.networks {
		if err := d.startPin(ctx, network); err != nil {
			return err
		}
	}
	return nil
}

func (d *AppleDriver) startPin(ctx context.Context, network string) error {
	item, found, err := d.lookupPin(ctx, network)
	if err != nil {
		return err
	}
	if found {
		return d.verifyPin(item, network)
	}
	id := d.pinID(network)
	out, err := d.output(ctx, "create", "--name", id,
		"--label", pinOwnerLabel, "--label", appleWorkerLabel+"="+d.workerID,
		"--network", network, "--platform", "linux/arm64",
		"--cpus", "1", "--memory", "256M", "--read-only", "--cap-drop", "ALL",
		"--no-dns", "--uid", "1000", "--gid", "1000", "--entrypoint", "/bin/sleep",
		d.pinImage, "2147483647")
	if err != nil {
		return errors.Join(err, d.cleanupPin(network))
	}
	if strings.TrimSpace(string(out)) != id {
		return errors.Join(fmt.Errorf("pin create returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupPin(network))
	}
	out, err = d.output(ctx, "start", id)
	if err != nil {
		return errors.Join(err, d.cleanupPin(network))
	}
	if strings.TrimSpace(string(out)) != id {
		return errors.Join(fmt.Errorf("pin start returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupPin(network))
	}
	item, found, err = d.lookupPin(ctx, network)
	if err != nil || !found {
		return errors.Join(err, fmt.Errorf("pin VM for network %q missing after start", network), d.cleanupPin(network))
	}
	if err := d.verifyPin(item, network); err != nil {
		return errors.Join(err, d.cleanupPin(network))
	}
	return nil
}

func (d *AppleDriver) cleanupPin(network string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, found, err := d.lookupPin(ctx, network)
	if err != nil || !found {
		return err
	}
	_, deleteErr := d.output(ctx, "delete", "--force", d.pinID(network))
	_, still, lookupErr := d.lookupPin(ctx, network)
	if still {
		return errors.Join(deleteErr, lookupErr, fmt.Errorf("pin VM for network %q remains after delete", network))
	}
	return errors.Join(deleteErr, lookupErr)
}

// Ready is checked before guest creation and execution, and repeatedly while
// a guest command runs. A missing helper or any missing slot pin denies new work.
func (d *AppleDriver) Ready(ctx context.Context) error {
	items, err := d.inventory(ctx)
	if err != nil {
		return err
	}
	for _, network := range d.networks {
		item, found, err := d.findPin(items, network)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("trusted bridge pin VM for network %q is missing", network)
		}
		if err := d.verifyPin(item, network); err != nil {
			return err
		}
	}
	return d.gate.Check(ctx)
}

// CleanupGuests removes only ordinary VMs bearing this worker's owner label.
// A failed deletion keeps the pins and PF anchor in place for safe recovery.
func (d *AppleDriver) CleanupGuests(ctx context.Context) error {
	items, err := d.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := d.Destroy(ctx, item.ID); err != nil {
			return err
		}
	}
	items, err = d.List(ctx)
	if err != nil {
		return err
	}
	if len(items) != 0 {
		return fmt.Errorf("ordinary sandbox VMs remain after cleanup")
	}
	return nil
}

// StopPin refuses to drop any bridge while another live VM uses a slot network.
func (d *AppleDriver) StopPin(ctx context.Context) error {
	items, err := d.inventory(ctx)
	if err != nil {
		return err
	}
	if err := d.runningOnSlots(items); err != nil {
		return err
	}
	for _, network := range d.networks {
		if err := d.cleanupPin(network); err != nil {
			return err
		}
	}
	return nil
}
