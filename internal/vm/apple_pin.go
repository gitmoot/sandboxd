package vm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

const pinOwnerLabel = "gitmoot.sandboxd.pin=apple-v1"

func (d *AppleDriver) pinID() string {
	hash := sha256.Sum256([]byte(d.workerID))
	return fmt.Sprintf("sandboxd-pin-%x", hash[:8])
}

func (d *AppleDriver) pinOwned(item appleContainer) bool {
	return item.Configuration.ID == d.pinID() &&
		item.Configuration.Labels["gitmoot.sandboxd.pin"] == "apple-v1" &&
		item.Configuration.Labels[appleWorkerLabel] == d.workerID &&
		item.Configuration.Labels["gitmoot.sandboxd.owner"] == ""
}

func (d *AppleDriver) lookupPin(ctx context.Context) (appleContainer, bool, error) {
	items, err := d.inventory(ctx)
	if err != nil {
		return appleContainer{}, false, err
	}
	for _, item := range items {
		if item.Configuration.ID == d.pinID() {
			if !d.pinOwned(item) {
				return appleContainer{}, false, fmt.Errorf("pin VM name is held by an unowned container")
			}
			return item, true, nil
		}
	}
	return appleContainer{}, false, nil
}

func (d *AppleDriver) verifyPin(item appleContainer) error {
	cfg := item.Configuration
	if !d.pinOwned(item) || item.Status.State != "running" || cfg.Image.Reference != d.pinImage ||
		len(cfg.Networks) != 1 || cfg.Networks[0].Network != d.network || !cfg.ReadOnly ||
		cfg.InitProcess.Executable != "/bin/sleep" || len(cfg.InitProcess.Arguments) != 1 ||
		cfg.InitProcess.Arguments[0] != "2147483647" ||
		cfg.InitProcess.User.ID.UID != 1000 || cfg.InitProcess.User.ID.GID != 1000 ||
		len(cfg.Mounts) != 0 || len(cfg.PublishedPorts) != 0 || len(cfg.PublishedSockets) != 0 ||
		len(cfg.CapAdd) != 0 || cfg.Resources.CPUs != 1 ||
		cfg.Resources.MemoryInBytes != 256<<20 ||
		(len(cfg.DNS) != 0 && string(cfg.DNS) != "null") {
		return fmt.Errorf("trusted bridge pin VM does not match its required configuration")
	}
	for _, capability := range cfg.CapDrop {
		if capability == "ALL" {
			return nil
		}
	}
	return fmt.Errorf("trusted bridge pin VM did not drop all capabilities")
}

// StartPin creates or adopts only the exact dedicated, read-only pin VM. It
// never sets the ordinary VM owner label and never creates a writable volume.
func (d *AppleDriver) StartPin(ctx context.Context) error {
	if err := d.checkNetwork(ctx); err != nil {
		return err
	}
	items, err := d.inventory(ctx)
	if err != nil {
		return err
	}
	for _, existing := range items {
		if existing.Configuration.ID == d.pinID() || existing.Status.State != "running" {
			continue
		}
		for _, network := range existing.Configuration.Networks {
			if network.Network == d.network {
				return fmt.Errorf("VM %q already uses the sandbox network before PF admission", existing.Configuration.ID)
			}
		}
	}
	item, found, err := d.lookupPin(ctx)
	if err != nil {
		return err
	}
	if found {
		return d.verifyPin(item)
	}
	id := d.pinID()
	out, err := d.output(ctx, "create", "--name", id,
		"--label", pinOwnerLabel, "--label", appleWorkerLabel+"="+d.workerID,
		"--network", d.network, "--platform", "linux/arm64",
		"--cpus", "1", "--memory", "256M", "--read-only", "--cap-drop", "ALL",
		"--no-dns", "--uid", "1000", "--gid", "1000", "--entrypoint", "/bin/sleep",
		d.pinImage, "2147483647")
	if err != nil {
		return errors.Join(err, d.cleanupPin())
	}
	if strings.TrimSpace(string(out)) != id {
		return errors.Join(fmt.Errorf("pin create returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupPin())
	}
	out, err = d.output(ctx, "start", id)
	if err != nil {
		return errors.Join(err, d.cleanupPin())
	}
	if strings.TrimSpace(string(out)) != id {
		return errors.Join(fmt.Errorf("pin start returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupPin())
	}
	item, found, err = d.lookupPin(ctx)
	if err != nil || !found {
		return errors.Join(err, fmt.Errorf("pin VM missing after start"), d.cleanupPin())
	}
	if err := d.verifyPin(item); err != nil {
		return errors.Join(err, d.cleanupPin())
	}
	return nil
}

func (d *AppleDriver) cleanupPin() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, found, err := d.lookupPin(ctx)
	if err != nil || !found {
		return err
	}
	_, deleteErr := d.output(ctx, "delete", "--force", d.pinID())
	_, still, lookupErr := d.lookupPin(ctx)
	if still {
		return errors.Join(deleteErr, lookupErr, fmt.Errorf("pin VM remains after delete"))
	}
	return errors.Join(deleteErr, lookupErr)
}

// Ready is checked before guest creation and execution, and repeatedly while
// a guest command runs. A missing helper or pin always denies new work.
func (d *AppleDriver) Ready(ctx context.Context) error {
	item, found, err := d.lookupPin(ctx)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("trusted bridge pin VM is missing")
	}
	if err := d.verifyPin(item); err != nil {
		return err
	}
	return d.gate.Check(ctx)
}

// CleanupGuests removes only ordinary VMs bearing this worker's owner label.
// A failed deletion keeps the pin and PF anchor in place for safe recovery.
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

// StopPin refuses to drop the bridge while any other live VM uses its network.
func (d *AppleDriver) StopPin(ctx context.Context) error {
	items, err := d.inventory(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Configuration.ID == d.pinID() || item.Status.State != "running" {
			continue
		}
		for _, network := range item.Configuration.Networks {
			if network.Network == d.network {
				return fmt.Errorf("VM %q still uses the sandbox network", item.Configuration.ID)
			}
		}
	}
	return d.cleanupPin()
}
