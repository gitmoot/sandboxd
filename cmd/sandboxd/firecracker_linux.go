//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// fcClaimDir holds the instance claims. A tmpfs: a claim lasts until reboot,
// exactly as long as guests can.
const fcClaimDir = "/run/sandboxd-fc"

// startFirecracker claims the instance, then arms the host firewall before
// any guest work. Guests that survived a daemon kill keep running behind the
// table, which outlives the daemon. The returned shutdown destroys every
// guest, then removes the table and the claim.
func startFirecracker(ctx context.Context, f firecrackerFlags, images, slots []string) (isolatedDriver, func(context.Context) error, error) {
	binary := *f.firecracker
	if binary == "" {
		binary = filepath.Join(*f.root, "bin", "firecracker")
	}
	jailer := *f.jailer
	if jailer == "" {
		jailer = filepath.Join(*f.root, "bin", "jailer")
	}
	if *f.kernel == "" {
		return nil, nil, errors.New("fc-kernel is required for the firecracker driver")
	}
	volumeDir := *f.volumeDir
	if volumeDir == "" {
		volumeDir = filepath.Join(*f.root, "volumes")
	}
	driver, err := vm.NewFirecrackerDriver(vm.FirecrackerConfig{
		Instance: *f.instance, ClaimDir: fcClaimDir,
		Root: *f.root, Firecracker: binary, Jailer: jailer, Kernel: *f.kernel, Images: images, Slots: slots,
		UIDBase: *f.uidBase, HomeDiskMiB: *f.homeDiskMiB, DiskFloorMiB: *f.diskFloorMiB,
		BootTimeout: *f.bootTimeout, ConsoleLog: *f.consoleLog, DenyCIDRs: *f.deny, HostPort: *f.hostPort,
		VolumeBudgetMiB: *f.volumeBudgetMiB, VolumeMiB: *f.volumeMiB, VolumeDir: volumeDir, Balloon: *f.balloon,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := driver.Claim(); err != nil {
		return nil, nil, err
	}
	if err := driver.Arm(ctx); err != nil {
		return nil, nil, fmt.Errorf("arm Firecracker host firewall: %w", err)
	}
	// A guest whose table may lag its recorded policy must not serve until
	// the table is brought up to the record.
	if err := driver.ReapplyEgress(ctx); err != nil {
		return nil, nil, err
	}
	log.Printf("Firecracker guests confined by nftables table inet %s and per-VM namespaces", driver.HostTable())
	// Re-check the table the moment the host ruleset changes. It stops
	// before shutdown, whose own Disarm is not a loss.
	eventsCtx, stopEvents := context.WithCancel(context.WithoutCancel(ctx))
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		driver.WatchFirewallEvents(eventsCtx)
	}()
	shutdown := func(ctx context.Context) error {
		stopEvents()
		<-eventsDone
		if err := driver.CleanupGuests(ctx); err != nil {
			return fmt.Errorf("leave firewall armed; guest cleanup failed: %w", err)
		}
		if err := driver.Disarm(ctx); err != nil {
			return fmt.Errorf("Firecracker firewall cleanup: %w", err)
		}
		return nil
	}
	return driver, shutdown, nil
}
