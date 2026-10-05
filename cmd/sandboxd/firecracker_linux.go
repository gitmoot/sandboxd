//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// startFirecracker arms the host firewall before any guest work. Guests that
// survived a daemon kill keep running behind the table, which outlives the
// daemon. The returned shutdown destroys every guest, then removes the table.
func startFirecracker(ctx context.Context, f firecrackerFlags, image string, slots []string) (isolatedDriver, func(context.Context) error, error) {
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
	driver, err := vm.NewFirecrackerDriver(vm.FirecrackerConfig{
		Root: *f.root, Firecracker: binary, Jailer: jailer, Kernel: *f.kernel, Images: []string{image}, Slots: slots,
		UIDBase: *f.uidBase, HomeDiskMiB: *f.homeDiskMiB, DiskFloorMiB: *f.diskFloorMiB,
		BootTimeout: *f.bootTimeout, ConsoleLog: *f.consoleLog,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := driver.Arm(ctx); err != nil {
		return nil, nil, fmt.Errorf("arm Firecracker host firewall: %w", err)
	}
	shutdown := func(ctx context.Context) error {
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
