//go:build linux

package vm

import (
	"context"
	"fmt"
)

// HostMemory samples the host's memory for the capacity report: what VMs
// really use shows in MemAvailable, so shared snapshot pages count once.
func (d *FirecrackerDriver) HostMemory(context.Context) (HostMemory, error) {
	memory, err := d.host.HostMemory()
	if err != nil {
		return HostMemory{}, err
	}
	memory.FloorBytes = uint64(d.cfg.MemoryFloorMiB) << 20
	return memory, nil
}

// checkMemoryFloor refuses a new VM while the host's available memory is
// below MemoryFloorMiB. A VM's memory.max still caps what it can take; the
// floor keeps the host from admitting VMs it cannot back.
func (d *FirecrackerDriver) checkMemoryFloor() error {
	if d.cfg.MemoryFloorMiB == 0 {
		return nil
	}
	memory, err := d.host.HostMemory()
	if err != nil {
		return err
	}
	if floor := uint64(d.cfg.MemoryFloorMiB) << 20; memory.AvailableBytes < floor {
		return fmt.Errorf("%w: %d MiB available, floor %d MiB", ErrMemoryPressure, memory.AvailableBytes>>20, d.cfg.MemoryFloorMiB)
	}
	return nil
}
