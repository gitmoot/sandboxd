package guestagent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// BalloonArg is the kernel argument of a guest whose VM has a balloon with
// free page reporting (vm.FirecrackerConfig.Balloon). Free page reporting
// returns only pages the guest kernel has freed; page cache is not free, so
// the guest agent also frees it once the guest has gone quiet (IdleReclaim).
const BalloonArg = "sandboxd.balloon=1"

// Idle reclaim timing: the agent samples the guest's CPU time every
// ReclaimInterval, and a guest that stayed below ReclaimBusyShare of one CPU
// for ReclaimQuietFor is quiet.
const (
	ReclaimInterval  = 5 * time.Second
	ReclaimQuietFor  = 30 * time.Second
	ReclaimBusyShare = 0.05
)

// IdleReclaim decides when a quiet guest gives its caches back: once per
// quiet period, ReclaimQuietFor after the last busy interval. A guest that
// stays quiet is reclaimed only once; any busy interval starts a new period.
// The cost of a reclaim is that the next read of a dropped file comes from
// the virtual disk (in practice the host's page cache, which all VMs of the
// same image share) instead of guest memory.
type IdleReclaim struct {
	quiet time.Duration
	done  bool
}

// Observe records one interval of length elapsed in which the guest used
// busy CPU time (all CPUs together), and reports whether to reclaim now.
func (r *IdleReclaim) Observe(busy, elapsed time.Duration) bool {
	if elapsed <= 0 || float64(busy) > ReclaimBusyShare*float64(elapsed) {
		r.quiet, r.done = 0, false
		return false
	}
	r.quiet += elapsed
	if r.done || r.quiet < ReclaimQuietFor {
		return false
	}
	r.done = true
	return true
}

// userHZ is the unit of /proc/stat CPU times (USER_HZ, 100 on Linux).
const userHZ = 100

// ParseCPUBusy returns the guest's total busy CPU time from /proc/stat: all
// CPUs together, everything but idle and iowait.
func ParseCPUBusy(stat string) (time.Duration, error) {
	line, _, _ := strings.Cut(stat, "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, fmt.Errorf("/proc/stat: no cpu line")
	}
	var busy uint64
	for i, field := range fields[1:] {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("/proc/stat: %w", err)
		}
		// Columns: user nice system idle iowait irq softirq steal guest
		// guest_nice. guest and guest_nice are already part of user and
		// nice; idle and iowait are not busy.
		switch i {
		case 3, 4, 8, 9:
		default:
			busy += n
		}
	}
	return time.Duration(busy) * time.Second / userHZ, nil
}
