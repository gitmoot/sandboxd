package main

import (
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gitmoot/sandboxd/internal/guestagent"
)

// idleReclaim runs for the life of a guest whose VM has a free-page-reporting
// balloon (guestagent.BalloonArg). Once the guest has been quiet for a while
// it writes back dirty pages, drops the page cache and reclaimable slab, and
// compacts memory: the dropped pages become free, and compaction gathers
// free pages into the 2 MiB blocks that free page reporting hands back to
// the host. It never stops the guest: a failure is logged and retried at the
// next quiet period.
func idleReclaim() {
	var policy guestagent.IdleReclaim
	last, err := cpuBusy()
	if err != nil {
		log.Printf("idle reclaim off: %v", err)
		return
	}
	at := time.Now()
	for range time.Tick(guestagent.ReclaimInterval) {
		busy, err := cpuBusy()
		if err != nil {
			log.Printf("idle reclaim off: %v", err)
			return
		}
		now := time.Now()
		reclaim := policy.Observe(busy-last, now.Sub(at))
		last, at = busy, now
		if !reclaim {
			continue
		}
		unix.Sync()
		// drop_caches 3: page cache and reclaimable slab; neither drops
		// anything dirty or in use. Then compact, in that order.
		for _, knob := range [][2]string{{"/proc/sys/vm/drop_caches", "3"}, {"/proc/sys/vm/compact_memory", "1"}} {
			if err := os.WriteFile(knob[0], []byte(knob[1]), 0); err != nil {
				log.Printf("idle reclaim: %v", err)
			}
		}
		// Measure the reclaim's own CPU time as part of this interval, not
		// as activity that ends the quiet period.
		if last, err = cpuBusy(); err != nil {
			log.Printf("idle reclaim off: %v", err)
			return
		}
	}
}

func cpuBusy() (time.Duration, error) {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	return guestagent.ParseCPUBusy(string(stat))
}
