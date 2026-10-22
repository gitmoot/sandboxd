package guestagent

import (
	"testing"
	"time"
)

// A guest is reclaimed once, ReclaimQuietFor after its last busy interval;
// staying quiet does not reclaim again, and new activity starts over.
func TestIdleReclaim(t *testing.T) {
	var r IdleReclaim
	step := ReclaimInterval
	idle := time.Duration(0)
	busy := step // a whole CPU for the interval
	quietSteps := int(ReclaimQuietFor / step)
	run := func(n int, cpu time.Duration) (fired []int) {
		for i := range n {
			if r.Observe(cpu, step) {
				fired = append(fired, i)
			}
		}
		return fired
	}
	if got := run(3, busy); got != nil {
		t.Fatalf("busy guest reclaimed at %v", got)
	}
	if got := run(quietSteps*3, idle); len(got) != 1 || got[0] != quietSteps-1 {
		t.Fatalf("quiet guest reclaimed at steps %v, want only %d", got, quietSteps-1)
	}
	// Just above the busy share: activity, not quiet.
	if run(1, time.Duration(ReclaimBusyShare*float64(step))+time.Millisecond) != nil {
		t.Fatal("busy interval reclaimed")
	}
	// At the busy share: still quiet, and a new period has begun.
	if got := run(quietSteps, time.Duration(ReclaimBusyShare*float64(step))); len(got) != 1 || got[0] != quietSteps-1 {
		t.Fatalf("second quiet period reclaimed at steps %v", got)
	}
}

func TestParseCPUBusy(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	stat := "cpu  100 20 30 9000 50 5 6 7 40 2\ncpu0 1 2 3 4 5 6 7 8 9 10\n"
	got, err := ParseCPUBusy(stat)
	// guest and guest_nice are inside user and nice; idle and iowait are not busy.
	if want := time.Duration(100+20+30+5+6+7) * 10 * time.Millisecond; err != nil || got != want {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
	for _, bad := range []string{"", "cpu0 1 2 3 4 5\n", "cpu 1 2 x 4 5\n", "cpu 1 2\n"} {
		if _, err := ParseCPUBusy(bad); err == nil {
			t.Fatalf("%q: no error", bad)
		}
	}
}
