//go:build linux

package vm

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// kvmSnapshotSpec is the shape the snapshot KVM tests create.
func kvmSnapshotSpec(image, id string, slot int) Spec {
	return Spec{ID: id, Image: image, Network: FirecrackerSlotNames(2)[slot], CPUs: 1, MemoryMiB: 512}
}

// kvmTemplate cold boots one VM, waits for the template snapshot build it
// starts and removes the VM: the next create of that shape restores. A
// snapshot an earlier run left is used as it is.
func kvmTemplate(t *testing.T, d *FirecrackerDriver, image string) {
	t.Helper()
	ctx := t.Context()
	if _, err := d.Create(ctx, kvmSnapshotSpec(image, fcTestID, 0)); err != nil {
		t.Fatal(err)
	}
	if done := buildDone(d); done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Minute):
			t.Fatal("template snapshot build did not end")
		}
	}
	if names, err := readDirNames(d.snapshotsDir()); err != nil || len(names) != 1 {
		t.Fatalf("template snapshot not built (see the log): %v %v", names, err)
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
}

// TestFirecrackerKVMSnapshot restores two real clones of one template
// snapshot: each has its own randomness, the host's clock, and the network
// and firewall of a cold-booted VM.
func TestFirecrackerKVMSnapshot(t *testing.T) {
	d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0, func(c *FirecrackerConfig) { c.Snapshots = true })
	kvmTemplate(t, d, image)
	// The snapshot's clock falls behind meanwhile.
	time.Sleep(3 * time.Second)
	random := map[string]string{}
	for i, id := range []string{fcTestID, fcTestID2} {
		started := time.Now()
		if _, err := d.Create(ctx, kvmSnapshotSpec(image, id, i)); err != nil {
			t.Fatal(err)
		}
		took := time.Since(started)
		if meta, err := d.readMeta(id); err != nil || meta.Snapshot == "" {
			t.Fatalf("%s was not restored: %+v %v", id, meta, err)
		}
		code, out, stderr := kvmRun(ctx, t, d, id, "/bin/sh", "-c", `od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; echo; date +%s.%N`)
		host := float64(time.Now().UnixNano()) / 1e9
		fields := strings.Fields(out)
		if code != 0 || len(fields) != 2 {
			t.Fatalf("%s: %d %q %q", id, code, out, stderr)
		}
		guest, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.Abs(host-guest) > 2 {
			t.Fatalf("%s clock after restore: guest %s, host %.3f (%v)", id, fields[1], host, err)
		}
		for other, seen := range random {
			if seen == fields[0] {
				t.Fatalf("%s and %s read the same random bytes %s", id, other, seen)
			}
		}
		random[id] = fields[0]
		if got := kvmProbe(ctx, t, d, id, "1.1.1.1:443"); got != "open" {
			t.Fatalf("%s internet egress after restore: %s", id, got)
		}
		if got := kvmProbe(ctx, t, d, id, "1.0.0.1:443"); got != "closed" {
			t.Fatalf("%s reaches a denied prefix after restore: %s", id, got)
		}
		t.Logf("%s restored in %v; random %s; clock off by %.3fs", id, took.Round(time.Millisecond), fields[0], host-guest)
	}
}

// kvmMemory samples VM id's host memory: its cgroup's memory.current and
// the RSS and PSS of its processes, in KiB.
func kvmMemory(t *testing.T, d *FirecrackerDriver, id string) (current, rss, pss uint64) {
	t.Helper()
	host, ok := d.host.(*linuxFCHost)
	if !ok {
		t.Fatal("not the Linux host")
	}
	dir := host.cgroupPath(id)
	data, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		t.Fatal(err)
	}
	if current, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
		t.Fatal(err)
	}
	procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range strings.Fields(string(procs)) {
		rollup, err := os.ReadFile(filepath.Join("/proc", pid, "smaps_rollup"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(rollup), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[2] != "kB" {
				continue
			}
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "Rss:":
				rss += value
			case "Pss:":
				pss += value
			}
		}
	}
	return current >> 10, rss, pss
}

// percentile is the nearest-rank p-th percentile of sorted.
func percentile(sorted []time.Duration, p int) time.Duration {
	return sorted[max(0, (p*len(sorted)+99)/100-1)]
}

// TestFirecrackerKVMSnapshotBench compares cold boots with restores of a
// template snapshot: the time Create takes to return a VM that answers,
// over SANDBOXD_FC_BENCH creates each, and the host memory of two VMs
// running side by side.
func TestFirecrackerKVMSnapshotBench(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("SANDBOXD_FC_BENCH"))
	if n < 1 {
		t.Skip("set SANDBOXD_FC_BENCH=<creates per mode> to compare cold boots with restores")
	}
	for _, mode := range []struct {
		name      string
		snapshots bool
	}{{"cold", false}, {"restore", true}} {
		t.Run(mode.name, func(t *testing.T) {
			d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0, func(c *FirecrackerConfig) { c.Snapshots = mode.snapshots })
			if mode.snapshots {
				kvmTemplate(t, d, image)
			}
			times := make([]time.Duration, 0, n)
			for range n {
				started := time.Now()
				if _, err := d.Create(ctx, kvmSnapshotSpec(image, fcTestID, 0)); err != nil {
					t.Fatal(err)
				}
				times = append(times, time.Since(started))
				if meta, err := d.readMeta(fcTestID); err != nil || (meta.Snapshot != "") != mode.snapshots {
					t.Fatalf("record = %+v, %v", meta, err)
				}
				if err := d.Destroy(ctx, fcTestID); err != nil {
					t.Fatal(err)
				}
			}
			slices.Sort(times)
			t.Logf("%s: %d creates: p50 %v, p95 %v, min %v, max %v", mode.name, n, percentile(times, 50).Round(time.Millisecond),
				percentile(times, 95).Round(time.Millisecond), times[0].Round(time.Millisecond), times[n-1].Round(time.Millisecond))
			ids := []string{fcTestID, fcTestID2}
			for i, id := range ids {
				if _, err := d.Create(ctx, kvmSnapshotSpec(image, id, i)); err != nil {
					t.Fatal(err)
				}
				if code, _, stderr := kvmRun(ctx, t, d, id, "true"); code != 0 {
					t.Fatalf("%s: %d %s", id, code, stderr)
				}
			}
			time.Sleep(2 * time.Second)
			for _, id := range ids {
				current, rss, pss := kvmMemory(t, d, id)
				t.Logf("%s: VM %s: memory.current %d MiB, VMM RSS %d MiB, PSS %d MiB", mode.name, id, current>>10, rss>>10, pss>>10)
			}
		})
	}
}
