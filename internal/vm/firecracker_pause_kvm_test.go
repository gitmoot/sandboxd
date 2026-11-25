//go:build linux

package vm

import (
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFirecrackerKVMPause pauses and resumes two real clones of one template
// snapshot. A background process (same PID) and a written file survive
// every cycle; after a resume the clones read different random bytes, the
// agent answers on its re-bound vsock, and the rebuilt network enforces the
// same egress. Pause and resume latency is measured over
// SANDBOXD_FC_PAUSE_CYCLES (default 20) cycles of one clone.
func TestFirecrackerKVMPause(t *testing.T) {
	d, image, ctx := newKVMFirecracker(t, "SANDBOXD_FC_IMAGE", "review-amd64-*.ext4", 0, func(c *FirecrackerConfig) { c.Snapshots = true })
	kvmTemplate(t, d, image)
	ids := []string{fcTestID, fcTestID2}
	pids := map[string]string{}
	for i, id := range ids {
		if _, err := d.Create(ctx, kvmSnapshotSpec(image, id, i)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Destroy(t.Context(), id) })
		code, out, stderr := kvmRun(ctx, t, d, id, "/bin/sh", "-c",
			`echo kept-`+id+` > /root/pause-marker && sync; setsid sleep 100000 </dev/null >/dev/null 2>&1 & echo $!`)
		if code != 0 || strings.TrimSpace(out) == "" {
			t.Fatalf("%s: start background process: %d %q %q", id, code, out, stderr)
		}
		pids[id] = strings.TrimSpace(out)
	}
	survived := func(id string) {
		t.Helper()
		code, out, stderr := kvmRun(ctx, t, d, id, "/bin/sh", "-c", `kill -0 "$0" && cat /root/pause-marker`, pids[id])
		if code != 0 || strings.TrimSpace(out) != "kept-"+id {
			t.Fatalf("%s after resume: process %s or file lost: %d %q %q", id, pids[id], code, out, stderr)
		}
	}
	instance := func(id string) Instance {
		t.Helper()
		instances, err := d.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, instance := range instances {
			if instance.ID == id {
				return instance
			}
		}
		t.Fatalf("%s not listed", id)
		return Instance{}
	}

	for i, id := range ids {
		if err := d.Pause(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got := instance(id); !got.Paused || got.Running || got.Network != FirecrackerSlotNames(2)[i] {
			t.Fatalf("%s listed after pause as %+v", id, got)
		}
		entries, err := os.ReadDir(d.chroot(id))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Logf("%s chroot while paused: %v", id, names)
	}
	// The VMM is gone: a paused VM runs no guest code.
	if _, err := d.Run(ctx, fcTestID, Command{Args: []string{"/bin/true"}}, io.Discard, io.Discard); err == nil {
		t.Fatal("a paused VM ran a command")
	}
	random := map[string]string{}
	for _, id := range ids {
		if err := d.Resume(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got := instance(id); !got.Running || got.Paused {
			t.Fatalf("%s listed after resume as %+v", id, got)
		}
		survived(id)
		code, out, _ := kvmRun(ctx, t, d, id, "/bin/sh", "-c", `od -An -tx1 -N32 /dev/urandom | tr -d ' \n'`)
		if code != 0 || len(out) != 64 {
			t.Fatalf("%s random: %d %q", id, code, out)
		}
		for other, seen := range random {
			if seen == out {
				t.Fatalf("resumed clones %s and %s read the same random bytes %s", id, other, out)
			}
		}
		random[id] = out
		if got := kvmProbe(ctx, t, d, id, "1.1.1.1:443"); got != "open" {
			t.Fatalf("%s internet egress after resume: %s", id, got)
		}
		if got := kvmProbe(ctx, t, d, id, "1.0.0.1:443"); got != "closed" {
			t.Fatalf("%s reaches a denied prefix after resume: %s", id, got)
		}
	}

	cycles := 20
	if value := os.Getenv("SANDBOXD_FC_PAUSE_CYCLES"); value != "" {
		var err error
		if cycles, err = strconv.Atoi(value); err != nil || cycles < 1 {
			t.Fatalf("SANDBOXD_FC_PAUSE_CYCLES=%q", value)
		}
	}
	var pauses, resumes []time.Duration
	for range cycles {
		started := time.Now()
		if err := d.Pause(ctx, fcTestID); err != nil {
			t.Fatal(err)
		}
		pauses = append(pauses, time.Since(started))
		started = time.Now()
		if err := d.Resume(ctx, fcTestID); err != nil {
			t.Fatal(err)
		}
		resumes = append(resumes, time.Since(started))
	}
	survived(fcTestID)
	slices.Sort(pauses)
	slices.Sort(resumes)
	t.Logf("%d cycles of a %d MiB VM: pause p50 %v p95 %v max %v; resume p50 %v p95 %v max %v", cycles,
		kvmSnapshotSpec(image, fcTestID, 0).MemoryMiB,
		percentile(pauses, 50).Round(time.Millisecond), percentile(pauses, 95).Round(time.Millisecond), pauses[len(pauses)-1].Round(time.Millisecond),
		percentile(resumes, 50).Round(time.Millisecond), percentile(resumes, 95).Round(time.Millisecond), resumes[len(resumes)-1].Round(time.Millisecond))

	// A paused VM is destroyed whole: its VMM is gone already.
	if err := d.Pause(ctx, fcTestID2); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, fcTestID2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.jailDir(fcTestID2)); !os.IsNotExist(err) {
		t.Fatalf("destroyed paused VM left its jail: %v", err)
	}
}
