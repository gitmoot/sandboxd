package vm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeAppleCLI(t *testing.T, inventory, networkInventory string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "inventory.json")
	volumes := filepath.Join(dir, "volumes.json")
	log := filepath.Join(dir, "calls")
	cli := filepath.Join(dir, "container")
	if err := os.WriteFile(state, []byte(inventory), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(volumes, []byte("[]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// This executable stands in for the configured Apple CLI, not the guest.
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$1" in
  network) printf '%%s\n' %q ;;
  volume)
    case "$2" in
      list) cat %q ;;
      create) printf 'sandboxd-new\n'; printf '%%s\n' '[{"id":"sandboxd-new","configuration":{"labels":{"gitmoot.sandboxd.volume":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}}}]' > %q ;;
      delete) printf '[]\n' > %q ;;
      *) exit 88 ;;
    esac ;;
  list) cat %q ;;
  create) printf 'sandboxd-new\n'; printf '%%s\n' '[{"configuration":{"id":"sandboxd-new","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}},"status":{"state":"stopped"}}]' > %q ;;
  start) printf 'sandboxd-new\n'; printf '%%s\n' '[{"configuration":{"id":"sandboxd-new","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}},"status":{"state":"running"}}]' > %q ;;
  delete) printf '[]\n' > %q ;;
  stats) printf '%%s\n' '[{"id":"sandboxd-new","cpuUsageUsec":7,"memoryUsageBytes":41943040,"memoryLimitBytes":536870912}]' ;;
  exec)
    if [ "$2" = "--interactive" ]; then cat > %q; exit 0; fi
    if [ "$3" = "0:0" ]; then exit 0; fi
    printf 'guest stdout'; printf 'guest stderr' >&2; exit 17 ;;
  *) exit 88 ;;
esac
`, log, networkInventory, volumes, volumes, volumes, state, state, state, state, log+".input")
	if err := os.WriteFile(cli, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return cli, log
}

func TestAppleInventoryOwnershipAndDestroy(t *testing.T) {
	cli, log := fakeAppleCLI(t, `[
 {"configuration":{"id":"sandboxd-a1","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}},"status":{"state":"stopped"}},
 {"configuration":{"id":"sandboxd-b1","labels":{}},"status":{"state":"running"}},
 {"configuration":{"id":"sandboxd-c1","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"another-worker"}},"status":{"state":"running"}},
 {"configuration":{"id":"other","labels":{}},"status":{"state":"running"}}
]`, `[{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]`)
	d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	items, err := d.List(ctx)
	if err != nil || len(items) != 1 || items[0] != (Instance{ID: "sandboxd-a1"}) {
		t.Fatalf("stopped owned container missing from complete inventory: %v, %v", items, err)
	}
	if err := d.Destroy(ctx, "sandboxd-b1"); err == nil {
		t.Fatal("destroy accepted a foreign container with the same name prefix")
	}
	if err := d.Destroy(ctx, "sandboxd-c1"); err == nil {
		t.Fatal("destroy accepted a container belonging to another worker")
	}
	if err := d.Destroy(ctx, "../sandboxd-a1"); err == nil {
		t.Fatal("destroy accepted a path instead of a service-owned ID")
	}
	if err := d.Destroy(ctx, "sandboxd-a1"); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, "sandboxd-a1"); err != nil {
		t.Fatalf("repeat destroy should be idempotent: %v", err)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "delete --force sandboxd-a1") != 1 || strings.Contains(string(calls), "delete --force sandboxd-b1") {
		t.Fatalf("unexpected delete invocations: %s", calls)
	}
}

func TestAppleCreateExecAndBoundedCopy(t *testing.T) {
	cli, log := fakeAppleCLI(t, "[]\n", `[{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]`)
	d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := d.Create(ctx, Spec{ID: "sandboxd-new", Image: "untrusted:latest", CPUs: 2, MemoryMiB: 512}); err == nil {
		t.Fatal("create accepted an image outside the allowlist")
	}
	instance, err := d.Create(ctx, Spec{ID: "sandboxd-new", Image: "example/image:arm64", CPUs: 2, MemoryMiB: 512})
	if err != nil || !instance.Running || instance.ID != "sandboxd-new" {
		t.Fatalf("create did not start an owned VM: %v, %v", instance, err)
	}
	usage, err := d.Usage(ctx, instance.ID)
	if err != nil || usage.MemoryUsedBytes != 40<<20 || usage.MemoryLimitBytes != 512<<20 || usage.CPUUsedPct != 0 {
		t.Fatalf("incorrect measured VM sample: %+v, %v", usage, err)
	}
	var stdout, stderr bytes.Buffer
	var pid int
	code, err := d.Run(ctx, instance.ID, Command{
		Args: []string{"/bin/false", "-n"}, Dir: "/tmp", Env: map[string]string{"X": "value"},
		OnStart: func(hostCLIPID int) { pid = hostCLIPID },
	}, &stdout, &stderr)
	if err != nil || code != 17 || pid <= 0 || stdout.String() != "guest stdout" || stderr.String() != "guest stderr" {
		t.Fatalf("incorrect exec exit or streamed output: code=%d err=%v pid=%d stdout=%q stderr=%q", code, err, pid, stdout.String(), stderr.String())
	}
	if _, err := d.Run(ctx, instance.ID, Command{Args: []string{"/bin/id"}, User: "root"}, &stdout, &stderr); err == nil {
		t.Fatal("exec accepted root")
	}
	source := filepath.Join(t.TempDir(), "upload")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyIn(ctx, instance.ID, source, "/tmp/../escape"); err == nil {
		t.Fatal("copy accepted traversal")
	}
	if err := d.CopyIn(ctx, instance.ID, source, "/tmp/upload"); err != nil {
		t.Fatal(err)
	}
	uploaded, err := os.ReadFile(log + ".input")
	if err != nil || string(uploaded) != "payload" {
		t.Fatalf("guest stdin copy lost bytes: %q, %v", uploaded, err)
	}
	if err := os.Truncate(source, maxCopyBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyIn(ctx, instance.ID, source, "/tmp/upload"); err == nil {
		t.Fatal("copy accepted a file larger than its cap")
	}
	if err := d.Destroy(ctx, instance.ID); err != nil {
		t.Fatalf("guest and bounded volume teardown: %v", err)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"volume create --label gitmoot.sandboxd.volume=apple-v1 --label gitmoot.sandboxd.worker=mac-local --opt size=10g sandboxd-new",
		"--label gitmoot.sandboxd.owner=apple-v1 --label gitmoot.sandboxd.worker=mac-local",
		"network list --format json", "--network sandboxd-internal",
		"--platform linux/arm64", "--cpus 2 --memory 512M",
		"--read-only --mount type=volume,source=sandboxd-new,target=/home/user",
		"--tmpfs /tmp:size=512M,mode=1777", "--uid 1000 --gid 1000",
		"exec --user 0:0 sandboxd-new /bin/chown 1000:1000 /home/user",
		"exec --user 1000:1000 --workdir /tmp --env X=value sandboxd-new /bin/false -n",
		"stats --format json --no-stream sandboxd-new",
		"exec --interactive --user 1000:1000 sandboxd-new /bin/sh -c umask 077; cat > \"$1\" sh /tmp/upload",
		"volume delete sandboxd-new",
	} {
		if !strings.Contains(string(calls), expected) {
			t.Errorf("Apple CLI call missing %q: %s", expected, calls)
		}
	}
}

func TestAppleCreateRejectsUntrustedGuestNetwork(t *testing.T) {
	for _, network := range []string{
		`[{"id":"sandboxd-internal","configuration":{"mode":"nat","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]`,
		`[{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{}}}]`,
		`[]`,
	} {
		cli, calls := fakeAppleCLI(t, "[]", network)
		d, err := NewAppleDriver(cli, []string{"example/image:arm64"}, "sandboxd-internal", "mac-local")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Create(context.Background(), Spec{ID: "sandboxd-new", Image: "example/image:arm64", CPUs: 2, MemoryMiB: 512}); err == nil {
			t.Fatalf("created VM without owned host-only network: %s", network)
		}
		logged, err := os.ReadFile(calls)
		if err != nil || strings.Contains(string(logged), "volume create") {
			t.Fatalf("allocated a volume despite unsafe network: %s, %v", logged, err)
		}
	}
}
