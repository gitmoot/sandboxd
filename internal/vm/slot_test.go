package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/firewall"
)

var testSlotNetworks = []string{"sandboxd-slot-1", "sandboxd-slot-2"}

const testSlotNetworkList = `[{"id":"sandboxd-slot-1","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}},` +
	`{"id":"sandboxd-slot-2","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}},` +
	`{"id":"sandboxd-internal","configuration":{"mode":"hostOnly","labels":{"gitmoot.sandboxd.network":"apple-v1"}}}]`

func slotPinJSON(network, state string) string {
	return strings.NewReplacer(`"id":"`+firewall.PinID("mac-local", "sandboxd-internal")+`"`, `"id":"`+firewall.PinID("mac-local", network)+`"`,
		`"network":"sandboxd-internal"`, `"network":"`+network+`"`,
		`"state":"running"`, `"state":"`+state+`"`).Replace(testPinJSON)
}

func slotGuestJSON(id, state string, networks ...string) string {
	var attached []string
	for _, network := range networks {
		attached = append(attached, `{"network":"`+network+`"}`)
	}
	return `{"configuration":{"id":"` + id + `","labels":{"gitmoot.sandboxd.owner":"apple-v1","gitmoot.sandboxd.worker":"mac-local"},"networks":[` +
		strings.Join(attached, ",") + `]},"status":{"state":"` + state + `"}}`
}

func inventoryJSON(items ...string) string { return "[" + strings.Join(items, ",") + "]" }

// slotCLI fakes the Apple CLI. After "create --name X" the inventory becomes
// transitions[X]; after "start X" it becomes transitions[X+".started"].
type slotCLI struct {
	path, dir, calls string
}

func newSlotCLI(t *testing.T, inventory string, transitions map[string]string) *slotCLI {
	t.Helper()
	dir := t.TempDir()
	c := &slotCLI{path: filepath.Join(dir, "container"), dir: dir, calls: filepath.Join(dir, "calls")}
	c.setInventory(t, inventory)
	for name, next := range transitions {
		if err := os.WriteFile(filepath.Join(dir, "next."+name), []byte(next), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "volumes"), []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %[1]q
cd %[2]q
case "$1" in
  network) printf '%%s\n' %[3]q ;;
  volume)
    case "$2" in
      list) cat volumes ;;
      create) printf 'sandboxd-new\n'; printf '%%s\n' '[{"id":"sandboxd-new","configuration":{"labels":{"gitmoot.sandboxd.volume":"apple-v1","gitmoot.sandboxd.worker":"mac-local"}}}]' > volumes ;;
      delete) printf '[]\n' > volumes ;;
      *) exit 88 ;;
    esac ;;
  list) cat inventory ;;
  create) printf '%%s\n' "$3"; cat "next.$3" > inventory ;;
  start) printf '%%s\n' "$2"; cat "next.$2.started" > inventory ;;
  exec) exit 0 ;;
  *) exit 88 ;;
esac
`, c.calls, dir, testSlotNetworkList)
	if err := os.WriteFile(c.path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *slotCLI) setInventory(t *testing.T, inventory string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(c.dir, "inventory"), []byte(inventory), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (c *slotCLI) log(t *testing.T) string {
	t.Helper()
	calls, err := os.ReadFile(c.calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(calls)
}

func TestGuestCreateAttachesOnlyToItsSlotNetwork(t *testing.T) {
	pins := []string{slotPinJSON("sandboxd-slot-1", "running"), slotPinJSON("sandboxd-slot-2", "running")}
	cli := newSlotCLI(t, inventoryJSON(pins...), map[string]string{
		"sandboxd-new":         inventoryJSON(append(pins, slotGuestJSON("sandboxd-new", "stopped", "sandboxd-slot-2"))...),
		"sandboxd-new.started": inventoryJSON(append(pins, slotGuestJSON("sandboxd-new", "running", "sandboxd-slot-2"))...),
	})
	d, err := NewAppleDriver(cli.path, []string{"example/image:arm64"}, testSlotNetworks, "mac-local", testPinImage, &fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	spec := Spec{ID: "sandboxd-new", Image: "example/image:arm64", CPUs: 2, MemoryMiB: 512}
	for _, network := range []string{"", "sandboxd-internal", "default"} {
		spec.Network = network
		if _, err := d.Create(ctx, spec); err == nil {
			t.Fatalf("created a guest on non-slot network %q", network)
		}
	}
	// Another VM, even stopped, already holds slot 2.
	cli.setInventory(t, inventoryJSON(append(pins, slotGuestJSON("sandboxd-old", "stopped", "sandboxd-slot-2"))...))
	spec.Network = "sandboxd-slot-2"
	if _, err := d.Create(ctx, spec); err == nil {
		t.Fatal("created a second guest on an occupied slot network")
	}
	if strings.Contains(cli.log(t), "volume create") {
		t.Fatalf("refused create still allocated a volume:\n%s", cli.log(t))
	}
	cli.setInventory(t, inventoryJSON(pins...))
	instance, err := d.Create(ctx, spec)
	if err != nil || !instance.Running || instance.Network != "sandboxd-slot-2" {
		t.Fatalf("did not create the guest on its slot: %+v %v", instance, err)
	}
	var create string
	for _, line := range strings.Split(cli.log(t), "\n") {
		if strings.HasPrefix(line, "create --name sandboxd-new ") {
			create = line
		}
	}
	if strings.Count(create, "--network") != 1 || !strings.Contains(create, "--network sandboxd-slot-2 ") {
		t.Fatalf("guest not attached to exactly its slot network: %q", create)
	}
	listed, err := d.List(ctx)
	if err != nil || len(listed) != 1 || listed[0] != (Instance{ID: "sandboxd-new", Running: true, Network: "sandboxd-slot-2"}) {
		t.Fatalf("inventory lost the guest's slot network: %+v %v", listed, err)
	}
}

func TestEverySlotKeepsItsOwnVerifiedPin(t *testing.T) {
	pin1 := slotPinJSON("sandboxd-slot-1", "running")
	pin2ID := firewall.PinID("mac-local", "sandboxd-slot-2")
	cli := newSlotCLI(t, inventoryJSON(pin1), map[string]string{
		pin2ID:              inventoryJSON(pin1, slotPinJSON("sandboxd-slot-2", "stopped")),
		pin2ID + ".started": inventoryJSON(pin1, slotPinJSON("sandboxd-slot-2", "running")),
	})
	d, err := NewAppleDriver(cli.path, []string{"example/image:arm64"}, testSlotNetworks, "mac-local", testPinImage, &fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.Ready(ctx); err == nil {
		t.Fatal("ready without slot 2's pin")
	}
	cli.setInventory(t, inventoryJSON(pin1, slotGuestJSON("sandboxd-stale", "running", "sandboxd-slot-2")))
	if err := d.StartPin(ctx); err == nil {
		t.Fatal("started pins while a guest was live on a slot network")
	}
	cli.setInventory(t, inventoryJSON(pin1))
	if err := d.StartPin(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli.log(t), "create --name "+pin2ID+" ") || !strings.Contains(cli.log(t), "--network sandboxd-slot-2 ") ||
		strings.Contains(cli.log(t), "create --name "+firewall.PinID("mac-local", "sandboxd-slot-1")) {
		t.Fatalf("did not create exactly the missing slot pin:\n%s", cli.log(t))
	}
	if err := d.Ready(ctx); err != nil {
		t.Fatalf("rejected both verified slot pins: %v", err)
	}
	// Slot 2's pin moved onto slot 1's network: slot 2's bridge is unpinned.
	cli.setInventory(t, inventoryJSON(pin1, strings.Replace(slotPinJSON("sandboxd-slot-2", "running"), `"network":"sandboxd-slot-2"`, `"network":"sandboxd-slot-1"`, 1)))
	if err := d.Ready(ctx); err == nil {
		t.Fatal("accepted slot 2's pin attached to another slot")
	}
}

func TestDriverRequiresDistinctSlotNetworks(t *testing.T) {
	for _, networks := range [][]string{nil, {"sandboxd-slot-1", "sandboxd-slot-1"}, {"default"}} {
		if _, err := NewAppleDriver("/usr/local/bin/container", []string{"example/image:arm64"}, networks, "mac-local", testPinImage, &fakeGate{}); err == nil {
			t.Fatalf("accepted slot networks %q", networks)
		}
	}
}
