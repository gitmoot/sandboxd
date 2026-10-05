//go:build linux

package vm

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/egress"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from the generated ruleset (go test -run %s -update to accept):\n%s", path, t.Name(), got)
	}
}

// The generated tables, with and without the host port exception, for the
// default UID base and the shared deny list. Without it they are the tables
// sandboxd has always installed; with it each gains exactly one rule.
func TestFirecrackerRulesetGolden(t *testing.T) {
	deny4, deny6, err := egress.Deny(nil)
	if err != nil {
		t.Fatal(err)
	}
	d4, d6 := prefixStrings(deny4), prefixStrings(deny6)
	for _, tc := range []struct {
		name string
		port int
	}{{"", 0}, {"-hostport-8443", 8443}} {
		host := fcHostRuleset(2900000, 2901999, d4, d6, tc.port)
		netns := fcNetnsRuleset(d4, tc.port)
		checkGolden(t, "fc-host"+tc.name+".nft", host)
		checkGolden(t, "fc-netns"+tc.name+".nft", netns)
		if tc.port == 0 {
			continue
		}
		// The exception is the only difference, and it is first in its chain.
		hostRule := "\t\tmeta skuid 2901000-2901999 ip daddr 127.0.0.1 tcp dport 8443 accept\n"
		netnsRule := "\t\tiifname \"sbxvm0\" oifname \"sbxsl0\" ip daddr 10.0.2.2 tcp dport 8443 accept\n"
		if strings.Replace(host, hostRule, "", 1) != fcHostRuleset(2900000, 2901999, d4, d6, 0) ||
			!strings.Contains(host, "chain guest {\n"+hostRule) {
			t.Errorf("host table with a host port is not the plain table plus %q first", hostRule)
		}
		if strings.Replace(netns, netnsRule, "", 1) != fcNetnsRuleset(d4, 0) ||
			!strings.Contains(netns, "ct state established,related accept\n"+netnsRule) {
			t.Errorf("namespace table with a host port is not the plain table plus %q before the internet rule", netnsRule)
		}
	}
}

// The readback checks accept what nft 1.0.9 prints for the tables (captured
// from the real `nft -s list table` in testdata/*.readback) and refuse a
// missing, moved, widened or extra exception.
func TestFirecrackerHostPortReadback(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	host, hostPlain := read("fc-host-hostport-8443.readback"), read("fc-host.readback")
	netns, netnsPlain := read("fc-netns-hostport-8443.readback"), read("fc-netns.readback")
	if err := fcCheckHostPortState(host, 2901000, 2901999, 8443); err != nil {
		t.Fatal(err)
	}
	if err := fcCheckHostPortState(hostPlain, 2901000, 2901999, 0); err != nil {
		t.Fatal(err)
	}
	if err := fcCheckNetnsHostPortState(netns, 8443); err != nil {
		t.Fatal(err)
	}
	if err := fcCheckNetnsHostPortState(netnsPlain, 0); err != nil {
		t.Fatal(err)
	}
	const rule = "meta skuid 2901000-2901999 ip daddr 127.0.0.1 tcp dport 8443 accept"
	for name, state := range map[string]string{
		"missing":        hostPlain,
		"other port":     strings.Replace(host, "dport 8443", "dport 8444", 1),
		"vmm uids too":   strings.Replace(host, "skuid 2901000-2901999 ip", "skuid 2900000-2901999 ip", 1),
		"any address":    strings.Replace(host, " ip daddr 127.0.0.1", "", 1),
		"after a reject": strings.Replace(strings.Replace(host, "\t\t"+rule+"\n", "", 1), "\t}\n}\n", "\t\t"+rule+"\n\t}\n}\n", 1),
		"second accept":  strings.Replace(host, rule, rule+"\n\t\tmeta skuid 2901000-2901999 tcp dport 22 accept", 1),
	} {
		if err := fcCheckHostPortState(state, 2901000, 2901999, 8443); err == nil {
			t.Errorf("host readback %s: accepted", name)
		}
	}
	if err := fcCheckHostPortState(host, 2901000, 2901999, 0); err == nil {
		t.Error("host readback with an exception accepted when none is configured")
	}
	const nsRule = `iifname "sbxvm0" oifname "sbxsl0" ip daddr 10.0.2.2 tcp dport 8443 accept`
	for name, state := range map[string]string{
		"missing":     netnsPlain,
		"other port":  strings.Replace(netns, "dport 8443", "dport 8444", 1),
		"any port":    strings.Replace(netns, " tcp dport 8443", "", 1),
		"second rule": strings.Replace(netns, nsRule, nsRule+"\n\t\t"+strings.Replace(nsRule, "8443", "22", 1), 1),
		"input":       strings.Replace(netns, `iifname "lo" accept`, `iifname "lo" accept`+"\n\t\tip daddr 10.0.2.2 accept", 1),
	} {
		if err := fcCheckNetnsHostPortState(state, 8443); err == nil {
			t.Errorf("namespace readback %s: accepted", name)
		}
	}
	if err := fcCheckNetnsHostPortState(netns, 0); err == nil {
		t.Error("namespace readback with an exception accepted when none is configured")
	}
}

// A configured host port reaches both tables and the network setup; Arm
// fails closed when the installed table does not read back the exception,
// and the monitor's check then reports the table lost.
func TestFirecrackerHostPortArmAndCreate(t *testing.T) {
	d, fake, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) { c.HostPort = 8443 })
	if !strings.Contains(fake.firewall, "\t\tmeta skuid 2901000-2901999 ip daddr 127.0.0.1 tcp dport 8443 accept\n") {
		t.Fatalf("armed host table lacks the exception:\n%s", fake.firewall)
	}
	if _, err := d.Create(context.Background(), Spec{ID: fcTestID, Image: cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	network := fake.networks[0]
	if network.HostPort != 8443 || !strings.Contains(network.Ruleset, `ip daddr 10.0.2.2 tcp dport 8443 accept`) {
		t.Fatalf("network = %+v", network)
	}
	// The table changes under the daemon: the exception is widened.
	fake.mu.Lock()
	fake.firewall = strings.Replace(fake.firewall, " tcp dport 8443", "", 1)
	fake.mu.Unlock()
	if err := d.Ready(context.Background()); err == nil {
		t.Fatal("Ready accepted a changed exception")
	}
	if _, plainFake, _ := newTestFirecracker(t); strings.Contains(plainFake.firewall, "dport") {
		t.Fatalf("host table without a host port has an exception:\n%s", plainFake.firewall)
	}

	// An nft that silently drops the rule fails Arm.
	d2, fake2, _ := newTestFirecracker(t, func(c *FirecrackerConfig) { c.HostPort = 8443 })
	fake2.dropAccept = true
	if err := d2.Arm(context.Background()); err == nil || !strings.Contains(err.Error(), "host port exception") {
		t.Fatalf("Arm without the exception read back: %v", err)
	}
	if err := d2.Ready(context.Background()); err == nil {
		t.Fatal("driver is armed after a failed Arm")
	}
}
