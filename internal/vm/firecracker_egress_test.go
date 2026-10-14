//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/egress"
)

// The policy tables: the order of the guest rules is the policy, so the
// goldens pin it. The always-denied set comes before Allow (no policy
// reopens it, here 10.0.0.1 and 192.168.1.0/24), the host port exception
// before both, and every guest rule before the conntrack accept.
func TestFirecrackerEgressRulesetGolden(t *testing.T) {
	deny4, _, err := egress.Deny(nil)
	if err != nil {
		t.Fatal(err)
	}
	d4 := prefixStrings(deny4)
	for _, tc := range []struct {
		name   string
		port   int
		policy EgressPolicy
	}{
		{"empty", 0, EgressPolicy{}},
		{"allow-hostport-8443", 8443, EgressPolicy{Allow: prefixes(t, "1.2.3.4/32", "10.0.2.2/32")}},
		{"deny", 0, EgressPolicy{AllowInternet: true, Allow: prefixes(t, "10.0.0.1/32", "192.168.1.0/24"), Deny: prefixes(t, "8.8.8.0/24", "9.9.9.9/32")}},
	} {
		got := fcNetnsPolicyRuleset(d4, tc.port, tc.policy)
		checkGolden(t, "fc-netns-egress-"+tc.name+".nft", got)
		if err := fcCheckNetnsState(got, tc.port, fcEgressMarker(tc.policy)); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		forward := got[strings.Index(got, "chain forward {"):]
		order := []string{"@deny4 reject", "@allow4 accept", "comment", "ct state established,related accept"}
		if tc.port != 0 {
			order = append([]string{"tcp dport 8443 accept"}, order...)
		}
		last := -1
		for _, rule := range order {
			at := strings.Index(forward, rule)
			if at <= last {
				t.Errorf("%s: %q is not after the rules before it", tc.name, rule)
			}
			last = at
		}
	}
	// A policy table never equals the default one, whose rules differ.
	if fcNetnsPolicyRuleset(d4, 0, DefaultEgress()) == fcNetnsRuleset(d4, 0) {
		t.Fatal("default policy table is the plain table")
	}
	a, b := EgressPolicy{Allow: prefixes(t, "1.2.3.4/32")}, EgressPolicy{Deny: prefixes(t, "1.2.3.4/32")}
	if fcEgressMarker(a) == fcEgressMarker(b) || fcEgressMarker(a) != fcEgressMarker(EgressPolicy{Allow: prefixes(t, "1.2.3.4/32")}) {
		t.Fatal("egress marker does not identify the policy")
	}
}

func TestFirecrackerEgressReadbackCheck(t *testing.T) {
	policy := EgressPolicy{Allow: prefixes(t, "10.0.2.2/32")}
	table := fcNetnsPolicyRuleset(nil, 8443, policy)
	// The alias in a policy set is no second host port rule.
	if err := fcCheckNetnsState(table, 8443, fcEgressMarker(policy)); err != nil {
		t.Fatal(err)
	}
	if err := fcCheckNetnsState(table, 8443, fcEgressMarker(DefaultEgress())); err == nil {
		t.Fatal("readback of another policy accepted")
	}
	if err := fcCheckNetnsState(fcNetnsRuleset(nil, 8443), 8443, fcEgressMarker(policy)); err == nil {
		t.Fatal("readback of the plain table accepted for a policy")
	}
	if err := fcCheckNetnsState(table, 0, fcEgressMarker(policy)); err == nil {
		t.Fatal("unexpected host port exception accepted")
	}
	// What nft 1.0.9 prints for the allow golden (testdata/*.readback),
	// whose allow set lists the host alias.
	readback, err := os.ReadFile(filepath.Join("testdata", "fc-netns-egress-allow-hostport-8443.readback"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fcCheckNetnsState(string(readback), 8443, fcEgressMarker(EgressPolicy{Allow: prefixes(t, "1.2.3.4/32", "10.0.2.2/32")})); err != nil {
		t.Fatal(err)
	}
	if err := fcCheckNetnsState(string(readback), 8443, fcEgressMarker(policy)); err == nil {
		t.Fatal("readback of another policy accepted")
	}
}

func fcEnvdSpec(id, network string, policy *EgressPolicy) Spec {
	return Spec{ID: id, Image: "", Network: network, CPUs: 1, MemoryMiB: 512, Envd: true, Egress: policy}
}

func lastNetwork(t *testing.T, host *fakeFCHost) fcNetwork {
	t.Helper()
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.networks) == 0 {
		t.Fatal("no network created")
	}
	return host.networks[len(host.networks)-1]
}

func TestFirecrackerCreateWithEgress(t *testing.T) {
	ctx := context.Background()
	d, host, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) { c.HostPort = 8443 })
	plain := fcEnvdSpec(fcTestID, "sbx0", nil)
	plain.Image = cfg.Images[0]
	if _, err := d.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if network := lastNetwork(t, host); network.Ruleset != fcNetnsRuleset(d.deny4, 8443) || network.Marker != "" {
		t.Fatalf("a VM without a policy got another table:\n%s", network.Ruleset)
	}
	if got, err := d.Egress(ctx, fcTestID); err != nil || !egressEqual(got, DefaultEgress()) {
		t.Fatalf("egress of a VM without a policy: %+v, %v", got, err)
	}
	if record, err := os.ReadFile(d.metaPath(fcTestID)); err != nil || strings.Contains(string(record), "egress") {
		t.Fatalf("record of a VM without a policy: %s, %v", record, err)
	}

	asked := EgressPolicy{Allow: prefixes(t, "9.9.9.9/32", "1.2.3.4/24")}
	spec := fcEnvdSpec(fcTestID2, "sbx1", &asked)
	spec.Image = cfg.Images[0]
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	want := EgressPolicy{Allow: prefixes(t, "1.2.3.0/24", "9.9.9.9/32")}
	network := lastNetwork(t, host)
	if network.Ruleset != fcNetnsPolicyRuleset(d.deny4, 8443, want) || network.Marker != fcEgressMarker(want) {
		t.Fatalf("policy table:\n%s", network.Ruleset)
	}
	if got, err := d.Egress(ctx, fcTestID2); err != nil || !egressEqual(got, want) {
		t.Fatalf("recorded egress %+v, %v", got, err)
	}
	for _, id := range []string{fcTestID, fcTestID2} {
		if err := d.Destroy(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Egress(ctx, fcTestID2); !errors.Is(err, ErrNoVM) {
		t.Fatalf("egress of a destroyed VM: %v", err)
	}
}

func TestFirecrackerCreateRefusesEgress(t *testing.T) {
	ctx := context.Background()
	d, host, cfg := newTestFirecracker(t)
	for name, policy := range map[string]EgressPolicy{
		"ipv6":     {Allow: prefixes(t, "2001:db8::/32")},
		"too many": {Deny: make([]netip.Prefix, maxEgressTargets+1)},
	} {
		spec := fcEnvdSpec(fcTestID, "sbx0", &policy)
		spec.Image = cfg.Images[0]
		if _, err := d.Create(ctx, spec); err == nil {
			t.Errorf("%s policy accepted", name)
		}
	}
	strict := fcEnvdSpec(fcTestID, "sbx0", &EgressPolicy{})
	strict.Image, strict.Envd = cfg.Images[0], false
	if _, err := d.Create(ctx, strict); err == nil {
		t.Error("a gitmoot-strict guest took an egress policy")
	}
	if len(host.networks) != 0 {
		t.Fatal("a refused create built a network")
	}
}

func TestFirecrackerUpdateEgress(t *testing.T) {
	ctx := context.Background()
	d, host, cfg := newTestFirecracker(t)
	spec := fcEnvdSpec(fcTestID, "sbx0", nil)
	spec.Image = cfg.Images[0]
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	netns := fcNetnsPrefix + fcTestID
	no := false
	deny := prefixes(t, "8.8.8.8/32")
	got, err := d.UpdateEgress(ctx, fcTestID, EgressUpdate{Deny: &deny})
	want := EgressPolicy{AllowInternet: true, Deny: deny}
	if err != nil || !egressEqual(got, want) {
		t.Fatalf("deny update: %+v, %v", got, err)
	}
	if host.tables[netns] != fcNetnsPolicyRuleset(d.deny4, 0, want) {
		t.Fatalf("namespace table after update:\n%s", host.tables[netns])
	}
	// Omitted fields keep their value.
	allow := prefixes(t, "1.1.1.1/32")
	got, err = d.UpdateEgress(ctx, fcTestID, EgressUpdate{AllowInternet: &no, Allow: &allow})
	want = EgressPolicy{Allow: allow, Deny: deny}
	if err != nil || !egressEqual(got, want) {
		t.Fatalf("internet update: %+v, %v", got, err)
	}
	if host.tables[netns] != fcNetnsPolicyRuleset(d.deny4, 0, want) {
		t.Fatalf("namespace table after update:\n%s", host.tables[netns])
	}
	// The record carries it across a daemon restart.
	restarted, err := newFirecrackerDriver(cfg, host)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Egress(ctx, fcTestID); err != nil || !egressEqual(got, want) {
		t.Fatalf("egress after restart: %+v, %v", got, err)
	}
	if entries, err := os.ReadDir(d.runDir()); err != nil || len(entries) != 1 {
		t.Fatalf("record directory holds %v, %v", entries, err)
	}
	if info, err := os.Stat(d.metaPath(fcTestID)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten record: %v, %v", info, err)
	}

	if _, err := d.UpdateEgress(ctx, fcTestID2, EgressUpdate{Deny: &deny}); !errors.Is(err, ErrNoVM) {
		t.Fatalf("update of an unknown VM: %v", err)
	}
	if _, err := d.Egress(ctx, fcTestID2); !errors.Is(err, ErrNoVM) {
		t.Fatalf("egress of an unknown VM: %v", err)
	}
	bad := prefixes(t, "2001:db8::/32")
	if _, err := d.UpdateEgress(ctx, fcTestID, EgressUpdate{Allow: &bad}); err == nil {
		t.Fatal("IPv6 update accepted")
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateEgress(ctx, fcTestID, EgressUpdate{Deny: &deny}); !errors.Is(err, ErrNoVM) {
		t.Fatalf("update of a destroyed VM: %v", err)
	}
}

// A failed update leaves the VM on its recorded policy: the table is put
// back and the record kept.
func TestFirecrackerUpdateEgressRollsBack(t *testing.T) {
	ctx := context.Background()
	d, host, cfg := newTestFirecracker(t)
	start := EgressPolicy{AllowInternet: true, Deny: prefixes(t, "8.8.8.8/32")}
	spec := fcEnvdSpec(fcTestID, "sbx0", &start)
	spec.Image = cfg.Images[0]
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	netns := fcNetnsPrefix + fcTestID
	before, err := os.ReadFile(d.metaPath(fcTestID))
	if err != nil {
		t.Fatal(err)
	}
	no := false
	check := func(name string) {
		t.Helper()
		if _, err := d.UpdateEgress(ctx, fcTestID, EgressUpdate{AllowInternet: &no}); err == nil {
			t.Fatalf("%s: update succeeded", name)
		}
		if host.tables[netns] != fcNetnsPolicyRuleset(d.deny4, 0, start) {
			t.Fatalf("%s: table not restored:\n%s", name, host.tables[netns])
		}
		if after, err := os.ReadFile(d.metaPath(fcTestID)); err != nil || string(after) != string(before) {
			t.Fatalf("%s: record changed: %s, %v", name, after, err)
		}
		if got, err := d.Egress(ctx, fcTestID); err != nil || !egressEqual(got, start) {
			t.Fatalf("%s: egress %+v, %v", name, got, err)
		}
	}

	// The record cannot be rewritten: its staging path is taken.
	staging := filepath.Join(cfg.Root, "run.tmp")
	if err := os.WriteFile(staging, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check("record")
	if err := os.Remove(staging); err != nil {
		t.Fatal(err)
	}

	// The new table does not read back.
	host.readback = func(ruleset string) string {
		if strings.Contains(ruleset, fcEgressMarker(start)) {
			return ruleset
		}
		return strings.Replace(ruleset, "comment", "", 1)
	}
	check("readback")
	host.readback = nil

	// nft fails.
	host.failReplace = 1
	check("nft")
}

func TestFirecrackerRecordEgressIsStrict(t *testing.T) {
	ctx := context.Background()
	d, _, cfg := newTestFirecracker(t)
	spec := fcEnvdSpec(fcTestID, "sbx0", &EgressPolicy{Allow: prefixes(t, "1.2.3.4/32")})
	spec.Image = cfg.Images[0]
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Destroy(ctx, fcTestID) }()
	data, err := os.ReadFile(d.metaPath(fcTestID))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if meta, err := d.readMeta(fcTestID); err != nil || meta == nil || meta.Egress == nil {
		t.Fatalf("record %s read as %+v, %v", data, meta, err)
	}
	for name, policy := range map[string]any{
		"unmasked": map[string]any{"allowInternet": false, "allow": []string{"1.2.3.4/24"}},
		"ipv6":     map[string]any{"allowInternet": false, "deny": []string{"2001:db8::/32"}},
		"garbage":  map[string]any{"allowInternet": false, "allow": []string{"example.com"}},
		"type":     "open",
	} {
		record["egress"] = policy
		bad, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d.metaPath(fcTestID), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if meta, err := d.readMeta(fcTestID); err != nil || meta != nil {
			t.Errorf("%s policy record read as %+v, %v", name, meta, err)
		}
	}
	if err := os.WriteFile(d.metaPath(fcTestID), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
