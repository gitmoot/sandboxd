//go:build linux

package vm

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFirecrackerInstanceNames(t *testing.T) {
	for _, tc := range []struct {
		instance                          string
		table, parent, prefix, cgroupPath string
	}{
		{"", "sbx_fc", "sbx-fc", "sbx-", "/sys/fs/cgroup/sbx-fc"},
		{"phobos", "sbx_fc_phobos", "sbx-fc-phobos", "sbi-phobos-", "/sys/fs/cgroup/sbx-fc-phobos"},
	} {
		names := fcInstanceNames(tc.instance)
		if names != (fcNames{table: tc.table, cgroupParent: tc.parent, netnsPrefix: tc.prefix}) {
			t.Errorf("%q: names = %+v", tc.instance, names)
		}
		host := newLinuxFCHost(names)
		if host.table != tc.table || host.cgroupPath("") != tc.cgroupPath || host.cgroupPath("net-x") != tc.cgroupPath+"/net-x" {
			t.Errorf("%q: host table %q, cgroup %q", tc.instance, host.table, host.cgroupPath(""))
		}
	}
	for _, name := range []string{"", "a", "phobos", "abcdefghijkl", "x1"} {
		if err := ValidateFirecrackerInstance(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
	for _, name := range []string{"default", "abcdefghijklm", "1x", "Phobos", "pho-bos", "pho_bos", "pho.bos", " x"} {
		if err := ValidateFirecrackerInstance(name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	_, _, base := newTestFirecracker(t)
	base.Instance = "default"
	if _, err := newFirecrackerDriver(base, newFakeFCHost(t)); err == nil {
		t.Error("driver accepted instance \"default\"")
	}
}

// A named instance's host table carries its own name and only its own UIDs,
// so its host port is granted to its own NAT UIDs alone; its VMs get its
// namespaces and cgroup parent.
func TestFirecrackerNamedInstanceHostState(t *testing.T) {
	d, host, cfg := newTestFirecracker(t, func(c *FirecrackerConfig) {
		c.Instance, c.UIDBase, c.HostPort = "phobos", 3000000, 8443
	})
	_, _, plain := newTestFirecracker(t, func(c *FirecrackerConfig) { c.HostPort = 8443 })
	want := fcHostRuleset("sbx_fc_phobos", 3000000, 3001999, d.deny4, d.deny6, 8443)
	if host.firewall != want || d.HostTable() != "sbx_fc_phobos" {
		t.Fatalf("host table %q:\n%s", d.HostTable(), host.firewall)
	}
	defaultTable := fcHostRuleset(fcHostTable, plain.UIDBase, plain.UIDBase+1999, d.deny4, d.deny6, 8443)
	renamed := strings.NewReplacer("table inet sbx_fc {", "table inet sbx_fc_phobos {",
		"meta skuid 2900000-2901999 jump", "meta skuid 3000000-3001999 jump",
		"meta skuid 2901000-2901999 ip daddr", "meta skuid 3001000-3001999 ip daddr").Replace(defaultTable)
	if renamed != want {
		t.Errorf("named table is not the default table with its name and UIDs:\n%s", want)
	}
	ctx := context.Background()
	spec := fcEnvdSpec(fcTestID, "sbx1", nil)
	spec.Image = cfg.Images[0]
	if _, err := d.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if n := host.networks[0]; n.Netns != "sbi-phobos-"+fcTestID || n.Cgroup != "net-"+fcTestID || n.NetUID != 3001001 || n.VMMUID != 3000001 {
		t.Fatalf("network = %+v", n)
	}
	args := host.vmmArgs[0]
	for flag, want := range map[string]string{
		"--uid": "3000001", "--netns": "/run/netns/sbi-phobos-" + fcTestID, "--parent-cgroup": "sbx-fc-phobos",
	} {
		if got := argAfter(args, flag); got != want {
			t.Errorf("%s = %q, want %q", flag, got, want)
		}
	}
	deny := prefixes(t, "8.8.8.8/32")
	if _, err := d.UpdateEgress(ctx, fcTestID, EgressUpdate{Deny: &deny}); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, fcTestID); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	calls := slices.Clone(host.calls)
	host.mu.Unlock()
	for _, want := range []string{"network sbi-phobos-" + fcTestID, "netns firewall sbi-phobos-" + fcTestID, "netns delete sbi-phobos-" + fcTestID} {
		if !slices.Contains(calls, want) {
			t.Errorf("no %q in %q", want, calls)
		}
	}
}

// Each instance's inventory sees only its own namespaces: the default
// ignores every sbi-*, a named one every sbx-* and other instances' sbi-*,
// including names that merely share a prefix.
func TestFirecrackerInstanceInventoryIgnoresOtherInstances(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		instance string
		foreign  []string
		own      string
	}{
		{"", []string{"sbi-phobos-", "sbi-pho-"}, "sbx-"},
		{"phobos", []string{"sbx-", "sbi-pho-", "sbi-phobos2-", "sbi-deimos-"}, "sbi-phobos-"},
		{"pho", []string{"sbx-", "sbi-phobos-"}, "sbi-pho-"},
	} {
		d, host, _ := newTestFirecracker(t, func(c *FirecrackerConfig) { c.Instance = tc.instance })
		for _, prefix := range tc.foreign {
			host.netns[prefix+fcTestID] = true
		}
		if list, err := d.List(ctx); err != nil || len(list) != 0 {
			t.Errorf("%q: list = %+v, %v", tc.instance, list, err)
		}
		host.netns[tc.own+fcTestID2] = true
		if list, err := d.List(ctx); err != nil || !slices.Equal(list, []Instance{{ID: fcTestID2}}) {
			t.Errorf("%q: own namespace: list = %+v, %v", tc.instance, list, err)
		}
	}
}

// newClaimDriver is a driver of instance on its own root, armed but not yet
// claimed, with claims in dir.
func newClaimDriver(t *testing.T, dir, instance string, uidBase int, mutate ...func(*FirecrackerConfig)) *FirecrackerDriver {
	t.Helper()
	d, _, _ := newTestFirecracker(t, append([]func(*FirecrackerConfig){func(c *FirecrackerConfig) {
		c.Instance, c.ClaimDir, c.UIDBase = instance, dir, uidBase
	}}, mutate...)...)
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.claim != nil {
			_ = d.claim.Close()
		}
	})
	return d
}

// kill drops the claim's lock without removing it, as kill -9 does.
func (d *FirecrackerDriver) kill() {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.claim.Close()
	d.claim = nil
}

func wantClaimError(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("claim accepted, want an error with %q", parts)
	}
	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q lacks %q", err, part)
		}
	}
}

func TestFirecrackerClaims(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claims")
	def := newClaimDriver(t, dir, "", 2900000)
	if err := def.Claim(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("claim dir: %v %v", info, err)
	}
	var claim fcClaim
	data, err := os.ReadFile(filepath.Join(dir, "default.json"))
	if err == nil {
		err = json.Unmarshal(data, &claim)
	}
	if err != nil || claim != (fcClaim{Root: def.cfg.Root, UIDLow: 2900000, UIDHigh: 2901999}) {
		t.Fatalf("default claim = %+v, %v", claim, err)
	}
	phobos := newClaimDriver(t, dir, "phobos", 3000000)
	if err := phobos.Claim(); err != nil {
		t.Fatal(err)
	}

	// The same name twice, whatever its configuration.
	wantClaimError(t, newClaimDriver(t, dir, "phobos", 3100000).Claim(), `instance "phobos" is already running`)
	wantClaimError(t, newClaimDriver(t, dir, "", 3100000).Claim(), `instance "default" is already running`)
	// Another name on phobos's root, directly or through a symlink, or on
	// UIDs overlapping phobos's or the default instance's.
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(phobos.cfg.Root, link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{phobos.cfg.Root, link} {
		err := newClaimDriver(t, dir, "deimos", 3100000, func(c *FirecrackerConfig) { c.Root = root }).Claim()
		wantClaimError(t, err, `would share root `+phobos.cfg.Root+` with instance "phobos"`, filepath.Join(dir, "phobos.json"), "stop it cleanly")
	}
	wantClaimError(t, newClaimDriver(t, dir, "deimos", 3001000).Claim(), `would share UIDs 3000000-3001999 with instance "phobos"`)
	wantClaimError(t, newClaimDriver(t, dir, "deimos", 2901999).Claim(), `would share UIDs 2900000-2901999 with instance "default"`)
	// A refused instance leaves no claim behind.
	if _, err := os.Stat(filepath.Join(dir, "deimos.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refused instance left a claim: %v", err)
	}
	deimos := newClaimDriver(t, dir, "deimos", 3002000)
	if err := deimos.Claim(); err != nil {
		t.Fatal(err)
	}

	// A killed daemon's claim stays and still counts against others; the
	// same instance restarted as it was takes it over, but not with other
	// UIDs or another root, whose guests its table would no longer confine.
	phobos.kill()
	wantClaimError(t, newClaimDriver(t, dir, "mars", 2999000).Claim(), `with instance "phobos"`)
	wantClaimError(t, newClaimDriver(t, dir, "phobos", 3100000, func(c *FirecrackerConfig) { c.Root = phobos.cfg.Root }).Claim(),
		`instance "phobos" last ran with root`, "remove "+filepath.Join(dir, "phobos.json"))
	wantClaimError(t, newClaimDriver(t, dir, "phobos", 3000000).Claim(), `instance "phobos" last ran with root`)
	// The same root spelled through a symlink is the same root.
	viaLink := newClaimDriver(t, dir, "phobos", 3000000, func(c *FirecrackerConfig) { c.Root = link })
	if err := viaLink.Claim(); err != nil {
		t.Fatalf("restart after kill through a symlinked root: %v", err)
	}
	viaLink.kill()
	restarted := newClaimDriver(t, dir, "phobos", 3000000, func(c *FirecrackerConfig) { c.Root = phobos.cfg.Root })
	if err := restarted.Claim(); err != nil {
		t.Fatalf("restart after kill: %v", err)
	}

	// A clean stop removes the claim, but only once it has disarmed.
	ctx := context.Background()
	if _, err := restarted.Create(ctx, Spec{ID: fcTestID, Image: restarted.cfg.Images[0], Network: "sbx0", CPUs: 1, MemoryMiB: 512}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Disarm(ctx); err == nil {
		t.Fatal("disarm with a VM accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "phobos.json")); err != nil {
		t.Fatalf("failed disarm dropped the claim: %v", err)
	}
	if err := restarted.CleanupGuests(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Disarm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "phobos.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("clean disarm kept the claim: %v", err)
	}
	if err := newClaimDriver(t, dir, "phobos", 3100000).Claim(); err != nil {
		t.Fatalf("claim after a clean stop: %v", err)
	}
}

// Two instances never share a volume directory: each one's in-use check
// sees only its own VMs, so both could attach one volume. An own claim that
// cannot be read is never assumed to match this run.
func TestFirecrackerClaimsVolumeDirAndUnreadableOwn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claims")
	volumes := filepath.Join(t.TempDir(), "volumes")
	withVolumes := func(c *FirecrackerConfig) { c.VolumeBudgetMiB, c.VolumeMiB, c.VolumeDir = 1024, 64, volumes }
	phobos := newClaimDriver(t, dir, "phobos", 3000000, withVolumes)
	if err := phobos.Claim(); err != nil {
		t.Fatal(err)
	}
	wantClaimError(t, newClaimDriver(t, dir, "deimos", 3100000, withVolumes).Claim(),
		`would share volume directory `+volumes+` with instance "phobos"`)
	// Without volumes the directory is no one's: no clash.
	if err := newClaimDriver(t, dir, "deimos", 3100000, func(c *FirecrackerConfig) { c.VolumeDir = volumes }).Claim(); err != nil {
		t.Fatalf("instance without volumes refused: %v", err)
	}

	phobos.kill()
	if err := os.WriteFile(filepath.Join(dir, "phobos.json"), []byte("{trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantClaimError(t, newClaimDriver(t, dir, "phobos", 3200000).Claim(), "of this instance is unreadable", "remove "+filepath.Join(dir, "phobos.json"))
}

// Without a default claim (a default daemon built before claims), a named
// instance refuses the default root and UIDs; a default claim that records
// others lifts that.
func TestFirecrackerClaimsAssumeUnclaimedDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claims")
	wantClaimError(t, newClaimDriver(t, dir, "phobos", FirecrackerDefaultUIDBase+1999).Claim(),
		"UIDs 2900000-2901999 with the default instance, which has no claim")
	wantClaimError(t, newClaimDriver(t, dir, "phobos", 3000000, func(c *FirecrackerConfig) { c.Root = FirecrackerDefaultRoot }).Claim(),
		"root /var/lib/sandboxd-fc with the default instance")
	def := newClaimDriver(t, dir, "", 2950000)
	if err := def.Claim(); err != nil {
		t.Fatal(err)
	}
	if err := newClaimDriver(t, dir, "phobos", FirecrackerDefaultUIDBase, func(c *FirecrackerConfig) { c.Root = FirecrackerDefaultRoot }).Claim(); err != nil {
		t.Fatalf("default claim elsewhere: %v", err)
	}
	// The default instance itself never assumes anything of named ones.
	dir2 := filepath.Join(t.TempDir(), "claims")
	if err := newClaimDriver(t, dir2, "", FirecrackerDefaultUIDBase).Claim(); err != nil {
		t.Fatal(err)
	}
}

func TestFirecrackerClaimDirMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	wantClaimError(t, newClaimDriver(t, dir, "", 2900000).Claim(), "not group or world writable")
	wantClaimError(t, newClaimDriver(t, "", "", 2900000).Claim(), "claim directory must be absolute")
}
