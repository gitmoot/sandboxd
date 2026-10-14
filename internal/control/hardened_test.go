package control

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/vm"
)

var hardenedBase = map[string]Template{
	"sandboxd-base": {Image: "linux-arm64-envd", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4", Hardened: true},
}

func TestParseTemplateHardened(t *testing.T) {
	_, template, err := ParseTemplate("id=h,profile=e2b,envd-version=0.9.0,hardened=true", "img")
	if err != nil || !template.Hardened {
		t.Fatalf("parsed %+v %v", template, err)
	}
	for _, spec := range []string{"id=p,profile=e2b,envd-version=0.9.0", "id=p,profile=e2b,envd-version=0.9.0,hardened=false"} {
		if _, plain, err := ParseTemplate(spec, "img"); err != nil || plain.Hardened {
			t.Fatalf("%s: parsed %+v %v", spec, plain, err)
		}
	}
	for _, spec := range []string{
		"id=s,hardened=true",                        // strict guests have no e2b init to harden
		"id=s,profile=gitmoot-strict,hardened=true", // nor when named
		"id=e,profile=e2b,envd-version=0.9.0,hardened=yes",
		"id=e,profile=e2b,envd-version=0.9.0,hardened=1",
		"id=e,profile=e2b,envd-version=0.9.0,hardened=true,hardened=true",
	} {
		if _, _, err := ParseTemplate(spec, "img"); err == nil {
			t.Errorf("%s: accepted", spec)
		}
	}
}

// Hardening reaches the local driver from a hardened template only.
func TestHardenedSpecReachesDriver(t *testing.T) {
	for _, c := range []struct {
		templates map[string]Template
		want      bool
	}{{hardenedBase, true}, {e2bBase, false}} {
		driver := newHardenedDriver()
		s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(c.templates, 1))
		createE2B(t, s, map[string]any{"templateID": "base"})
		specs := driver.recorded()
		if len(specs) != 1 || specs[0].Hardened != c.want || !specs[0].Envd {
			t.Fatalf("hardened template %v: specs %+v", c.want, specs)
		}
	}
	// A strict sandbox is never hardened.
	driver := newHardenedDriver()
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(hardenedBase, 1))
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-A", 1)); got.Code != http.StatusCreated {
		t.Fatalf("strict create: %d %s", got.Code, got.Body.String())
	}
	if specs := driver.recorded(); len(specs) != 1 || specs[0].Hardened || specs[0].Envd {
		t.Fatalf("strict specs %+v", specs)
	}
}

// A hardened sandbox runs on the gateway's local worker or nowhere, however
// much room an enrolled worker declaring the template has.
func TestHardenedSandboxNeverPlacedOnRemoteWorker(t *testing.T) {
	remote := newFakeWorker(t, "arm-1", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 4)
	driver := newHardenedDriver()
	cfg := mixedConfig(hardenedBase, 1)
	cfg.Arch = "arm64"
	cfg.Workers = []Remote{{ID: remote.id, Member: remote.client}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	body := map[string]any{"templateID": "base"}
	sandbox := createE2B(t, s, body)
	if row, err := s.ledger.Get(context.Background(), sandbox.ID); err != nil || row.WorkerID != "mac-local" {
		t.Fatalf("hardened sandbox placed on %q (%v)", row.WorkerID, err)
	}
	got := request(t, s, http.MethodPost, "/v2/sandboxes", body)
	if got.Code != http.StatusConflict {
		t.Fatalf("local full: %d %s", got.Code, got.Body.String())
	}
	if n := remote.driver.count(); n != 0 {
		t.Fatalf("remote worker ran %d VMs", n)
	}
}

// hardenedDriver is a local driver that declares hardened guest support.
type hardenedDriver struct{ *specDriver }

func (hardenedDriver) BootsHardened() {}

func newHardenedDriver() hardenedDriver {
	return hardenedDriver{&specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}}
}

// A hardened template the local driver cannot serve is a startup error,
// never a sandbox booted without hardening. Support is what the driver
// declares, whatever it is called.
func TestOpenRefusesUnservableHardenedTemplate(t *testing.T) {
	for _, name := range []string{"apple", "devvm", "firecracker", "future"} {
		cfg := mixedConfig(hardenedBase, 1)
		cfg.DriverName = name
		driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
		if s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg); err == nil || !strings.Contains(err.Error(), "firecracker") {
			if s != nil {
				_ = s.Close()
			}
			t.Fatalf("%s driver: %v", name, err)
		}
	}
	cfg := mixedConfig(hardenedBase, 1)
	cfg.DriverName = "anything"
	driver := newHardenedDriver()
	openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)

	// Served only by enrolled workers: refused too.
	remoteOnly := map[string]Template{"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, EnvdVersion: "0.2.4", Hardened: true}}
	cfg = mixedConfig(remoteOnly, 1)
	cfg.Arch = "arm64"
	if s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg); err == nil {
		_ = s.Close()
		t.Fatal("opened with a hardened template no local image serves")
	}
}

// A hardened guest's root is read-only: its volume mounts only below
// /home/user. A plain e2b template keeps any valid path.
func TestHardenedVolumePath(t *testing.T) {
	for _, c := range []struct {
		templates map[string]Template
		path      string
		ok        bool
	}{
		{hardenedBase, "/data", false},
		{hardenedBase, "/home/user", false},
		{hardenedBase, "/home/username", false},
		{hardenedBase, "/home/user/data", true},
		{e2bBase, "/data", true},
		{e2bBase, "/home/user/data", true},
	} {
		driver := newHardenedDriver()
		cfg := mixedConfig(c.templates, 1)
		cfg.Volumes = &fakeVolumes{}
		s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
		createVolume(t, s, "data")
		got := request(t, s, http.MethodPost, "/v2/sandboxes", mountBody([]map[string]string{{"name": "data", "path": c.path}}))
		if !c.ok {
			wantFailure(t, c.path, got, http.StatusBadRequest, "volumes mount only below /home/user")
			if specs := driver.recorded(); len(specs) != 0 {
				t.Fatalf("%s: refusal reached the driver: %+v", c.path, specs)
			}
			continue
		}
		if got.Code != http.StatusCreated {
			t.Fatalf("%s (hardened %v): %d %s", c.path, c.templates["sandboxd-base"].Hardened, got.Code, got.Body.String())
		}
		if specs := driver.recorded(); len(specs) != 1 || specs[0].Volume == nil || specs[0].Volume.Path != c.path {
			t.Fatalf("%s: specs %+v", c.path, specs)
		}
	}
}
