package control

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// TestUnsupportedFeaturesAreRefused: every unsupported E2B feature answers
// 501 with E2B's JSON error and its documented message, which the SDKs raise
// as "501: <message>" (Python SandboxException/VolumeException/
// SecretException/BuildException, JS SandboxError/BuildError).
func TestUnsupportedFeaturesAreRefused(t *testing.T) {
	driver := &fakeDriver{instances: map[string]vm.Instance{}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 3))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	for _, c := range []struct {
		method, path string
		body         any
		reason       string
	}{
		{http.MethodPost, "/sandboxes/" + id + "/pause", map[string]any{}, refusePause},
		{http.MethodPost, "/sandboxes/" + id + "/resume", map[string]any{}, refusePause},
		{http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","autoPause":true}`), "autoPause (pause and resume) is not supported"},
		{http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","autoResume":{"enabled":true}}`), "autoResume is not supported"},
		{http.MethodPost, "/sandboxes/" + id + "/snapshots", map[string]any{}, refuseSnapshots},
		{http.MethodGet, "/snapshots", nil, refuseSnapshots},
		{http.MethodDelete, "/templates/snap-1", nil, refuseTemplateDelete},
		{http.MethodPost, "/sandboxes/" + id + "/fork", map[string]any{}, refuseFork},
		{http.MethodPut, "/sandboxes/" + id + "/network", map[string]any{}, refuseNetwork},
		{http.MethodPost, "/volumes", map[string]any{"name": "v"}, refuseVolumes},
		{http.MethodGet, "/volumes/v", nil, refuseVolumes},
		{http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","volumeMounts":[{"name":"v","path":"/v"}]}`), "volume mounts are not supported"},
		{http.MethodPost, "/secrets", map[string]any{"name": "s"}, refuseSecrets},
		{http.MethodGet, "/secrets/s", nil, refuseSecrets},
		{http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","mcp":{"exa":{}}}`), "MCP gateways are not supported"},
		{http.MethodPost, "/v2/sandboxes", json.RawMessage(`{"templateID":"base","iam":{"tokens":{}}}`), "IAM options are not supported"},
		{http.MethodGet, "/teams", nil, refuseTeams},
		{http.MethodPost, "/v3/templates", map[string]any{"name": "x"}, refuseTemplates},
		{http.MethodPost, "/v2/templates/t/builds/b", map[string]any{}, refuseTemplates},
		{http.MethodGet, "/templates/t/files/abc", nil, refuseTemplates},
		{http.MethodGet, "/templates", nil, refuseTemplates},
	} {
		got := request(t, s, c.method, c.path, c.body)
		failure := decodeBody[e2bError](t, got.Body)
		want := c.reason + "; " + notSupportedDoc
		if got.Code != http.StatusNotImplemented || failure.Code != http.StatusNotImplemented || failure.Message != want {
			t.Errorf("%s %s: %d %s, want 501 %q", c.method, c.path, got.Code, got.Body.String(), want)
		}
	}
	// A refusal changes nothing: the sandbox still runs.
	if got := request(t, s, http.MethodGet, "/sandboxes/"+id, nil); got.Code != http.StatusOK {
		t.Fatalf("sandbox after refusals: %d", got.Code)
	}
	// An action on a gone or unknown sandbox stays a 404 (the SDKs' not
	// found), as on E2B; only a live sandbox gets the refusal.
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+id, nil); got.Code != http.StatusNoContent {
		t.Fatalf("kill: %d", got.Code)
	}
	for _, path := range []string{"/sandboxes/" + id + "/fork", "/sandboxes/" + id + "/pause", "/sandboxes/sandboxd-00000000000000000000000000000000/snapshots", "/sandboxes/bogus/fork"} {
		got := request(t, s, http.MethodPost, path, map[string]any{})
		if failure := decodeBody[e2bError](t, got.Body); got.Code != http.StatusNotFound || failure.Code != http.StatusNotFound {
			t.Errorf("%s on a gone sandbox: %d %s", path, got.Code, got.Body.String())
		}
	}
}

func TestTemplateAliasLookup(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), &fakeDriver{instances: map[string]vm.Instance{}}, mixedConfig(e2bBase, 1))
	got := request(t, s, http.MethodGet, "/templates/aliases/base", nil)
	if got.Code != http.StatusOK || got.Body.String() != "{\"templateID\":\"sandboxd-base\",\"public\":false}\n" {
		t.Fatalf("alias base: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, s, http.MethodGet, "/templates/aliases/missing", nil); got.Code != http.StatusNotFound {
		t.Fatalf("missing alias: %d %s", got.Code, got.Body.String())
	}
}

// Without an e2b template every such route stays the plain 404.
func TestStrictOnlyServiceKeepsPlainNotFound(t *testing.T) {
	s := openService(t, &fakeDriver{instances: map[string]vm.Instance{}})
	id := "sandboxd-00000000000000000000000000000000"
	for _, path := range []string{"/sandboxes/" + id + "/pause", "/sandboxes/" + id + "/logs", "/v2/sandboxes/" + id + "/logs",
		"/snapshots", "/volumes", "/secrets", "/v3/templates", "/templates/aliases/base"} {
		got := request(t, s, http.MethodGet, path, nil)
		if got.Code != http.StatusNotFound || got.Body.String() != "404 page not found\n" {
			t.Errorf("%s: %d %q", path, got.Code, got.Body.String())
		}
	}
}
