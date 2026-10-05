package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
)

const testSecret = "0123456789abcdef0123456789abcdef"

var e2bBase = map[string]Template{
	"sandboxd-base": {Image: "linux-arm64-envd", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4"},
}

// meteredDriver adds measured usage to the fake driver.
type meteredDriver struct {
	*fakeDriver
	usage vm.Usage
}

func (d *meteredDriver) Usage(context.Context, string) (vm.Usage, error) { return d.usage, nil }

func mixedConfig(templates map[string]Template, slots int) Config {
	names := make([]string, slots)
	for i := range names {
		names[i] = "slot-" + strconv.Itoa(i+1)
	}
	return Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64", Domain: "sandbox.example",
		WorkerID: "mac-local", CPUs: 2, MemoryMiB: 512, MaxVMs: slots, MaxTTL: time.Hour, Slots: names,
		Templates: templates, TokenSecret: []byte(testSecret)}
}

func openAt(t *testing.T, path string, driver vm.Driver, cfg Config) *Service {
	t.Helper()
	s, err := Open(context.Background(), path, driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func decodeBody[T any](t *testing.T, body *bytes.Buffer) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(body.Bytes(), &value); err != nil {
		t.Fatalf("decode %q: %v", body.String(), err)
	}
	return value
}

type e2bCreated struct {
	ID          string `json:"sandboxID"`
	TemplateID  string `json:"templateID"`
	ClientID    string `json:"clientID"`
	EnvdVersion string `json:"envdVersion"`
	Token       string `json:"envdAccessToken"`
	Domain      string `json:"domain"`
}

func TestTemplateRegistryResolvesAliasesAndRejectsConflicts(t *testing.T) {
	r, err := newRegistry("review-arm64", "linux-arm64", "arm64", e2bBase)
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"base": "sandboxd-base", "sandboxd-base": "sandboxd-base", "review-arm64": "review-arm64"} {
		if got, ok := r.lookup(name); !ok || got.ID != id {
			t.Fatalf("lookup %q = %+v %v, want %s", name, got, ok, id)
		}
	}
	if primary, _ := r.lookup("review-arm64"); primary.Profile != ProfileStrict || primary.Image != "linux-arm64" {
		t.Fatalf("primary template is not gitmoot-strict: %+v", primary)
	}
	if _, ok := r.lookup("code-interpreter-v1"); ok || !r.e2b {
		t.Fatal("unregistered template resolved, or e2b registration not recorded")
	}
	if base, _ := r.lookup("base"); base.Arch != "arm64" {
		t.Fatalf("template without an architecture did not get the local worker's: %+v", base)
	}
	// Without a local worker every template names its architecture, and no
	// template has a local image.
	if _, err := newRegistry("", "", "", map[string]Template{"x": {Profile: ProfileStrict}}); err == nil {
		t.Fatal("gateway without a local worker admitted a template without an architecture")
	}
	if _, err := newRegistry("", "", "", map[string]Template{"x": {Arch: "amd64", Image: "i"}}); err == nil {
		t.Fatal("gateway without a local worker admitted a local image")
	}
	if remote, err := newRegistry("", "", "", map[string]Template{"x": {Arch: "amd64"}}); err != nil || remote.byID["x"].Profile != ProfileStrict {
		t.Fatalf("remote-only strict template: %+v %v", remote, err)
	}
	for name, templates := range map[string]map[string]Template{
		"alias shadows primary":   {"x": {Image: "i", Profile: ProfileE2B, EnvdVersion: "0.2.4", Aliases: []string{"review-arm64"}}},
		"alias twice":             {"x": {Image: "i", Profile: ProfileE2B, EnvdVersion: "0.2.4", Aliases: []string{"base"}}, "y": {Image: "i", Profile: ProfileStrict, Aliases: []string{"base"}}},
		"unknown profile":         {"x": {Image: "i", Profile: "e2b-loose"}},
		"e2b without version":     {"x": {Image: "i", Profile: ProfileE2B}},
		"e2b version too old":     {"x": {Image: "i", Profile: ProfileE2B, EnvdVersion: "0.0.9"}},
		"e2b non-semver":          {"x": {Image: "i", Profile: ProfileE2B, EnvdVersion: "sandboxd-1"}},
		"strict with version":     {"x": {Image: "i", Profile: ProfileStrict, EnvdVersion: "0.2.4"}},
		"local image, other arch": {"x": {Arch: "amd64", Image: "i", Profile: ProfileStrict}},
		"unknown arch":            {"x": {Arch: "riscv64", Profile: ProfileStrict}},
		"flag-like image":         {"x": {Image: "--privileged", Profile: ProfileStrict}},
		"bad name":                {"bad name": {Image: "i", Profile: ProfileStrict}},
	} {
		if _, err := newRegistry("review-arm64", "linux-arm64", "arm64", templates); err == nil {
			t.Errorf("%s: registry accepted %+v", name, templates)
		}
	}
	cfg := mixedConfig(e2bBase, 1)
	cfg.TokenSecret = nil
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), &fakeDriver{instances: map[string]vm.Instance{}}, cfg); err == nil {
		t.Fatal("e2b template admitted without an envd token secret")
	}
}

func TestParseTemplateFlag(t *testing.T) {
	id, template, err := ParseTemplate("id=sandboxd-base,image=registry/base@sha256:ab,profile=e2b,alias=base,alias=default,envd-version=0.5.7", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Template{Image: "registry/base@sha256:ab", Profile: ProfileE2B, Aliases: []string{"base", "default"}, EnvdVersion: "0.5.7"}
	if id != "sandboxd-base" || template.Image != want.Image || template.Profile != want.Profile ||
		!slices.Equal(template.Aliases, want.Aliases) || template.EnvdVersion != want.EnvdVersion {
		t.Fatalf("parsed %q %+v", id, template)
	}
	if _, fixed, err := ParseTemplate("id=x,profile=gitmoot-strict", "dev-image"); err != nil || fixed.Image != "dev-image" {
		t.Fatalf("fixed image not applied: %+v %v", fixed, err)
	}
	for _, bad := range []string{
		"id=x,profile=e2b",                                 // no image, no envd version
		"id=x,image=i,profile=gitmoot-strict,id=y",         // repeated key
		"id=x,image=i,profile=gitmoot-strict,secure=false", // unknown key
		"id=x,image=i,profile=gitmoot-strict,alias",        // not key=value
		"id=x,image=other,profile=gitmoot-strict",          // with fixedImage below
	} {
		fixed := ""
		if strings.Contains(bad, "image=other") {
			fixed = "dev-image"
		}
		if _, _, err := ParseTemplate(bad, fixed); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	var flags TemplateFlags
	if err := flags.Set("id=x,image=i,profile=gitmoot-strict"); err != nil {
		t.Fatal(err)
	}
	if err := flags.Set("id=x,image=j,profile=gitmoot-strict"); err == nil {
		t.Fatal("template registered twice")
	}
	registered := map[string]Template{"a": {Image: "img-b"}, "b": {Image: "linux-arm64"}, "c": {Image: "img-b"}, "remote": {Arch: "amd64"}}
	if got := Images("linux-arm64", registered); !slices.Equal(got, []string{"linux-arm64", "img-b"}) {
		t.Fatalf("image allowlist %v", got)
	}
	if got := Declared("review", "linux-arm64", registered); len(got) != 4 || got["review"] != "linux-arm64" || got["a"] != "img-b" || got["remote"] != "" {
		t.Fatalf("local declaration %v", got)
	}
	if _, arch, err := ParseTemplate("id=x,arch=amd64", ""); err != nil || arch.Arch != "amd64" || arch.Profile != "" {
		t.Fatalf("arch-only registration: %+v %v", arch, err)
	}
}

func TestReadTokenSecretRequiresPrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenSecret(path); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if secret, err := ReadTokenSecret(path); err != nil || string(secret) != testSecret {
		t.Fatalf("secret %q %v", secret, err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenSecret(path); err == nil {
		t.Fatal("short secret accepted")
	}
}

// legacySandbox is the list item the service encoded before template
// profiles existed, field for field.
type legacySandbox struct {
	ID          string            `json:"sandboxID"`
	TemplateID  string            `json:"templateID"`
	StartedAt   time.Time         `json:"startedAt"`
	EndAt       time.Time         `json:"endAt"`
	CPUCount    int               `json:"cpuCount"`
	MemoryMB    int               `json:"memoryMB"`
	DiskSizeMB  int               `json:"diskSizeMB"`
	State       string            `json:"state"`
	EnvdVersion string            `json:"envdVersion"`
	Metadata    map[string]string `json:"metadata"`
	Domain      string            `json:"domain"`
}

// legacyList renders rows exactly as the pre-profile list handler did:
// sorted by ID, every item running with envdVersion sandboxd-1.
func legacyList(t *testing.T, s *Service, ids []string) string {
	t.Helper()
	sort.Strings(ids)
	items := make([]legacySandbox, 0, len(ids))
	for _, id := range ids {
		row, err := s.ledger.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		var metadata map[string]string
		if err := json.Unmarshal([]byte(row.Metadata), &metadata); err != nil {
			t.Fatal(err)
		}
		items = append(items, legacySandbox{ID: row.ID, TemplateID: row.TemplateID, StartedAt: row.Started, EndAt: row.Ends,
			CPUCount: 2, MemoryMB: 512, DiskSizeMB: 10 * 1024, State: "running", EnvdVersion: "sandboxd-1", Metadata: metadata, Domain: "sandbox.example"})
	}
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(items); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestStrictOnlyResponsesAreByteIdentical(t *testing.T) {
	// A further strict template is registered but no e2b one: Gitmoot's view
	// must be exactly the pre-profile one.
	strict := map[string]Template{"review-amd64": {Image: "linux-amd64", Profile: ProfileStrict}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), &fakeDriver{instances: map[string]vm.Instance{}}, mixedConfig(strict, 3))
	var ids []string
	for _, job := range []string{"job-A", "job-B", "job-C"} {
		created := request(t, s, http.MethodPost, "/sandboxes", createBody(job, 1))
		if created.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", job, created.Code, created.Body.String())
		}
		if strings.Contains(created.Body.String(), "clientID") {
			t.Fatalf("strict create response gained clientID: %s", created.Body.String())
		}
		ids = append(ids, decodeBody[e2bCreated](t, created.Body).ID)
	}
	got := request(t, s, http.MethodGet, "/v2/sandboxes?limit=100", nil)
	if got.Code != http.StatusOK || got.Body.String() != legacyList(t, s, slices.Clone(ids)) ||
		got.Header().Get("Content-Type") != "application/json" || got.Header().Get("X-Total-Running") != "3" || got.Header().Get("X-Next-Token") != "" {
		t.Fatalf("strict-only list changed:\n got %d %v %s\nwant %s", got.Code, got.Header(), got.Body.String(), legacyList(t, s, slices.Clone(ids)))
	}
	sort.Strings(ids)
	first := request(t, s, http.MethodGet, "/v2/sandboxes?limit=2", nil)
	if first.Header().Get("X-Next-Token") != ids[1] || first.Body.String() != legacyList(t, s, ids[:2]) {
		t.Fatalf("strict-only first page changed: %v %s", first.Header(), first.Body.String())
	}
	rest := request(t, s, http.MethodGet, "/v2/sandboxes?limit=2&nextToken="+ids[1], nil)
	if rest.Header().Get("X-Next-Token") != "" || rest.Body.String() != legacyList(t, s, ids[2:]) {
		t.Fatalf("strict-only last page changed: %v %s", rest.Header(), rest.Body.String())
	}
	unauthorized := httptestRequest(s, http.MethodGet, "/v2/sandboxes", "wrong-key", nil)
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Body.String() != "unauthorized\n" ||
		unauthorized.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("strict-only error format changed: %d %q", unauthorized.Code, unauthorized.Body.String())
	}
	if missing := request(t, s, http.MethodGet, "/sandboxes/sandboxd-"+strings.Repeat("0", 32), nil); missing.Code != http.StatusNotFound || missing.Body.String() != "sandbox unavailable\n" {
		t.Fatalf("strict-only 404 changed: %d %q", missing.Code, missing.Body.String())
	}
	if unrouted := request(t, s, http.MethodDelete, "/sandboxes/nonexistingsandbox", nil); unrouted.Code != http.StatusNotFound || unrouted.Body.String() != "404 page not found\n" {
		t.Fatalf("strict-only unrouted 404 changed: %d %q", unrouted.Code, unrouted.Body.String())
	}
	// Without an e2b template the v2 create and connect routes do not exist.
	for _, path := range []string{"/v2/sandboxes", "/v2/sandboxes/" + ids[0] + "/connect"} {
		v2 := request(t, s, http.MethodPost, path, map[string]any{"templateID": "review-arm64"})
		if v2.Code != http.StatusNotFound || v2.Body.String() != "404 page not found\n" || v2.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("strict-only POST %s changed: %d %q", path, v2.Code, v2.Body.String())
		}
	}
}

func httptestRequest(s *Service, method, path, key string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func createE2B(t *testing.T, s *Service, body map[string]any) e2bCreated {
	t.Helper()
	got := request(t, s, http.MethodPost, "/v2/sandboxes", body)
	if got.Code != http.StatusCreated {
		t.Fatalf("v2 create %v: %d %s", body, got.Code, got.Body.String())
	}
	return decodeBody[e2bCreated](t, got.Body)
}

type listed struct {
	ID          string            `json:"sandboxID"`
	ClientID    string            `json:"clientID"`
	TemplateID  string            `json:"templateID"`
	EnvdVersion string            `json:"envdVersion"`
	State       string            `json:"state"`
	Metadata    map[string]string `json:"metadata"`
	StartedAt   time.Time         `json:"startedAt"`
	EndAt       time.Time         `json:"endAt"`
}

func listIDs(t *testing.T, s *Service, query string) ([]string, http.Header) {
	t.Helper()
	got := request(t, s, http.MethodGet, "/v2/sandboxes"+query, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("list %s: %d %s", query, got.Code, got.Body.String())
	}
	var ids []string
	for _, item := range decodeBody[[]listed](t, got.Body) {
		ids = append(ids, item.ID)
	}
	return ids, got.Header()
}

func TestProfilesStaySeparate(t *testing.T) {
	driver := &meteredDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}},
		usage: vm.Usage{CPUUsedPct: 12.5, MemoryUsedBytes: 1 << 20, MemoryLimitBytes: 512 << 20}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 3))

	// v1 create serves only strict templates; v2 only e2b ones.
	if got := request(t, s, http.MethodPost, "/sandboxes", map[string]any{"templateID": "base", "timeout": 60, "secure": true,
		"metadata": map[string]string{"job_id": "j", "attempt": "1", "lifecycle_generation": "1"}}); got.Code != http.StatusBadRequest {
		t.Fatalf("v1 create of an e2b template: %d", got.Code)
	}
	if got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "review-arm64"}); got.Code != http.StatusBadRequest ||
		decodeBody[e2bError](t, got.Body).Code != http.StatusBadRequest {
		t.Fatalf("v2 create of a strict template: %d %s", got.Code, got.Body.String())
	}
	unknown := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "code-interpreter-v1"})
	if failure := decodeBody[e2bError](t, unknown.Body); unknown.Code != http.StatusNotFound || failure.Code != http.StatusNotFound || failure.Message == "" {
		t.Fatalf("unknown template: %d %s", unknown.Code, unknown.Body.String())
	}
	for _, option := range []map[string]any{
		{"templateID": "base", "autoPause": true},
		{"templateID": "base", "allow_internet_access": true},
		{"templateID": "base", "envVars": map[string]string{"A": "1"}},
		{"templateID": "base", "secure": false},
		{"templateID": "base", "brandNewOption": 1},
		{"templateID": "base", "timeout": 7200},
	} {
		if got := request(t, s, http.MethodPost, "/v2/sandboxes", option); got.Code != http.StatusBadRequest {
			t.Errorf("unsupported option %v: %d", option, got.Code)
		}
	}

	strict := request(t, s, http.MethodPost, "/sandboxes", createBody("job-A", 1))
	if strict.Code != http.StatusCreated || strings.Contains(strict.Body.String(), "clientID") {
		t.Fatalf("strict create: %d %s", strict.Code, strict.Body.String())
	}
	strictID := decodeBody[e2bCreated](t, strict.Body).ID
	// Owner metadata is optional for e2b; the SDK sends empty metadata and envVars.
	sdk := createE2B(t, s, map[string]any{"templateID": "base", "timeout": 60, "metadata": map[string]string{}, "envVars": map[string]string{}})
	if sdk.TemplateID != "sandboxd-base" || sdk.ClientID != "sandboxd" || sdk.EnvdVersion != "0.2.4" || sdk.Domain != "sandbox.example" ||
		!s.Authorize(sdk.ID, sdk.Token) || sdk.Token != s.envdToken(sdk.ID) {
		t.Fatalf("e2b create response: %+v", sdk)
	}

	strictInfo := request(t, s, http.MethodGet, "/sandboxes/"+strictID, nil)
	if strings.Contains(strictInfo.Body.String(), "clientID") || decodeBody[listed](t, strictInfo.Body).EnvdVersion != "sandboxd-1" {
		t.Fatalf("strict get changed: %s", strictInfo.Body.String())
	}
	info := decodeBody[listed](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID, nil).Body)
	if info.ClientID != "sandboxd" || info.EnvdVersion != "0.2.4" || info.State != "running" || info.TemplateID != "sandboxd-base" {
		t.Fatalf("e2b get: %+v", info)
	}

	// connect: e2b only; returns the same token and only ever extends.
	if got := request(t, s, http.MethodPost, "/v2/sandboxes/"+strictID+"/connect", map[string]any{}); got.Code != http.StatusConflict {
		t.Fatalf("connect to a strict sandbox: %d", got.Code)
	}
	reconnected := decodeBody[e2bCreated](t, request(t, s, http.MethodPost, "/v2/sandboxes/"+sdk.ID+"/connect", map[string]any{"timeout": 10}).Body)
	if reconnected.Token != sdk.Token || reconnected.ID != sdk.ID {
		t.Fatalf("connect returned another capability: %+v", reconnected)
	}
	if after := decodeBody[listed](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID, nil).Body); !after.EndAt.Equal(info.EndAt) {
		t.Fatalf("connect shortened the timeout: %v -> %v", info.EndAt, after.EndAt)
	}
	request(t, s, http.MethodPost, "/v2/sandboxes/"+sdk.ID+"/connect", map[string]any{"timeout": 600})
	if after := decodeBody[listed](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID, nil).Body); !after.EndAt.After(info.EndAt) {
		t.Fatalf("connect did not extend the timeout: %v -> %v", info.EndAt, after.EndAt)
	}
	missing := request(t, s, http.MethodPost, "/v2/sandboxes/sandboxd-"+strings.Repeat("0", 32)+"/connect", map[string]any{})
	if missing.Code != http.StatusNotFound || decodeBody[e2bError](t, missing.Body).Code != http.StatusNotFound {
		t.Fatalf("connect to unknown sandbox: %d %s", missing.Code, missing.Body.String())
	}

	// metrics: strict keeps its shape; e2b needs the driver's detailed sample.
	strictMetrics := request(t, s, http.MethodGet, "/sandboxes/"+strictID+"/metrics", nil)
	if strings.Contains(strictMetrics.Body.String(), "diskUsed") {
		t.Fatalf("strict metrics changed: %s", strictMetrics.Body.String())
	}
	if got := request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID+"/metrics", nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("e2b metrics from an undetailed sample: %d %s", got.Code, got.Body.String())
	}
	driver.usage.Detailed, driver.usage.MemoryCacheBytes, driver.usage.DiskUsedBytes, driver.usage.DiskTotalBytes = true, 4096, 8192, 10<<30
	metrics := decodeBody[[]e2bMetric](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID+"/metrics", nil).Body)
	if len(metrics) != 1 || metrics[0].DiskTotal != 10<<30 || metrics[0].DiskUsed != 8192 || metrics[0].MemCache != 4096 ||
		metrics[0].CPUCount != 2 || metrics[0].Timestamp == "" || metrics[0].TimestampUnix == 0 {
		t.Fatalf("e2b metrics: %+v", metrics)
	}
	past := time.Now().Add(-time.Hour).Unix()
	if old := decodeBody[[]e2bMetric](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID+"/metrics?start="+strconv.FormatInt(past, 10)+"&end="+strconv.FormatInt(past+60, 10), nil).Body); len(old) != 0 {
		t.Fatalf("metrics from before the sandbox existed: %+v", old)
	}

	// kill: E2B reports a second kill as not found; strict stays idempotent.
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+sdk.ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("kill: %d", got.Code)
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+sdk.ID, nil); got.Code != http.StatusNotFound || decodeBody[e2bError](t, got.Body).Code != http.StatusNotFound {
		t.Fatalf("second kill: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/nonexistingsandbox", nil); got.Code != http.StatusNotFound || decodeBody[e2bError](t, got.Body).Code != http.StatusNotFound {
		t.Fatalf("kill of a malformed ID: %d %s", got.Code, got.Body.String())
	}
	if s.Authorize(sdk.ID, sdk.Token) {
		t.Fatal("killed sandbox kept its envd capability")
	}
	for range 2 {
		if got := request(t, s, http.MethodDelete, "/sandboxes/"+strictID, nil); got.Code != http.StatusNoContent {
			t.Fatalf("strict delete: %d", got.Code)
		}
	}
	if got := httptestRequest(s, http.MethodGet, "/v2/sandboxes", "wrong-key", nil); got.Code != http.StatusUnauthorized ||
		decodeBody[e2bError](t, got.Body) != (e2bError{Code: http.StatusUnauthorized, Message: "unauthorized"}) {
		t.Fatalf("e2b 401 body: %s", got.Body.String())
	}
}

// TestMixedInventoryKeepsStrictViewComplete is the regression for the global
// identity check: on main, any row of another template made GET
// /v2/sandboxes return 503.
func TestMixedInventoryKeepsStrictViewComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	driver := &fakeDriver{instances: map[string]vm.Instance{}}
	strict2 := Template{Image: "linux-arm64-v2", Profile: ProfileStrict}
	both := map[string]Template{"sandboxd-base": e2bBase["sandboxd-base"], "review-v2": strict2}
	s, err := Open(context.Background(), path, driver, mixedConfig(both, 4))
	if err != nil {
		t.Fatal(err)
	}
	strictID := decodeBody[e2bCreated](t, request(t, s, http.MethodPost, "/sandboxes", createBody("job-A", 1)).Body).ID
	second2 := createBody("job-B", 1)
	second2["templateID"] = "review-v2"
	strict2ID := decodeBody[e2bCreated](t, request(t, s, http.MethodPost, "/sandboxes", second2).Body).ID
	first := createE2B(t, s, map[string]any{"templateID": "base", "metadata": map[string]string{"suite": "x", "n": "1"}})
	time.Sleep(2 * time.Millisecond)
	second := createE2B(t, s, map[string]any{"templateID": "sandboxd-base", "metadata": map[string]string{"suite": "x", "n": "2", "literal": "a%20b"}})

	all := request(t, s, http.MethodGet, "/v2/sandboxes?limit=100", nil)
	if all.Code != http.StatusOK || all.Header().Get("X-Total-Running") != "4" {
		t.Fatalf("mixed inventory: %d %v %s", all.Code, all.Header(), all.Body.String())
	}
	items := decodeBody[[]listed](t, all.Body)
	byID := map[string]listed{}
	for _, item := range items {
		byID[item.ID] = item
		if item.ClientID != "sandboxd" {
			t.Fatalf("listed item without clientID: %+v", item)
		}
	}
	if byID[strictID].EnvdVersion != "sandboxd-1" || byID[strictID].TemplateID != "review-arm64" || byID[first.ID].EnvdVersion != "0.2.4" || len(byID) != 4 {
		t.Fatalf("mixed inventory items: %+v", items)
	}

	// Filters: metadata, template (ID or alias), state, order and pages.
	metadata := "?metadata=" + url.QueryEscape("suite=x")
	if ids, _ := listIDs(t, s, metadata); !slices.Equal(ids, []string{second.ID, first.ID}) {
		t.Fatalf("metadata filter, newest first: %v", ids)
	}
	if ids, _ := listIDs(t, s, metadata+"&order=asc"); !slices.Equal(ids, []string{first.ID, second.ID}) {
		t.Fatalf("ascending order: %v", ids)
	}
	if ids, _ := listIDs(t, s, "?metadata="+url.QueryEscape("n=2&suite=x")); !slices.Equal(ids, []string{second.ID}) {
		t.Fatalf("two-key metadata filter: %v", ids)
	}
	// The JS SDK encodes each metadata pair twice.
	if ids, _ := listIDs(t, s, "?metadata="+url.QueryEscape(url.QueryEscape("n")+"="+url.QueryEscape("1"))); !slices.Equal(ids, []string{first.ID}) {
		t.Fatalf("double-encoded metadata filter: %v", ids)
	}
	// A literal value that is itself URL encoding matches as each SDK sends
	// it: Python URL-encodes the pairs once, JS encodes each key and value
	// once more first.
	for name, query := range map[string]string{
		"python": url.QueryEscape("literal=" + url.QueryEscape("a%20b")),
		"js":     url.QueryEscape("literal=" + url.QueryEscape(url.QueryEscape("a%20b"))),
	} {
		if ids, _ := listIDs(t, s, "?metadata="+query); !slices.Equal(ids, []string{second.ID}) {
			t.Fatalf("%s literal %%-value filter: %v", name, ids)
		}
	}
	if ids, _ := listIDs(t, s, "?metadata="+url.QueryEscape("literal=a b")); len(ids) != 0 {
		t.Fatalf("decoded form of a literal %%-value matched: %v", ids)
	}
	for _, template := range []string{"base", "sandboxd-base"} {
		if ids, _ := listIDs(t, s, "?template="+template); len(ids) != 2 || slices.Contains(ids, strictID) || slices.Contains(ids, strict2ID) {
			t.Fatalf("template filter %s: %v", template, ids)
		}
	}
	if ids, _ := listIDs(t, s, "?template=unknown-template"); len(ids) != 0 {
		t.Fatalf("unknown template filter: %v", ids)
	}
	if ids, _ := listIDs(t, s, "?state=paused"); len(ids) != 0 {
		t.Fatalf("paused filter: %v", ids)
	}
	if ids, _ := listIDs(t, s, "?state=running&state=paused"); len(ids) != 4 {
		t.Fatalf("running and paused filter: %v", ids)
	}
	if ids, _ := listIDs(t, s, "?state=running,paused"); len(ids) != 4 {
		t.Fatalf("comma state filter: %v", ids)
	}
	after := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	if ids, _ := listIDs(t, s, "?startedAfter="+url.QueryEscape(after)); len(ids) != 0 {
		t.Fatalf("startedAfter filter: %v", ids)
	}
	page, headers := listIDs(t, s, metadata+"&limit=1")
	if !slices.Equal(page, []string{second.ID}) || headers.Get("X-Next-Token") != second.ID {
		t.Fatalf("first page %v %v", page, headers)
	}
	if rest, headers := listIDs(t, s, metadata+"&limit=1&nextToken="+second.ID); !slices.Equal(rest, []string{first.ID}) || headers.Get("X-Next-Token") != "" {
		t.Fatalf("second page %v %v", rest, headers)
	}
	if got := request(t, s, http.MethodGet, "/v2/sandboxes?state=frozen", nil); got.Code != http.StatusBadRequest || decodeBody[e2bError](t, got.Body).Code != http.StatusBadRequest {
		t.Fatalf("invalid state filter: %d %s", got.Code, got.Body.String())
	}

	reopen := func(templates map[string]Template) *Service {
		t.Helper()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s, err = Open(context.Background(), path, driver, mixedConfig(templates, 4)); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The operator re-registers the e2b template as gitmoot-strict (same
	// image, so the worker keeps its VMs): its e2b rows are no longer
	// servable, but they never make the inventory a 503.
	rebased := map[string]Template{"sandboxd-base": {Image: "linux-arm64-envd", Profile: ProfileStrict, Aliases: []string{"base"}}, "review-v2": strict2}
	reopen(rebased)
	if ids, headers := listIDs(t, s, "?limit=100"); len(ids) != 2 || !slices.Contains(ids, strictID) || !slices.Contains(ids, strict2ID) || headers.Get("X-Total-Running") != "2" {
		t.Fatalf("foreign-profile rows broke the strict inventory: %v %v", ids, headers)
	}
	if got := request(t, s, http.MethodGet, "/sandboxes/"+first.ID, nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("e2b row served under a strict template: %d", got.Code)
	}
	// The reverse keeps the strict completeness rule: a strict row whose
	// template turned e2b makes the inventory a 503, as an unservable strict
	// row always has.
	reopen(map[string]Template{"sandboxd-base": e2bBase["sandboxd-base"], "review-v2": {Image: "linux-arm64-v2", Profile: ProfileE2B, EnvdVersion: "0.2.4"}})
	if got := request(t, s, http.MethodGet, "/v2/sandboxes", nil); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("strict inventory hid an unservable strict row: %d %s", got.Code, got.Body.String())
	}
	// Dropping every further template: the worker no longer serves them, so
	// reconciliation reaps their VMs, and the strict view is today's bytes.
	reopen(nil)
	got := request(t, s, http.MethodGet, "/v2/sandboxes", nil)
	if got.Code != http.StatusOK || got.Header().Get("X-Total-Running") != "1" || got.Body.String() != legacyList(t, s, []string{strictID}) {
		t.Fatalf("strict-only inventory after mixed rows: %d %v %s", got.Code, got.Header(), got.Body.String())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE2BRowsWithoutOwnerMetadataAreUnfenced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	ledger, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, id := range []string{"sandboxd-" + strings.Repeat("a", 32), "sandboxd-" + strings.Repeat("b", 32)} {
		row := store.Row{ID: id, TokenHash: make([]byte, 32), Metadata: "{}", TemplateID: "sandboxd-base", Image: "img",
			WorkerID: "w", Profile: string(ProfileE2B), Started: now, Ends: now.Add(time.Hour)}
		if _, err := ledger.Reserve(context.Background(), row, 2, []string{"slot-1", "slot-2"}); err != nil {
			t.Fatalf("row %d: two unfenced rows must not supersede each other: %v", i, err)
		}
		if current, err := ledger.Current(context.Background(), row); err != nil || !current {
			t.Fatalf("unfenced row not current: %v %v", current, err)
		}
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestE2BSandboxesRunOnEnrolledWorkers: e2b templates are scheduled like
// strict ones, onto the enrolled worker that declares them under its lease,
// and connect and set_timeout reach that worker.
func TestE2BSandboxesRunOnEnrolledWorkers(t *testing.T) {
	arm := newFakeWorker(t, "arm-1", "arm64", map[string]string{"review-arm64": "linux-arm64", "sandboxd-base": "linux-arm64-envd"}, 2)
	amd := newFakeWorker(t, "amd-1", "amd64", amd64Templates, 2)
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), nil, Config{APIKey: "control-secret", Domain: "sandbox.example",
		MaxTTL: time.Hour, TokenSecret: []byte(testSecret), Workers: []Remote{{ID: arm.id, Member: arm.client}, {ID: amd.id, Member: amd.client}},
		Templates: map[string]Template{
			"review-arm64":  {Arch: "arm64"},
			"review-amd64":  {Arch: "amd64"},
			"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4"},
			"e2b-amd64":     {Arch: "amd64", Profile: ProfileE2B, EnvdVersion: "0.2.4"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	sdk := createE2B(t, s, map[string]any{"templateID": "base", "timeout": 60})
	row, err := s.ledger.Get(context.Background(), sdk.ID)
	if err != nil || row.WorkerID != "arm-1" || row.Image != "linux-arm64-envd" || row.Lease == 0 || row.Profile != string(ProfileE2B) {
		t.Fatalf("e2b row not scheduled onto the declaring worker under its lease: %+v %v", row, err)
	}
	if !s.Authorize(sdk.ID, sdk.Token) {
		t.Fatal("e2b token not authorized on its worker")
	}
	strict := request(t, s, http.MethodPost, "/sandboxes", createFor("review-amd64", "job-A", 1))
	if strict.Code != http.StatusCreated {
		t.Fatalf("strict create: %d %s", strict.Code, strict.Body.String())
	}
	// No enrolled worker declares e2b-amd64: a refusal, in E2B's error shape.
	if got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "e2b-amd64"}); got.Code < 400 || decodeBody[e2bError](t, got.Body).Code != got.Code {
		t.Fatalf("undeclared e2b template: %d %s", got.Code, got.Body.String())
	}
	before := decodeBody[listed](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID, nil).Body)
	if got := request(t, s, http.MethodPost, "/v2/sandboxes/"+sdk.ID+"/connect", map[string]any{"timeout": 600}); got.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", got.Code, got.Body.String())
	}
	after := decodeBody[listed](t, request(t, s, http.MethodGet, "/sandboxes/"+sdk.ID, nil).Body)
	if !after.EndAt.After(before.EndAt) || after.ClientID != "sandboxd" || after.EnvdVersion != "0.2.4" {
		t.Fatalf("connect through the worker: %+v -> %+v", before, after)
	}
	if ids, _ := listIDs(t, s, ""); len(ids) != 2 {
		t.Fatalf("mixed multi-worker inventory: %v", ids)
	}
	// A partitioned worker's sandboxes stay listed, unconfirmed.
	arm.down.Store(true)
	if ids, headers := listIDs(t, s, "?template=base"); !slices.Equal(ids, []string{sdk.ID}) || headers.Get("X-Sandboxd-Offline-Workers") != "arm-1" {
		t.Fatalf("offline worker's e2b sandbox: %v %v", ids, headers)
	}
	arm.down.Store(false)
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+sdk.ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("kill: %d %s", got.Code, got.Body.String())
	}
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+sdk.ID, nil); got.Code != http.StatusNotFound {
		t.Fatalf("second kill: %d", got.Code)
	}
}

// TestConnectNeverShortensUnderConcurrentExtends: overlapping extensions, in
// either order, leave the latest end time in the ledger; set_timeout still
// sets the end time as asked.
func TestConnectNeverShortensUnderConcurrentExtends(t *testing.T) {
	driver := &meteredDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 1))
	sdk := createE2B(t, s, map[string]any{"templateID": "base", "timeout": 60})
	ends := func() time.Time {
		t.Helper()
		row, err := s.ledger.Get(context.Background(), sdk.ID)
		if err != nil {
			t.Fatal(err)
		}
		return row.Ends
	}
	_, m, err := s.live(context.Background(), sdk.ID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	later, earlier := base.Add(50*time.Minute), base.Add(20*time.Minute)
	// Both callers read the row before either extended it, as two connects
	// racing between their guard and their update would.
	if err := s.extend(context.Background(), sdk.ID, m, later, true); err != nil {
		t.Fatal(err)
	}
	if err := s.extend(context.Background(), sdk.ID, m, earlier, true); err != nil {
		t.Fatal(err)
	}
	if got := ends(); !got.Equal(later) {
		t.Fatalf("a later extension was undone: ends %v, want %v", got, later)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.extend(context.Background(), sdk.ID, m, base.Add(time.Duration(30+i)*time.Minute), true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := ends(); !got.Equal(later) {
		t.Fatalf("concurrent shorter extensions moved the end: %v, want %v", got, later)
	}
	newest := base.Add(55 * time.Minute)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			end := base.Add(time.Duration(51+i%4) * time.Minute)
			if i == 7 {
				end = newest
			}
			if err := s.extend(context.Background(), sdk.ID, m, end, true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := ends(); !got.Equal(newest) {
		t.Fatalf("overlapping extensions: ends %v, want the latest %v", got, newest)
	}
	// set_timeout (E2B semantics) may shorten.
	if got := request(t, s, http.MethodPost, "/sandboxes/"+sdk.ID+"/timeout", map[string]any{"timeout": 30}); got.Code != http.StatusNoContent {
		t.Fatalf("set_timeout: %d %s", got.Code, got.Body.String())
	}
	if got := ends(); !got.Before(base.Add(time.Minute)) {
		t.Fatalf("set_timeout did not shorten: %v", got)
	}
}
