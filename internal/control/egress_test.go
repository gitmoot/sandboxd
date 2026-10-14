package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// fakeEgress is a driver's per-sandbox egress store; it records every update.
type fakeEgress struct {
	mu       sync.Mutex
	policies map[string]vm.EgressPolicy
	updates  []vm.EgressUpdate
	gone     map[string]bool
	err      error // UpdateEgress failure
	readErr  error // Egress failure
}

func (e *fakeEgress) Egress(_ context.Context, id string) (vm.EgressPolicy, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gone[id] {
		return vm.EgressPolicy{}, fmt.Errorf("egress %s: %w", id, vm.ErrNoVM)
	}
	if e.readErr != nil {
		return vm.EgressPolicy{}, e.readErr
	}
	if policy, ok := e.policies[id]; ok {
		return policy, nil
	}
	return vm.DefaultEgress(), nil
}

func (e *fakeEgress) UpdateEgress(ctx context.Context, id string, u vm.EgressUpdate) (vm.EgressPolicy, error) {
	current, err := e.Egress(ctx, id)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updates = append(e.updates, u)
	if err != nil {
		return vm.EgressPolicy{}, err
	}
	if e.err != nil {
		return vm.EgressPolicy{}, e.err
	}
	next := current.Apply(u)
	e.policies[id] = next
	return next, nil
}

func (e *fakeEgress) recorded() []vm.EgressUpdate {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]vm.EgressUpdate(nil), e.updates...)
}

func openEgress(t *testing.T, slots int) (*Service, *specDriver, *fakeEgress) {
	t.Helper()
	driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
	egress := &fakeEgress{policies: map[string]vm.EgressPolicy{}, gone: map[string]bool{}}
	cfg := mixedConfig(e2bBase, slots)
	cfg.Egress = egress
	return openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg), driver, egress
}

func prefixes(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(entries))
	for i, entry := range entries {
		out[i] = netip.MustParsePrefix(entry)
	}
	return out
}

func samePolicy(a, b vm.EgressPolicy) bool {
	return a.AllowInternet == b.AllowInternet && fmt.Sprint(a.Allow) == fmt.Sprint(b.Allow) && fmt.Sprint(a.Deny) == fmt.Sprint(b.Deny)
}

// Without Config.Egress every egress option keeps today's 501, byte for byte.
func TestEgressOffStaysRefused(t *testing.T) {
	driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 2))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	createRefusal := `{"code":501,"message":"network and internet access options are not supported (guest ports are never public: only network.allowPublicTraffic=false is accepted); ` + notSupportedDoc + `"}` + "\n"
	networkRefusal := `{"code":501,"message":"` + refuseNetwork + "; " + notSupportedDoc + `"}` + "\n"
	for _, c := range []struct {
		method, path string
		body         string
		want         string
	}{
		{http.MethodPost, "/v2/sandboxes", `{"templateID":"base","allow_internet_access":false}`, createRefusal},
		{http.MethodPost, "/v2/sandboxes", `{"templateID":"base","allow_internet_access":true}`, createRefusal},
		{http.MethodPost, "/v2/sandboxes", `{"templateID":"base","network":{"allowOut":["1.1.1.1"]}}`, createRefusal},
		{http.MethodPost, "/v2/sandboxes", `{"templateID":"base","network":{"denyOut":["0.0.0.0/0"],"allowPublicTraffic":false}}`, createRefusal},
		{http.MethodPost, "/v2/sandboxes", `{"templateID":"base","network":{"allowPublicTraffic":true}}`, createRefusal},
		{http.MethodPut, "/sandboxes/" + id + "/network", `{"allowOut":["1.1.1.1"]}`, networkRefusal},
		{http.MethodPut, "/sandboxes/" + id + "/network", `{}`, networkRefusal},
	} {
		got := request(t, s, c.method, c.path, json.RawMessage(c.body))
		if got.Code != http.StatusNotImplemented || got.Body.String() != c.want {
			t.Errorf("%s %s %s: %d %q, want 501 %q", c.method, c.path, c.body, got.Code, got.Body.String(), c.want)
		}
	}
	if specs := driver.recorded(); len(specs) != 1 || specs[0].Egress != nil {
		t.Fatalf("specs: %+v", specs)
	}
	// allowPublicTraffic=false alone is still accepted, without a policy.
	createE2B(t, s, map[string]any{"templateID": "base", "network": map[string]any{"allowPublicTraffic": false}})
	if specs := driver.recorded(); len(specs) != 2 || specs[1].Egress != nil {
		t.Fatalf("specs: %+v", specs)
	}
	// The detail carries no egress fields.
	if got := request(t, s, http.MethodGet, "/sandboxes/"+id, nil); got.Code != http.StatusOK || json.Valid(got.Body.Bytes()) && containsKey(t, got.Body.Bytes(), "allowInternetAccess") {
		t.Fatalf("detail: %d %s", got.Code, got.Body.String())
	}
}

func containsKey(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	_, ok := fields[key]
	return ok
}

func TestCreateEgressPolicy(t *testing.T) {
	for _, c := range []struct {
		name string
		body map[string]any
		want *vm.EgressPolicy
	}{
		{"none", map[string]any{"templateID": "base"}, nil},
		{"private traffic only", map[string]any{"templateID": "base", "network": map[string]any{"allowPublicTraffic": false}}, nil},
		{"null fields", map[string]any{"templateID": "base", "allow_internet_access": nil, "network": map[string]any{"allowOut": nil}}, nil},
		{"no internet", map[string]any{"templateID": "base", "allow_internet_access": false}, &vm.EgressPolicy{AllowInternet: false}},
		{"internet", map[string]any{"templateID": "base", "allow_internet_access": true}, &vm.EgressPolicy{AllowInternet: true}},
		{"lists", map[string]any{"templateID": "base", "allow_internet_access": false,
			"network": map[string]any{"allowOut": []string{"8.8.8.8", "1.1.1.0/24", "1.1.1.7/24"}, "denyOut": []string{"203.0.113.0/24"}, "allowPublicTraffic": false}},
			&vm.EgressPolicy{AllowInternet: false, Allow: prefixes(t, "1.1.1.0/24", "8.8.8.8/32"), Deny: prefixes(t, "203.0.113.0/24")}},
		{"deny only", map[string]any{"templateID": "base", "network": map[string]any{"denyOut": []string{"0.0.0.0/0"}}},
			&vm.EgressPolicy{AllowInternet: true, Deny: prefixes(t, "0.0.0.0/0")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, driver, _ := openEgress(t, 1)
			createE2B(t, s, c.body)
			specs := driver.recorded()
			if len(specs) != 1 {
				t.Fatalf("specs: %+v", specs)
			}
			got := specs[0].Egress
			if (got == nil) != (c.want == nil) || got != nil && !samePolicy(*got, *c.want) {
				t.Fatalf("spec egress %+v, want %+v", got, c.want)
			}
		})
	}
}

// A refused egress option reserves no slot and never reaches the driver.
func TestCreateEgressRefusals(t *testing.T) {
	s, driver, _ := openEgress(t, 2)
	for _, c := range []struct {
		body    string
		status  int
		message string
	}{
		{`{"templateID":"base","network":{"allowOut":["example.com"]}}`, http.StatusBadRequest, "network.allowOut: entry \"example.com\": only IPv4 addresses and CIDRs are supported (hostnames are not)"},
		{`{"templateID":"base","network":{"denyOut":["2001:db8::/32"]}}`, http.StatusBadRequest, "network.denyOut: entry \"2001:db8::/32\": IPv6"},
		{`{"templateID":"base","network":{"allowOut":"1.1.1.1"}}`, http.StatusBadRequest, "network.allowOut must be a list"},
		{`{"templateID":"base","network":{"egressProxy":{"address":"p:1"}}}`, http.StatusBadRequest, "network.egressProxy is not supported"},
		{`{"templateID":"base","network":{"rules":{"x.com":[]}}}`, http.StatusBadRequest, "network.rules is not supported"},
		{`{"templateID":"base","network":{"maskRequestHost":"h"}}`, http.StatusBadRequest, "network.maskRequestHost is not supported"},
		{`{"templateID":"base","network":{"httpsPorts":[443]}}`, http.StatusBadRequest, "network.httpsPorts is not supported"},
		{`{"templateID":"base","network":{"AllowOut":["1.1.1.1"]}}`, http.StatusBadRequest, "network.AllowOut is not supported"},
		{`{"templateID":"base","network":[]}`, http.StatusBadRequest, "network must be an object"},
		{`{"templateID":"base","allow_internet_access":"no"}`, http.StatusBadRequest, "allow_internet_access must be a boolean"},
		{`{"templateID":"base","network":{"allowPublicTraffic":true,"allowOut":["1.1.1.1"]}}`, http.StatusNotImplemented, "public traffic is not supported"},
	} {
		got := request(t, s, http.MethodPost, "/v2/sandboxes", json.RawMessage(c.body))
		wantFailure(t, c.body, got, c.status, c.message)
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.0.2.%d", i)
	}
	got := request(t, s, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base", "network": map[string]any{"allowOut": tooMany}})
	wantFailure(t, "65 entries", got, http.StatusBadRequest, "at most 64 entries")
	if rows, err := s.ledger.Active(context.Background()); err != nil || len(rows) != 0 {
		t.Fatalf("refusals reserved slots: %+v %v", rows, err)
	}
	if specs := driver.recorded(); len(specs) != 0 {
		t.Fatalf("refusals reached the driver: %+v", specs)
	}
}

// A policy sandbox runs on the gateway's local worker or nowhere, however
// much room an enrolled worker has; without a policy it may run remotely.
func TestEgressSandboxNeverPlacedOnRemoteWorker(t *testing.T) {
	remote := newFakeWorker(t, "arm-1", "arm64", map[string]string{"sandboxd-base": "linux-arm64-envd"}, 4)
	newGateway := func(local map[string]Template) (*Service, *specDriver) {
		driver := &specDriver{fakeDriver: &fakeDriver{instances: map[string]vm.Instance{}}}
		cfg := mixedConfig(local, 1)
		cfg.Arch = "arm64"
		cfg.Egress = &fakeEgress{policies: map[string]vm.EgressPolicy{}, gone: map[string]bool{}}
		cfg.Workers = []Remote{{ID: remote.id, Member: remote.client}}
		return openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg), driver
	}
	policy := map[string]any{"templateID": "base", "allow_internet_access": false}

	s, driver := newGateway(e2bBase)
	sandbox := createE2B(t, s, policy)
	if row, err := s.ledger.Get(context.Background(), sandbox.ID); err != nil || row.WorkerID != "mac-local" || len(driver.recorded()) != 1 {
		t.Fatalf("policy sandbox placed on %q (%v)", row.WorkerID, err)
	}
	got := request(t, s, http.MethodPost, "/v2/sandboxes", policy)
	wantFailure(t, "local full", got, http.StatusConflict, "capacity exhausted")
	if n := remote.driver.count(); n != 0 {
		t.Fatalf("remote worker ran %d VMs", n)
	}

	remoteOnly := map[string]Template{"sandboxd-base": {Arch: "arm64", Profile: ProfileE2B, Aliases: []string{"base"}, EnvdVersion: "0.2.4"}}
	s, driver = newGateway(remoteOnly)
	got = request(t, s, http.MethodPost, "/v2/sandboxes", policy)
	wantFailure(t, "remote only", got, http.StatusConflict, "a sandbox with an egress policy runs only on the gateway's local worker, which does not serve template sandboxd-base")
	if n := remote.driver.count(); n != 0 || len(driver.recorded()) != 0 {
		t.Fatalf("policy sandbox ran: remote %d local %d", n, len(driver.recorded()))
	}
	plain := createE2B(t, s, map[string]any{"templateID": "base"})
	if row, err := s.ledger.Get(context.Background(), plain.ID); err != nil || row.WorkerID != remote.id {
		t.Fatalf("plain sandbox placed on %q (%v)", row.WorkerID, err)
	}
	// Its network cannot be updated: the remote worker enforces no policy.
	got = request(t, s, http.MethodPut, "/sandboxes/"+plain.ID+"/network", map[string]any{"allow_internet_access": false})
	wantFailure(t, "remote update", got, http.StatusConflict, "enrolled worker")
}

// An update changes only the fields it names; GET reports the result.
func TestUpdateNetworkMergesPresentFields(t *testing.T) {
	s, _, egress := openEgress(t, 1)
	id := createE2B(t, s, map[string]any{"templateID": "base", "network": map[string]any{"allowOut": []string{"1.1.1.1"}, "denyOut": []string{"0.0.0.0/0"}}}).ID
	egress.policies[id] = vm.EgressPolicy{AllowInternet: true, Allow: prefixes(t, "1.1.1.1/32"), Deny: prefixes(t, "0.0.0.0/0")}

	got := request(t, s, http.MethodPut, "/sandboxes/"+id+"/network", map[string]any{"allow_internet_access": false})
	if got.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", got.Code, got.Body.String())
	}
	got = request(t, s, http.MethodPut, "/sandboxes/"+id+"/network", map[string]any{"allowOut": []string{"8.8.8.8", "9.9.9.0/24"}})
	if got.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", got.Code, got.Body.String())
	}
	got = request(t, s, http.MethodPut, "/sandboxes/"+id+"/network", map[string]any{"denyOut": []string{}})
	if got.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", got.Code, got.Body.String())
	}
	updates := egress.recorded()
	if len(updates) != 3 {
		t.Fatalf("updates: %+v", updates)
	}
	if u := updates[0]; u.AllowInternet == nil || *u.AllowInternet || u.Allow != nil || u.Deny != nil {
		t.Fatalf("first update %+v: want only AllowInternet=false", u)
	}
	if u := updates[1]; u.AllowInternet != nil || u.Allow == nil || fmt.Sprint(*u.Allow) != "[8.8.8.8/32 9.9.9.0/24]" || u.Deny != nil {
		t.Fatalf("second update %+v: want only Allow", u)
	}
	if u := updates[2]; u.AllowInternet != nil || u.Allow != nil || u.Deny == nil || len(*u.Deny) != 0 {
		t.Fatalf("third update %+v: want only an empty Deny", u)
	}
	want := vm.EgressPolicy{AllowInternet: false, Allow: prefixes(t, "8.8.8.8/32", "9.9.9.0/24")}
	if !samePolicy(egress.policies[id], want) {
		t.Fatalf("policy %+v, want %+v", egress.policies[id], want)
	}

	got = request(t, s, http.MethodGet, "/sandboxes/"+id, nil)
	detail := decodeBody[struct {
		AllowInternetAccess *bool `json:"allowInternetAccess"`
		Network             *struct {
			AllowOut []string `json:"allowOut"`
			DenyOut  []string `json:"denyOut"`
		} `json:"network"`
	}](t, got.Body)
	if got.Code != http.StatusOK || detail.AllowInternetAccess == nil || *detail.AllowInternetAccess || detail.Network == nil ||
		fmt.Sprint(detail.Network.AllowOut) != "[8.8.8.8/32 9.9.9.0/24]" || detail.Network.DenyOut != nil {
		t.Fatalf("detail: %d %+v", got.Code, detail)
	}
}

// The detail is the SDKs' get_info: an unreadable policy leaves its fields
// unset (unknown) and never fails it.
func TestGetDetailSurvivesUnreadableEgress(t *testing.T) {
	s, _, egress := openEgress(t, 1)
	id := createE2B(t, s, map[string]any{"templateID": "base", "allow_internet_access": false}).ID
	egress.policies[id] = vm.EgressPolicy{AllowInternet: false}
	got := request(t, s, http.MethodGet, "/sandboxes/"+id, nil)
	if got.Code != http.StatusOK || !containsKey(t, got.Body.Bytes(), "allowInternetAccess") {
		t.Fatalf("readable detail: %d %s", got.Code, got.Body.String())
	}
	for _, fail := range []func(){
		func() { egress.readErr = errors.New("record unreadable") },
		func() { egress.readErr = nil; egress.gone[id] = true },
	} {
		egress.mu.Lock()
		fail()
		egress.mu.Unlock()
		got := request(t, s, http.MethodGet, "/sandboxes/"+id, nil)
		if got.Code != http.StatusOK || containsKey(t, got.Body.Bytes(), "allowInternetAccess") || containsKey(t, got.Body.Bytes(), "network") {
			t.Fatalf("unreadable detail: %d %s", got.Code, got.Body.String())
		}
		if detail := decodeBody[sandbox](t, got.Body); detail.ID != id || detail.State != "running" {
			t.Fatalf("unreadable detail: %+v", detail)
		}
	}
}

func TestUpdateNetworkRefusals(t *testing.T) {
	s, _, egress := openEgress(t, 3)
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	path := "/sandboxes/" + id + "/network"
	for _, c := range []struct {
		body    string
		message string
	}{
		{`{"rules":{"x.com":[]}}`, "rules is not supported"},
		{`{"egressProxy":{"address":"p:1"}}`, "egressProxy is not supported"},
		{`{"allowOut":["1.1.1.1"],"rules":{}}`, "rules is not supported"},
		{`{"allow_out":["1.1.1.1"]}`, `unknown network update field "allow_out"`},
		{`{"allowInternetAccess":false}`, `unknown network update field "allowInternetAccess"`},
		{`{"allowOut":null}`, "allowOut must not be null"},
		{`{"allow_internet_access":null}`, "allow_internet_access must not be null"},
		{`{"allowOut":["example.com"]}`, `allowOut: entry "example.com": only IPv4`},
		{`{"denyOut":["::/0"]}`, `denyOut: entry "::/0": IPv6`},
		{`{"allow_internet_access":"no"}`, "allow_internet_access must be a boolean"},
		{`[]`, "invalid network update body"},
		{`null`, "invalid network update body"},
	} {
		got := request(t, s, http.MethodPut, path, json.RawMessage(c.body))
		wantFailure(t, c.body, got, http.StatusBadRequest, c.message)
	}
	if updates := egress.recorded(); len(updates) != 0 {
		t.Fatalf("refused updates reached the driver: %+v", updates)
	}
	if got := request(t, s, http.MethodPost, path, map[string]any{}); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST network: %d %s", got.Code, got.Body.String())
	}

	// Unknown and malformed IDs are not found.
	for _, other := range []string{"sandboxd-00000000000000000000000000000000", "bogus"} {
		got := request(t, s, http.MethodPut, "/sandboxes/"+other+"/network", map[string]any{"allow_internet_access": false})
		wantFailure(t, other, got, http.StatusNotFound, "")
	}
	// A strict sandbox has no network update.
	strict := request(t, s, http.MethodPost, "/sandboxes", createBody("job-1", 1))
	if strict.Code != http.StatusCreated {
		t.Fatalf("strict create: %d %s", strict.Code, strict.Body.String())
	}
	strictID := decodeBody[sandbox](t, strict.Body).ID
	got := request(t, s, http.MethodPut, "/sandboxes/"+strictID+"/network", map[string]any{"allow_internet_access": false})
	wantFailure(t, "strict", got, http.StatusConflict, "gitmoot-strict profile")
	// A sandbox that is not running (here: mid-teardown) is refused.
	s.mu.Lock()
	s.markBusy(id)
	s.mu.Unlock()
	got = request(t, s, http.MethodPut, path, map[string]any{"allow_internet_access": false})
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy sandbox: %d %s", got.Code, got.Body.String())
	}
	s.mu.Lock()
	s.clearBusy(id)
	s.mu.Unlock()
	if updates := egress.recorded(); len(updates) != 0 {
		t.Fatalf("refused updates reached the driver: %+v", updates)
	}

	// The driver's not-found is a 404; any other failure a 503.
	egress.mu.Lock()
	egress.gone[id] = true
	egress.mu.Unlock()
	got = request(t, s, http.MethodPut, path, map[string]any{"allow_internet_access": false})
	wantFailure(t, "driver gone", got, http.StatusNotFound, "not found")
	egress.mu.Lock()
	delete(egress.gone, id)
	egress.err = errors.New("nft: boom")
	egress.mu.Unlock()
	got = request(t, s, http.MethodPut, path, map[string]any{"allow_internet_access": false})
	wantFailure(t, "driver error", got, http.StatusServiceUnavailable, "sandbox network update unavailable")

	// A killed sandbox is not found.
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+id, nil); got.Code != http.StatusNoContent {
		t.Fatalf("kill: %d", got.Code)
	}
	got = request(t, s, http.MethodPut, path, map[string]any{"allow_internet_access": false})
	wantFailure(t, "killed", got, http.StatusNotFound, "")
}
