package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// Per-sandbox egress policies (E2B's allow_internet_access and network
// allowOut/denyOut), served only with Config.Egress. Every field name below
// is matched exactly, never case-folded: an option sandboxd does not know is
// refused, never silently ignored.

// egressObject decodes a JSON object into its fields, keeping each value raw
// so that presence, null and type are judged per field.
func egressObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// egressTargets parses an allowOut/denyOut list into the vm package's
// canonical prefixes; field names it in the client message.
func egressTargets(field string, raw json.RawMessage) ([]netip.Prefix, error) {
	var entries []string
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s must be a list of IPv4 addresses or CIDRs", field)
	}
	prefixes, err := vm.ParseEgressTargets(entries)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return prefixes, nil
}

func egressBool(field string, raw json.RawMessage) (*bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("%s must be a boolean", field)
	}
	return &value, nil
}

// publicTraffic reports whether a create's network asks for public guest
// ports, which sandboxd never serves (refused as unsupported). A malformed
// network is left to createEgress.
func publicTraffic(network json.RawMessage) bool {
	fields, ok := egressObject(network)
	if !ok {
		return false
	}
	public, err := egressBool("network.allowPublicTraffic", fields["allowPublicTraffic"])
	return err == nil && *public
}

// createEgress returns the egress policy a v2 create asks for, applied to
// the default, or nil when it names none: such a sandbox keeps the driver's
// default egress exactly as before policies existed. Null is absent here, as
// in E2B's create. publicTraffic already refused allowPublicTraffic=true.
func createEgress(allowInternet, network json.RawMessage) (*vm.EgressPolicy, error) {
	var update vm.EgressUpdate
	named := false
	if !absent(allowInternet) {
		value, err := egressBool("allow_internet_access", allowInternet)
		if err != nil {
			return nil, err
		}
		update.AllowInternet, named = value, true
	}
	if !absent(network) {
		fields, ok := egressObject(network)
		if !ok {
			return nil, errors.New("network must be an object")
		}
		// Sorted, so the field a refusal names does not depend on map order.
		for _, field := range slices.Sorted(maps.Keys(fields)) {
			raw := fields[field]
			if absent(raw) {
				continue
			}
			switch field {
			case "allowPublicTraffic":
				if _, err := egressBool("network.allowPublicTraffic", raw); err != nil {
					return nil, err
				}
			case "allowOut", "denyOut":
				prefixes, err := egressTargets("network."+field, raw)
				if err != nil {
					return nil, err
				}
				if field == "allowOut" {
					update.Allow = &prefixes
				} else {
					update.Deny = &prefixes
				}
				named = true
			default:
				return nil, fmt.Errorf("network.%s is not supported (only allowOut, denyOut and allowPublicTraffic=false are)", field)
			}
		}
	}
	policy := vm.DefaultEgress().Apply(update)
	// A policy equal to the default (allow_internet_access:true, empty
	// lists) changes nothing, so it must not pin the sandbox to the local
	// worker either.
	if !named || policy.Equal(vm.DefaultEgress()) {
		return nil, nil
	}
	return &policy, nil
}

// networkUpdate parses E2B's SandboxNetworkUpdateConfig. Only present fields
// change: sandboxd deliberately differs from E2B, whose update clears omitted
// ones, so an update can never silently reopen the internet. An explicit
// null is refused rather than read as either "keep" or "clear".
func networkUpdate(fields map[string]json.RawMessage) (vm.EgressUpdate, error) {
	var update vm.EgressUpdate
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		raw := fields[field]
		switch field {
		case "allowOut", "denyOut", "allow_internet_access":
		case "rules", "egressProxy":
			return vm.EgressUpdate{}, fmt.Errorf("%s is not supported (only allowOut, denyOut and allow_internet_access are)", field)
		default:
			return vm.EgressUpdate{}, fmt.Errorf("unknown network update field %q", field)
		}
		if string(raw) == "null" {
			return vm.EgressUpdate{}, fmt.Errorf("%s must not be null: omit it to keep the current value", field)
		}
		switch field {
		case "allow_internet_access":
			value, err := egressBool(field, raw)
			if err != nil {
				return vm.EgressUpdate{}, err
			}
			update.AllowInternet = value
		case "allowOut":
			prefixes, err := egressTargets(field, raw)
			if err != nil {
				return vm.EgressUpdate{}, err
			}
			update.Allow = &prefixes
		case "denyOut":
			prefixes, err := egressTargets(field, raw)
			if err != nil {
				return vm.EgressUpdate{}, err
			}
			update.Deny = &prefixes
		}
	}
	return update, nil
}

// updateNetwork serves PUT /sandboxes/{id}/network for a running e2b sandbox
// on the local worker, the only one whose driver enforces egress policies.
func (s *Service) updateNetwork(w http.ResponseWriter, r *http.Request, id string) {
	// An unknown sandbox is not found whatever the body says.
	if !validID(id) {
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
		return
	}
	if _, _, err := s.live(r.Context(), id); err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return
	}
	var fields map[string]json.RawMessage
	if err := decode(w, r, &fields); !errors.Is(err, io.EOF) || fields == nil {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid network update body")
		return
	}
	update, err := networkUpdate(fields)
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusBadRequest, err.Error())
		return
	}
	row, m, err := s.live(r.Context(), id)
	if err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return
	}
	if profile := rowProfile(row.Profile); profile != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q uses the %s profile, which has no network update", id, profile))
		return
	}
	if m != s.localMember {
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q runs on an enrolled worker, which does not enforce egress policies", id))
		return
	}
	// The busy mark keeps a delete or reconciliation from judging the row
	// while the policy changes; a delete waits for the update to settle.
	s.mu.Lock()
	current, err := s.ledger.Get(r.Context(), id)
	if err != nil || current.State != "running" || current.WorkerID != row.WorkerID || current.Lease != row.Lease || s.busy[id] != nil {
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is changing state; retry", id))
		return
	}
	s.markBusy(id)
	s.mu.Unlock()
	callCtx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	_, err = s.egress.UpdateEgress(callCtx, id, update)
	cancel()
	s.mu.Lock()
	s.clearBusy(id)
	s.mu.Unlock()
	switch {
	case errors.Is(err, vm.ErrNoVM):
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
	case err != nil:
		log.Printf("sandbox %s: egress update failed: %v", id, err)
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox network update unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// egressNetworkInfo is the detail's network: the policy's public lists.
type egressNetworkInfo struct {
	AllowOut []string `json:"allowOut,omitempty"`
	DenyOut  []string `json:"denyOut,omitempty"`
}

// describeEgress adds an e2b sandbox's egress policy to its detail when the
// local driver enforces it; other sandboxes keep their detail unchanged. The
// detail is the SDKs' get_info, so an unreadable policy never fails it: the
// fields stay unset (unknown), never the default. live already proved the
// sandbox running, so a driver's ErrNoVM here is a race that the next
// request's reconciliation judges, not a not-found.
func (s *Service) describeEgress(ctx context.Context, row store.Row, m *member, described *sandbox) {
	if s.egress == nil || m != s.localMember || rowProfile(row.Profile) != ProfileE2B {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, workerTimeout)
	policy, err := s.egress.Egress(callCtx, row.ID)
	cancel()
	if err != nil {
		log.Printf("sandbox %s: egress policy unreadable, omitted from detail: %v", row.ID, err)
		return
	}
	described.AllowInternetAccess = &policy.AllowInternet
	if len(policy.Allow) > 0 || len(policy.Deny) > 0 {
		described.Network = &egressNetworkInfo{AllowOut: prefixStrings(policy.Allow), DenyOut: prefixStrings(policy.Deny)}
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.String()
	}
	return out
}
