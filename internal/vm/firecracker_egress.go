//go:build linux

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fcEgressMarker is the comment on an egress policy table's last guest rule:
// a digest of the policy, so a readback proves the namespace holds this
// policy's table and not an earlier one, whatever nft makes of the sets.
func fcEgressMarker(policy EgressPolicy) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "internet=%t allow=%s deny=%s",
		policy.AllowInternet, strings.Join(prefixStrings(policy.Allow), ","), strings.Join(prefixStrings(policy.Deny), ",")))
	return "sandboxd egress " + hex.EncodeToString(sum[:8])
}

// fcNetnsSet is a named interval set of IPv4 prefixes; nft refuses an empty
// elements list, so an empty set has none.
func fcNetnsSet(name string, elements []string) string {
	set := "\tset " + name + " {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n"
	if len(elements) != 0 {
		set += "\t\telements = { " + strings.Join(elements, ", ") + " }\n"
	}
	return set + "\t}\n"
}

// fcNetnsPolicyRuleset is fcNetnsRuleset for a VM with an egress policy.
// Every packet the guest sends is judged by the policy, before any
// conntrack accept, so tightening a policy also cuts established flows;
// only what reaches the guest is admitted by conntrack. In order: the host
// port exception, the always-denied set (which no policy reopens), the
// policy's Allow, then without internet nothing else, with it everything but
// the policy's Deny; anything not IPv4 is refused. The last guest rule
// carries fcEgressMarker.
func fcNetnsPolicyRuleset(deny4 []string, hostPort int, policy EgressPolicy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", fcNetnsTable)
	b.WriteString(fcNetnsSet("deny4", deny4))
	b.WriteString(fcNetnsSet("allow4", prefixStrings(policy.Allow)))
	b.WriteString(fcNetnsSet("udeny4", prefixStrings(policy.Deny)))
	fmt.Fprintf(&b, `	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname %q reject with icmpx type admin-prohibited
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
`, fcGuestTap)
	if hostPort != 0 {
		b.WriteString("\t\t" + fcNetnsHostPortRule(hostPort) + "\n")
	}
	guest := fmt.Sprintf("\t\tiifname %q ", fcGuestTap)
	toNAT := fmt.Sprintf("%soifname %q ", guest, fcSlirpTap)
	b.WriteString(guest + "ip daddr @deny4 reject with icmpx type admin-prohibited\n")
	b.WriteString(toNAT + "ip daddr @allow4 accept\n")
	if policy.AllowInternet {
		b.WriteString(guest + "ip daddr @udeny4 reject with icmpx type admin-prohibited\n")
		b.WriteString(toNAT + "meta nfproto ipv4 accept\n")
	}
	fmt.Fprintf(&b, "%sreject with icmpx type admin-prohibited comment %q\n", guest, fcEgressMarker(policy))
	fmt.Fprintf(&b, `		ct state established,related accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %q masquerade
	}
}
`, fcSlirpTap)
	return b.String()
}

// fcCheckNetnsState checks a namespace table's readback: the host port
// exception as fcCheckNetnsHostPortState, and a nonempty marker (an egress
// policy table's) on exactly one rule.
func fcCheckNetnsState(state string, hostPort int, marker string) error {
	if err := fcCheckNetnsHostPortState(state, hostPort); err != nil {
		return err
	}
	if marker != "" && strings.Count(state, fmt.Sprintf(" comment %q\n", marker)) != 1 {
		return fmt.Errorf("namespace firewall table does not read back egress policy %q", marker)
	}
	return nil
}

// netnsRuleset is the namespace table for a VM's recorded policy (nil: one
// created without, whose table is unchanged) and the marker its readback
// must show.
func (d *FirecrackerDriver) netnsRuleset(policy *EgressPolicy) (string, string) {
	if policy == nil {
		return fcNetnsRuleset(d.deny4, d.cfg.HostPort), ""
	}
	return fcNetnsPolicyRuleset(d.deny4, d.cfg.HostPort, *policy), fcEgressMarker(*policy)
}

// checkEgressSpec returns the canonical form of spec's policy, or refuses
// one this driver cannot enforce.
func (d *FirecrackerDriver) checkEgressSpec(spec Spec) (*EgressPolicy, error) {
	if spec.Egress == nil {
		return nil, nil
	}
	if !spec.Envd {
		return nil, errors.New("only e2b guests take an egress policy")
	}
	policy := EgressPolicy{AllowInternet: spec.Egress.AllowInternet}.Apply(EgressUpdate{Allow: &spec.Egress.Allow, Deny: &spec.Egress.Deny})
	if err := validEgress(policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// Egress returns the policy recorded for VM id.
func (d *FirecrackerDriver) Egress(ctx context.Context, id string) (EgressPolicy, error) {
	if err := validAppleID(id); err != nil {
		return EgressPolicy{}, err
	}
	if err := ctx.Err(); err != nil {
		return EgressPolicy{}, err
	}
	meta, err := d.readMeta(id)
	if errors.Is(err, fs.ErrNotExist) {
		return EgressPolicy{}, fmt.Errorf("Firecracker VM %q: %w", id, ErrNoVM)
	}
	if err != nil {
		return EgressPolicy{}, err
	}
	if meta == nil {
		return EgressPolicy{}, fmt.Errorf("Firecracker VM %q has no valid ownership record", id)
	}
	if meta.Egress == nil {
		return DefaultEgress(), nil
	}
	return *meta.Egress, nil
}

// UpdateEgress merges u into a running VM's policy, records it, then
// replaces the VM's namespace table with the merged policy's. The record is
// written first so that a crash in between leaves the record ahead of the
// kernel, never behind: ReapplyEgress at the next start installs it, so the
// table ends at the newest requested policy and a crash in a tightening
// update can never leave the looser one in force. If the table cannot be
// confirmed, record and table are put back (best effort).
func (d *FirecrackerDriver) UpdateEgress(ctx context.Context, id string, u EgressUpdate) (EgressPolicy, error) {
	if err := validAppleID(id); err != nil {
		return EgressPolicy{}, err
	}
	d.egressMu.Lock()
	defer d.egressMu.Unlock()
	vm, found, err := d.lookup(id)
	if err != nil {
		return EgressPolicy{}, err
	}
	if !found || vm.meta == nil {
		return EgressPolicy{}, fmt.Errorf("Firecracker VM %q: %w", id, ErrNoVM)
	}
	if !vm.running() {
		return EgressPolicy{}, fmt.Errorf("Firecracker VM %q is not running", id)
	}
	if !vm.meta.Envd {
		return EgressPolicy{}, errors.New("only e2b guests take an egress policy")
	}
	current := DefaultEgress()
	if vm.meta.Egress != nil {
		current = *vm.meta.Egress
	}
	merged := current.Apply(u)
	if err := validEgress(merged); err != nil {
		return EgressPolicy{}, err
	}
	meta := *vm.meta
	meta.Egress = &merged
	if err := d.rewriteRecord(meta); err != nil {
		return EgressPolicy{}, fmt.Errorf("record egress policy of %q: %w", id, err)
	}
	if err := d.enforceEgress(ctx, id, &merged); err != nil {
		// The caller's context may be what failed; the restore gets its own.
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if restoreErr := d.rewriteRecord(*vm.meta); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous egress record of %q: %w", id, restoreErr))
		}
		if restoreErr := d.enforceEgress(restoreCtx, id, vm.meta.Egress); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous egress policy of %q: %w", id, restoreErr))
		}
		return EgressPolicy{}, err
	}
	return merged, nil
}

// ReapplyEgress installs every running e2b VM's recorded policy again. Run it
// once at start, after Arm and before serving: it snapshots the inventory
// first, so run while UpdateEgress can be live it could install an older
// policy over a newer one. A daemon killed during UpdateEgress can leave the
// record ahead of the kernel table, and this brings the table up to it. A VM
// whose policy cannot be installed is destroyed, since what its table
// enforces is unknown; its volume is flushed first (over vsock, not the
// network, and only while the host firewall is confirmed). A VM with no
// recorded policy is left alone: its table was never replaced. UpdateEgress
// always records the merged policy, even one equal to the default, so every
// replaced table is covered here.
func (d *FirecrackerDriver) ReapplyEgress(ctx context.Context) error {
	vms, err := d.inventory()
	if err != nil {
		return err
	}
	var errs []error
	for _, vm := range vms {
		if !vm.running() || vm.meta.Egress == nil {
			continue
		}
		d.egressMu.Lock()
		err := d.enforceEgress(ctx, vm.id, vm.meta.Egress)
		d.egressMu.Unlock()
		if err == nil {
			continue
		}
		log.Printf("firecracker: destroying %s: its recorded egress policy could not be installed: %v", vm.id, err)
		if err := d.destroy(ctx, vm.id, true); err != nil {
			errs = append(errs, fmt.Errorf("destroy %q after failing to reapply its egress policy: %w", vm.id, err))
		}
	}
	return errors.Join(errs...)
}

// enforceEgress atomically replaces VM id's namespace table with the one
// for policy and confirms its readback.
func (d *FirecrackerDriver) enforceEgress(ctx context.Context, id string, policy *EgressPolicy) error {
	ruleset, marker := d.netnsRuleset(policy)
	state, err := d.host.ReplaceNetnsFirewall(ctx, d.names.netnsPrefix+id, ruleset)
	if err != nil {
		return err
	}
	return fcCheckNetnsState(state, d.cfg.HostPort, marker)
}

// rewriteRecord atomically replaces an existing VM record: a synced
// temporary file outside the record directory (whose every entry inventory
// reads as a record), renamed over it, then the directory synced.
func (d *FirecrackerDriver) rewriteRecord(meta fcMeta) error {
	record, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	staging := filepath.Join(d.cfg.Root, "run.tmp")
	if err := os.Mkdir(staging, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	tmp := filepath.Join(staging, meta.ID+".json")
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(record)
	if err = errors.Join(err, file.Chmod(0o600), file.Sync(), file.Close()); err == nil {
		err = os.Rename(tmp, d.metaPath(meta.ID))
	}
	if err != nil {
		return errors.Join(err, fcRemoveMissing(tmp))
	}
	return fcSyncPath(d.runDir())
}
