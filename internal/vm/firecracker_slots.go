package vm

import (
	"fmt"
	"regexp"
	"strconv"
)

// The default (unnamed) instance's Root and UIDBase. A named instance
// refuses to overlap them unless the default instance's claim says it uses
// something else: a default daemon built before claims writes none.
const (
	FirecrackerDefaultRoot    = "/var/lib/sandboxd-fc"
	FirecrackerDefaultUIDBase = 2900000
)

var fcInstanceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)

// ValidateFirecrackerInstance checks FirecrackerConfig.Instance: empty (the
// default instance) or a short lowercase name. "default" is the default
// instance's claim name, so no named instance may take it. It builds on
// every platform so flag validation does.
func ValidateFirecrackerInstance(name string) error {
	if name != "" && (!fcInstanceName.MatchString(name) || name == "default") {
		return fmt.Errorf("Firecracker instance name %q must match %s and not be \"default\"", name, fcInstanceName)
	}
	return nil
}

// FirecrackerSlotNames returns the slot network names of a Firecracker worker
// with n VM slots. Each slot owns one UID pair; the ledger assigns slots
// exclusively. It builds on every platform so flag validation does.
func FirecrackerSlotNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "sbx" + strconv.Itoa(i)
	}
	return names
}
