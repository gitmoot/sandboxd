package vm

import "strconv"

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
