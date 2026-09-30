package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"
)

var testSlots = []string{"slot-1"}

func slotRow(id string) Row {
	now := time.Now()
	return Row{ID: id, TokenHash: make([]byte, 32), Metadata: "{}", JobID: "job-" + id, Attempt: 1,
		TemplateID: "review", Image: "linux-arm64", WorkerID: "mac-local", Started: now, Ends: now.Add(time.Hour)}
}

func openLedger(t *testing.T) *Store {
	t.Helper()
	ledger, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func TestConcurrentReservationsGetExclusiveSlots(t *testing.T) {
	ctx := context.Background()
	ledger := openLedger(t)
	slots := []string{"slot-1", "slot-2", "slot-3"}
	type result struct {
		id, slot string
		err      error
	}
	results := make(chan result, 12)
	start := make(chan struct{})
	for i := range cap(results) {
		go func(id string) {
			<-start
			slot, err := ledger.Reserve(ctx, slotRow(id), len(slots), slots)
			results <- result{id, slot, err}
		}("vm-" + strconv.Itoa(i))
	}
	close(start)
	var got []string
	for range cap(results) {
		r := <-results
		switch {
		case r.err == nil:
			row, err := ledger.Get(ctx, r.id)
			if err != nil || row.Slot != r.slot {
				t.Fatalf("slot %q not durably recorded for %s: %+v %v", r.slot, r.id, row, err)
			}
			got = append(got, r.slot)
		case errors.Is(r.err, ErrCapacity):
		default:
			t.Fatalf("reservation error: %v", r.err)
		}
	}
	sort.Strings(got)
	if len(got) != 3 || got[0] != "slot-1" || got[1] != "slot-2" || got[2] != "slot-3" {
		t.Fatalf("concurrent reservations did not get one exclusive slot each: %v", got)
	}
	// The ledger itself refuses a second live row on a held slot.
	if _, err := ledger.db.ExecContext(ctx, `INSERT INTO sandboxes(id,token_hash,metadata,job_id,attempt,generation,fence,state,slot,started_ns,ends_ns)
		VALUES('intruder',x'00','{}','j',1,0,'','reserved','slot-2',0,0)`); err == nil {
		t.Fatal("ledger admitted two live rows on one slot")
	}
}

func TestSlotIsHeldUntilGoneNeverOnUnknown(t *testing.T) {
	ctx := context.Background()
	ledger := openLedger(t)
	slots := []string{"slot-1", "slot-2"}
	first, err := ledger.Reserve(ctx, slotRow("a"), 2, slots)
	if err != nil || first != "slot-1" {
		t.Fatalf("first reservation: %q %v", first, err)
	}
	if err := ledger.SetState(ctx, "a", "unknown"); err != nil {
		t.Fatal(err)
	}
	second, err := ledger.Reserve(ctx, slotRow("b"), 2, slots)
	if err != nil || second != "slot-2" {
		t.Fatalf("reused a slot whose guest may still exist: %q %v", second, err)
	}
	if _, err := ledger.Reserve(ctx, slotRow("c"), 2, slots); !errors.Is(err, ErrCapacity) {
		t.Fatalf("admitted a guest with every slot held: %v", err)
	}
	// Capacity may be lower than the slot count, never higher.
	if err := ledger.SetState(ctx, "b", "gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(ctx, slotRow("c"), 1, slots); !errors.Is(err, ErrCapacity) {
		t.Fatalf("exceeded max VMs: %v", err)
	}
	if err := ledger.SetState(ctx, "a", "gone"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetState(ctx, "a", "running"); err != nil {
		t.Fatal(err)
	}
	third, err := ledger.Reserve(ctx, slotRow("c"), 2, slots)
	if err != nil || third != "slot-1" {
		t.Fatalf("slot proved gone was not reusable: %q %v", third, err)
	}
	// A configured slot list that no longer names a live row's slot still
	// counts that row toward capacity.
	if _, err := ledger.Reserve(ctx, slotRow("d"), 1, []string{"slot-2"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("ignored a live row on a removed slot: %v", err)
	}
}

// A ledger from before slots existed may hold live guests on an unknown
// network. It keeps them, assigns them nothing, and admits nobody until they
// are proved gone.
func TestPreSlotLedgerRefusesAdmissionUntilLegacyRowsAreGone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pre-slot.sqlite")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`CREATE TABLE sandboxes (
		id TEXT PRIMARY KEY, token_hash BLOB NOT NULL, metadata TEXT NOT NULL,
		job_id TEXT NOT NULL, attempt INTEGER NOT NULL, generation INTEGER NOT NULL,
		fence TEXT NOT NULL, state TEXT NOT NULL,
		template_id TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
		worker_id TEXT NOT NULL DEFAULT '',
		started_ns INTEGER NOT NULL, ends_ns INTEGER NOT NULL
	)`)
	for _, row := range [][]any{{"live", "running"}, {"old", "gone"}} {
		if err == nil {
			_, err = old.Exec(`INSERT INTO sandboxes VALUES (?,x'00','{}',?,1,1,'',?,'review','linux-arm64','mac-local',0,0)`, row[0], row[0], row[1])
		}
	}
	if closeErr := old.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if row, err := ledger.Get(ctx, "live"); err != nil || row.State != "running" || row.Slot != "" {
		t.Fatalf("legacy row lost or given a guessed slot: %+v %v", row, err)
	}
	slots := []string{"slot-1", "slot-2"}
	for _, state := range []string{"running", "unknown"} {
		if err := ledger.SetState(ctx, "live", state); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Reserve(ctx, slotRow("new"), 2, slots); !errors.Is(err, ErrLegacySlot) {
			t.Fatalf("admitted beside a %s legacy guest: %v", state, err)
		}
	}
	if err := ledger.SetState(ctx, "live", "gone"); err != nil {
		t.Fatal(err)
	}
	if slot, err := ledger.Reserve(ctx, slotRow("new"), 2, slots); err != nil || slot != "slot-1" {
		t.Fatalf("legacy rows proved gone still block admission: %q %v", slot, err)
	}
}
