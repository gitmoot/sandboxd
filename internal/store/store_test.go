package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableCapacityAndAttemptFence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(ctx, path); err == nil {
		_ = other.Close()
		t.Fatal("second service acquired a live ledger during VM creation")
	}
	start := time.Now()
	row := Row{ID: "first", TokenHash: make([]byte, 32), Metadata: "{}", JobID: "review", Attempt: 1,
		TemplateID: "review", Image: "linux-arm64", WorkerID: "mac-local", Generation: 2, Started: start, Ends: start.Add(time.Hour)}
	if err := ledger.Reserve(ctx, row, 1); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if got, err := ledger.Get(ctx, "first"); err != nil || got.State != "reserved" {
		t.Fatalf("lost durable reservation: state %q error %v", got.State, err)
	}
	second := row
	second.ID = "second"
	second.JobID = "other"
	if err := ledger.Reserve(ctx, second, 1); !errors.Is(err, ErrCapacity) {
		t.Fatalf("concurrency slot was released without proof of absence: %v", err)
	}
	if err := ledger.SetState(ctx, row.ID, "gone"); err != nil {
		t.Fatal(err)
	}
	second.JobID = row.JobID
	if err := ledger.Reserve(ctx, second, 1); !errors.Is(err, ErrStale) {
		t.Fatalf("duplicate attempt after restart: %v", err)
	}
	second.Attempt = 2
	if err := ledger.Reserve(ctx, second, 1); err != nil {
		t.Fatalf("new attempt should replace proved-gone slot: %v", err)
	}
}

func TestConcurrentReservationsDoNotOversubscribe(t *testing.T) {
	ctx := context.Background()
	ledger, err := Open(ctx, filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	start := make(chan struct{})
	results := make(chan error, 8)
	now := time.Now()
	for i := range cap(results) {
		go func(i int) {
			<-start
			row := Row{ID: string(rune('a' + i)), TokenHash: make([]byte, 32), Metadata: "{}",
				TemplateID: "review", Image: "linux-arm64", WorkerID: "mac-local",
				JobID: string(rune('A' + i)), Attempt: 1, Started: now, Ends: now.Add(time.Hour)}
			results <- ledger.Reserve(ctx, row, 1)
		}(i)
	}
	close(start)
	successes := 0
	for range cap(results) {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrCapacity):
		default:
			t.Fatalf("reservation error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("allocated %d of one VM slots", successes)
	}
}

func TestLegacyLedgerPreservesUnknownWorkerAndCapacity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`CREATE TABLE sandboxes (
		id TEXT PRIMARY KEY, token_hash BLOB NOT NULL, metadata TEXT NOT NULL,
		job_id TEXT NOT NULL, attempt INTEGER NOT NULL, generation INTEGER NOT NULL,
		fence TEXT NOT NULL, state TEXT NOT NULL, started_ns INTEGER NOT NULL, ends_ns INTEGER NOT NULL
	)`)
	if err == nil {
		_, err = old.Exec(`INSERT INTO sandboxes VALUES (?,?,?,?,?,?,?,?,?,?)`,
			"legacy-vm", make([]byte, 32), "{}", "old-job", 1, 1, "", "running", time.Now().UnixNano(), time.Now().Add(time.Minute).UnixNano())
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	row, err := ledger.Get(ctx, "legacy-vm")
	if err != nil || row.State != "running" || row.WorkerID != "" || row.TemplateID != "" || row.Image != "" {
		t.Fatalf("legacy owner guessed or reservation lost: %+v, %v", row, err)
	}
	newRow := Row{ID: "new-vm", TokenHash: make([]byte, 32), Metadata: "{}", JobID: "new-job",
		TemplateID: "review", Image: "linux-arm64", WorkerID: "mac-local", Attempt: 1,
		Started: time.Now(), Ends: time.Now().Add(time.Minute)}
	if err := ledger.Reserve(ctx, newRow, 1); !errors.Is(err, ErrCapacity) {
		t.Fatalf("migration released an unconfirmed old VM: %v", err)
	}
}
