// Package store owns the durable reservation and identity ledger for sandbox VMs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrCapacity = errors.New("sandbox capacity exhausted")
	ErrStale    = errors.New("stale or duplicate job attempt")
	// ErrLegacySlot refuses admission while a live row predates network slots:
	// its guest's network is unknown, so no slot can be proven free.
	ErrLegacySlot = errors.New("live sandbox without a recorded network slot")
)

type Row struct {
	ID         string
	TemplateID string
	Image      string
	WorkerID   string
	TokenHash  []byte
	Metadata   string
	JobID      string
	Attempt    int64
	Generation int64
	Fence      string
	State      string
	// Slot is the guest's exclusive network slot on its worker. It stays
	// occupied until the row is gone; "" marks a row created before slots were
	// recorded.
	Slot string
	// CPUs and MemoryMiB are the VM shape the worker was asked for; zero marks
	// a row written before they were recorded.
	CPUs      int
	MemoryMiB int
	// Lease is the worker enrollment lease under which the row was last
	// proven present. Guest access requires the worker's current lease.
	Lease   int64
	Started time.Time
	Ends    time.Time
}

type Store struct {
	db   *sql.DB
	lock *os.File
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") || strings.ContainsAny(path, "?#") {
		return nil, errors.New("durable SQLite filesystem path required")
	}
	// The database contains only token hashes, but should not be world-readable.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open ledger lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("ledger already owned: %w", err)
	}
	release := func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		release()
		return nil, fmt.Errorf("open ledger: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		release()
		return nil, fmt.Errorf("secure ledger permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		release()
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		release()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
		`CREATE TABLE IF NOT EXISTS sandboxes (
			id TEXT PRIMARY KEY, token_hash BLOB NOT NULL, metadata TEXT NOT NULL,
			job_id TEXT NOT NULL, attempt INTEGER NOT NULL, generation INTEGER NOT NULL,
			fence TEXT NOT NULL, state TEXT NOT NULL,
			template_id TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
			worker_id TEXT NOT NULL DEFAULT '', slot TEXT NOT NULL DEFAULT '',
			cpus INTEGER NOT NULL DEFAULT 0, memory_mib INTEGER NOT NULL DEFAULT 0, lease INTEGER NOT NULL DEFAULT 0,
			started_ns INTEGER NOT NULL, ends_ns INTEGER NOT NULL
		)`,
		"CREATE INDEX IF NOT EXISTS sandboxes_job ON sandboxes(job_id, generation DESC, attempt DESC)",
		// Lease counters survive restarts, so a restarted gateway never presents
		// a worker with a lease it has already superseded.
		// local marks an identity whose VMs ran on the gateway's own host and
		// so shared its physical slot networks.
		"CREATE TABLE IF NOT EXISTS workers (id TEXT PRIMARY KEY, lease INTEGER NOT NULL, local INTEGER NOT NULL DEFAULT 0)",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			release()
			return nil, fmt.Errorf("initialize ledger: %w", err)
		}
	}
	if err := migrateIdentity(ctx, db); err != nil {
		_ = db.Close()
		release()
		return nil, err
	}
	// Durable exclusivity: no two live rows ever share a slot on one worker.
	// Slot names are worker-local, so two workers may reuse the same names.
	for _, statement := range []string{
		"DROP INDEX IF EXISTS sandboxes_live_slot",
		"CREATE UNIQUE INDEX IF NOT EXISTS sandboxes_live_worker_slot ON sandboxes(worker_id, slot) WHERE state NOT IN ('gone','unverified') AND slot <> ''",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			release()
			return nil, fmt.Errorf("initialize ledger slot index: %w", err)
		}
	}
	return &Store{db: db, lock: lock}, nil
}

// Old development ledgers lacked template, image, worker and slot identity.
// Preserve their rows and reservations; an unknown identity is never inferred
// as a new worker or a free slot during recovery.
func migrateIdentity(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(sandboxes)")
	if err != nil {
		return err
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var index, required, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&index, &name, &kind, &required, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []struct{ name, kind string }{
		{"template_id", "TEXT NOT NULL DEFAULT ''"}, {"image", "TEXT NOT NULL DEFAULT ''"},
		{"worker_id", "TEXT NOT NULL DEFAULT ''"}, {"slot", "TEXT NOT NULL DEFAULT ''"},
		{"cpus", "INTEGER NOT NULL DEFAULT 0"}, {"memory_mib", "INTEGER NOT NULL DEFAULT 0"},
		{"lease", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if existing[column.name] {
			continue
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE sandboxes ADD COLUMN "+column.name+" "+column.kind); err != nil {
			return fmt.Errorf("migrate ledger %s: %w", column.name, err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	err := s.db.Close()
	_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	if lockErr := s.lock.Close(); err == nil {
		err = lockErr
	}
	return err
}

// Reserve serializes capacity, fencing and slot checks with insertion, and
// returns the exclusive network slot recorded for the new row: the first of
// slots held by no live row of the same worker or of sharing, other
// identities whose VMs use the same physical slots. Capacity and slots are
// per worker; job fencing and the pre-slot guard span the whole ledger. An
// exclusive filesystem lock also prevents a second service from reconciling
// an in-flight Create in another process.
func (s *Store) Reserve(ctx context.Context, row Row, maxVMs int, slots []string, sharing ...string) (slot string, err error) {
	if row.TemplateID == "" || row.Image == "" || row.WorkerID == "" {
		return "", errors.New("sandbox template, image and worker identity are required")
	}
	if len(slots) == 0 {
		return "", errors.New("sandbox network slots are required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var generation, attempt int64
	err = conn.QueryRowContext(ctx, "SELECT generation,attempt FROM sandboxes WHERE job_id=? ORDER BY generation DESC,attempt DESC LIMIT 1", row.JobID).Scan(&generation, &attempt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err == nil && (row.Generation < generation || row.Generation == generation && row.Attempt <= attempt) {
		return "", ErrStale
	}
	live, err := conn.QueryContext(ctx, "SELECT worker_id,slot FROM sandboxes WHERE "+liveState)
	if err != nil {
		return "", err
	}
	occupied := make(map[string]bool)
	active, legacy := 0, false
	for live.Next() {
		var worker, held string
		if err = live.Scan(&worker, &held); err != nil {
			live.Close()
			return "", err
		}
		legacy = legacy || held == ""
		if worker != row.WorkerID && !slices.Contains(sharing, worker) {
			continue
		}
		active++
		occupied[held] = true
	}
	err = live.Err()
	live.Close()
	if err != nil {
		return "", err
	}
	if legacy {
		return "", ErrLegacySlot
	}
	if active >= maxVMs {
		return "", ErrCapacity
	}
	for _, candidate := range slots {
		if candidate != "" && !occupied[candidate] {
			slot = candidate
			break
		}
	}
	if slot == "" {
		return "", ErrCapacity
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO sandboxes(id,token_hash,metadata,job_id,attempt,generation,fence,state,template_id,image,worker_id,slot,cpus,memory_mib,lease,started_ns,ends_ns)
		VALUES(?,?,?,?,?,?,?,'reserved',?,?,?,?,?,?,?,?,?)`, row.ID, row.TokenHash, row.Metadata, row.JobID, row.Attempt, row.Generation, row.Fence,
		row.TemplateID, row.Image, row.WorkerID, slot, row.CPUs, row.MemoryMiB, row.Lease, row.Started.UnixNano(), row.Ends.UnixNano())
	if err != nil {
		return "", err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return "", err
	}
	return slot, nil
}

func scanRow(scanner interface{ Scan(...any) error }) (Row, error) {
	var row Row
	var start, end int64
	err := scanner.Scan(&row.ID, &row.TokenHash, &row.Metadata, &row.JobID, &row.Attempt, &row.Generation, &row.Fence, &row.State,
		&row.TemplateID, &row.Image, &row.WorkerID, &row.Slot, &row.CPUs, &row.MemoryMiB, &row.Lease, &start, &end)
	if err == nil {
		row.Started = time.Unix(0, start).UTC()
		row.Ends = time.Unix(0, end).UTC()
	}
	return row, err
}

const columns = "id,token_hash,metadata,job_id,attempt,generation,fence,state,template_id,image,worker_id,slot,cpus,memory_mib,lease,started_ns,ends_ns"

func (s *Store) Get(ctx context.Context, id string) (Row, error) {
	return scanRow(s.db.QueryRowContext(ctx, "SELECT "+columns+" FROM sandboxes WHERE id=?", id))
}

func (s *Store) Active(ctx context.Context) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+columns+" FROM sandboxes WHERE "+liveState)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Row{}
	for rows.Next() {
		row, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) Current(ctx context.Context, row Row) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM sandboxes WHERE job_id=? ORDER BY generation DESC,attempt DESC LIMIT 1", row.JobID).Scan(&id)
	return id == row.ID, err
}

// liveState selects rows that hold a reservation. "gone" rows were proven
// destroyed; "unverified" rows were released by an operator who forgot their
// worker without proof that their VMs are gone.
const liveState = "state NOT IN ('gone','unverified')"

// SetState never revives a released row.
func (s *Store) SetState(ctx context.Context, id, state string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET state=? WHERE id=? AND "+liveState, state, id)
	return err
}

// Forget releases every live reservation of workerID as "unverified" and
// returns the released sandbox IDs.
func (s *Store) Forget(ctx context.Context, workerID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "UPDATE sandboxes SET state='unverified' WHERE worker_id=? AND "+liveState+" RETURNING id", workerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Unverified returns workerID's rows released by Forget.
func (s *Store) Unverified(ctx context.Context, workerID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM sandboxes WHERE worker_id=? AND state='unverified'", workerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ResolveUnverified marks a released row gone once its worker's complete
// inventory and a targeted destroy proved its VM gone.
func (s *Store) ResolveUnverified(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET state='gone' WHERE id=? AND state='unverified'", id)
	return err
}

// Identities returns every worker identity that ever enrolled, mapped to
// whether it ran on the gateway's own host.
func (s *Store) Identities(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,local FROM workers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]bool)
	for rows.Next() {
		var id string
		var local bool
		if err := rows.Scan(&id, &local); err != nil {
			return nil, err
		}
		result[id] = local
	}
	return result, rows.Err()
}

// NextLease durably advances a worker's enrollment lease and returns it. A
// new gateway instance claims each worker once with it; no earlier instance
// ever used the result, including one that ran before a gateway restart and
// was not fenced yet. The result exceeds above, which lets a newly
// started gateway claim a worker that already holds a higher lease (its ledger
// was replaced). local records whether the worker runs on the gateway's own
// host.
func (s *Store) NextLease(ctx context.Context, workerID string, local bool, above int64) (int64, error) {
	if workerID == "" {
		return 0, errors.New("worker identity is required")
	}
	var lease int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO workers(id,lease,local) VALUES(?,max(1,?+1),?)
		ON CONFLICT(id) DO UPDATE SET lease=max(lease+1,?+1), local=excluded.local RETURNING lease`,
		workerID, above, local, above).Scan(&lease)
	return lease, err
}

// Adopt records that a running row was proven present under lease.
func (s *Store) Adopt(ctx context.Context, id string, lease int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET lease=? WHERE id=? AND state='running'", lease, id)
	return err
}

func (s *Store) Extend(ctx context.Context, id string, end time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET ends_ns=? WHERE id=? AND state='running'", end.UnixNano(), id)
	return err
}
