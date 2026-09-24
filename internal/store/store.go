// Package store owns the durable reservation and identity ledger for sandbox VMs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrCapacity = errors.New("sandbox capacity exhausted")
	ErrStale    = errors.New("stale or duplicate job attempt")
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
	Started    time.Time
	Ends       time.Time
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
			worker_id TEXT NOT NULL DEFAULT '',
			started_ns INTEGER NOT NULL, ends_ns INTEGER NOT NULL
		)`,
		"CREATE INDEX IF NOT EXISTS sandboxes_job ON sandboxes(job_id, generation DESC, attempt DESC)",
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
	return &Store{db: db, lock: lock}, nil
}

// Old development ledgers lacked template, image and worker identity. Preserve
// their rows and reservations; an unknown identity is never inferred as a new
// worker during recovery.
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
	for _, name := range []string{"template_id", "image", "worker_id"} {
		if existing[name] {
			continue
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE sandboxes ADD COLUMN "+name+" TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("migrate ledger %s: %w", name, err)
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

// Reserve serializes capacity and fencing checks with insertion. An exclusive
// filesystem lock also prevents a second service from reconciling an in-flight
// Create in another process.
func (s *Store) Reserve(ctx context.Context, row Row, maxVMs int) (err error) {
	if row.TemplateID == "" || row.Image == "" || row.WorkerID == "" {
		return errors.New("sandbox template, image and worker identity are required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var generation, attempt int64
	err = conn.QueryRowContext(ctx, "SELECT generation,attempt FROM sandboxes WHERE job_id=? ORDER BY generation DESC,attempt DESC LIMIT 1", row.JobID).Scan(&generation, &attempt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (row.Generation < generation || row.Generation == generation && row.Attempt <= attempt) {
		return ErrStale
	}
	var active int
	if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM sandboxes WHERE state <> 'gone'").Scan(&active); err != nil {
		return err
	}
	if active >= maxVMs {
		return ErrCapacity
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO sandboxes(id,token_hash,metadata,job_id,attempt,generation,fence,state,template_id,image,worker_id,started_ns,ends_ns)
		VALUES(?,?,?,?,?,?,?,'reserved',?,?,?,?,?)`, row.ID, row.TokenHash, row.Metadata, row.JobID, row.Attempt, row.Generation, row.Fence,
		row.TemplateID, row.Image, row.WorkerID, row.Started.UnixNano(), row.Ends.UnixNano())
	if err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func scanRow(scanner interface{ Scan(...any) error }) (Row, error) {
	var row Row
	var start, end int64
	err := scanner.Scan(&row.ID, &row.TokenHash, &row.Metadata, &row.JobID, &row.Attempt, &row.Generation, &row.Fence, &row.State,
		&row.TemplateID, &row.Image, &row.WorkerID, &start, &end)
	if err == nil {
		row.Started = time.Unix(0, start).UTC()
		row.Ends = time.Unix(0, end).UTC()
	}
	return row, err
}

const columns = "id,token_hash,metadata,job_id,attempt,generation,fence,state,template_id,image,worker_id,started_ns,ends_ns"

func (s *Store) Get(ctx context.Context, id string) (Row, error) {
	return scanRow(s.db.QueryRowContext(ctx, "SELECT "+columns+" FROM sandboxes WHERE id=?", id))
}

func (s *Store) Active(ctx context.Context) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+columns+" FROM sandboxes WHERE state <> 'gone'")
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

func (s *Store) SetState(ctx context.Context, id, state string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET state=? WHERE id=? AND state <> 'gone'", state, id)
	return err
}

func (s *Store) Extend(ctx context.Context, id string, end time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sandboxes SET ends_ns=? WHERE id=? AND state='running'", end.UnixNano(), id)
	return err
}
