package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// EnvPostgresDSN is where the Postgres connection string is read from. It is
// environment-only on purpose: a DSN carries a password, and a flag would put it
// in `ps` output and in the fleet's forwarded argv.
const EnvPostgresDSN = "ACHILLES_VAULT_DSN"

const (
	pgTable     = "vault_records"
	pgLockKey   = 7305411 // arbitrary app-wide advisory-lock id serializing schema setup
	pgOpTimeout = 30 * time.Second
)

// pgSchema is applied statement by statement at open. Every statement is
// idempotent, so any number of processes may start at once.
var pgSchema = []string{
	`CREATE TABLE IF NOT EXISTS ` + pgTable + ` (
		seq            BIGSERIAL PRIMARY KEY,
		tenant         TEXT        NOT NULL,
		id             TEXT        NOT NULL,
		run_id         TEXT        NOT NULL,
		phase          TEXT        NOT NULL DEFAULT '',
		kind           TEXT        NOT NULL,
		source         TEXT        NOT NULL DEFAULT '',
		prompt_version TEXT        NOT NULL DEFAULT '',
		fingerprint    TEXT        NOT NULL DEFAULT '',
		prev_id        TEXT        NOT NULL DEFAULT '',
		ts             TIMESTAMPTZ NOT NULL,
		payload        BYTEA,
		UNIQUE (tenant, id)
	)`,
	`CREATE INDEX IF NOT EXISTS vault_records_run_idx  ON ` + pgTable + ` (tenant, run_id, seq)`,
	`CREATE INDEX IF NOT EXISTS vault_records_fp_idx   ON ` + pgTable + ` (tenant, fingerprint, seq)`,
	`CREATE INDEX IF NOT EXISTS vault_records_ts_idx   ON ` + pgTable + ` (tenant, ts)`,
}

// PostgresStore is an Evidence Vault in PostgreSQL. All tenants share one table;
// a store is bound to one tenant and every query carries `tenant = $1`, so a
// handle can never read another tenant's rows. That isolation is by construction
// of this type, not enforced by the database: run each tenant in its own database
// if you need isolation that survives a bug here. (The file backend
// isolates structurally: a file per tenant.)
//
// Payloads are stored as BYTEA, not JSONB, so the audit trail keeps the exact
// bytes that were written (JSONB would reorder keys and normalize numbers).
type PostgresStore struct {
	db     *sql.DB
	tenant string
	readHealth
}

var (
	poolMu sync.Mutex
	pools  = map[string]*sql.DB{} // one pool per DSN, shared by every tenant's store
)

// poolFor returns the shared pool for dsn, opening it and ensuring the schema on
// first use.
func poolFor(ctx context.Context, dsn string) (*sql.DB, error) {
	poolMu.Lock()
	defer poolMu.Unlock()
	if db, ok := pools[dsn]; ok {
		return db, nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres vault: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := ensureSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	pools[dsn] = db
	return db, nil
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("connect to postgres vault: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit
	// Concurrent CREATE ... IF NOT EXISTS can still race inside Postgres; the
	// transaction-scoped advisory lock makes simultaneous starts take turns.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockKey); err != nil {
		return fmt.Errorf("lock postgres vault schema: %w", err)
	}
	for _, stmt := range pgSchema {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create postgres vault schema: %w", err)
		}
	}
	return tx.Commit()
}

// NewPostgresStore opens the vault for one tenant. tenant is the isolation key
// (see TenantKey, e.g. "tenant-acme"); it must be non-empty.
func NewPostgresStore(ctx context.Context, dsn, tenant string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres vault: no connection string (set %s)", EnvPostgresDSN)
	}
	if tenant == "" {
		return nil, fmt.Errorf("postgres vault: empty tenant key")
	}
	db, err := poolFor(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{db: db, tenant: tenant}, nil
}

// PostgresTenants lists the tenant keys that hold records and start with prefix,
// with the prefix removed.
func PostgresTenants(ctx context.Context, dsn, prefix string) ([]string, error) {
	db, err := poolFor(ctx, dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT tenant FROM `+pgTable+` WHERE starts_with(tenant, $1) ORDER BY tenant`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		if id := t[len(prefix):]; id != "" {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

func newRecordID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Append stores r immutably. The returned record carries the stored timestamp,
// which Postgres keeps at microsecond precision.
func (s *PostgresStore) Append(r Record) (Record, error) {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	r.Timestamp = r.Timestamp.UTC().Truncate(time.Microsecond)
	id, err := newRecordID()
	if err != nil {
		return Record{}, fmt.Errorf("record id: %w", err)
	}
	r.ID = id

	ctx, cancel := context.WithTimeout(context.Background(), pgOpTimeout)
	defer cancel()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO `+pgTable+` (tenant, id, run_id, phase, kind, source, prompt_version, fingerprint, prev_id, ts, payload)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.tenant, r.ID, r.RunID, r.Phase, string(r.Kind), r.Source, r.PromptVersion, r.Fingerprint, r.PrevID,
		r.Timestamp, []byte(r.Payload))
	if err != nil {
		return Record{}, fmt.Errorf("append to postgres vault: %w", err)
	}
	return r, nil
}

const pgColumns = `id, run_id, phase, kind, source, prompt_version, fingerprint, prev_id, ts, payload`

// Get returns a record by ID.
func (s *PostgresStore) Get(id string) (Record, bool) {
	recs := s.query(`SELECT `+pgColumns+` FROM `+pgTable+` WHERE tenant = $1 AND id = $2`, s.tenant, id)
	if len(recs) == 0 {
		return Record{}, false
	}
	return recs[0], true
}

// ByRun returns all records for a run in insertion order.
func (s *PostgresStore) ByRun(runID string) []Record {
	return s.query(`SELECT `+pgColumns+` FROM `+pgTable+` WHERE tenant = $1 AND run_id = $2 ORDER BY seq`, s.tenant, runID)
}

// ByFingerprint returns all records for a finding fingerprint in insertion order.
func (s *PostgresStore) ByFingerprint(fp string) []Record {
	return s.query(`SELECT `+pgColumns+` FROM `+pgTable+` WHERE tenant = $1 AND fingerprint = $2 ORDER BY seq`, s.tenant, fp)
}

// All returns every record in insertion order.
func (s *PostgresStore) All() []Record {
	return s.query(`SELECT `+pgColumns+` FROM `+pgTable+` WHERE tenant = $1 ORDER BY seq`, s.tenant)
}

// Purge deletes this tenant's records older than the cutoff (retention).
func (s *PostgresStore) Purge(before time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pgOpTimeout)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+pgTable+` WHERE tenant = $1 AND ts < $2`, s.tenant, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("purge postgres vault: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// query runs a SELECT of pgColumns. The Store read methods cannot return an
// error, so a failure is reported on stderr, recorded for ReadErr/ReadFailures
// (so a caller can tell "the query failed" from "nothing is there"), and yields
// no rows.
func (s *PostgresStore) query(q string, args ...any) (out []Record) {
	var readErr error
	defer func() { s.noteRead(readErr) }()

	ctx, cancel := context.WithTimeout(context.Background(), pgOpTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		readErr = fmt.Errorf("postgres vault query: %w", err)
		fmt.Fprintf(os.Stderr, "achilles: postgres vault query failed: %v\n", err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var (
			r       Record
			kind    string
			payload []byte
		)
		if err := rows.Scan(&r.ID, &r.RunID, &r.Phase, &kind, &r.Source, &r.PromptVersion,
			&r.Fingerprint, &r.PrevID, &r.Timestamp, &payload); err != nil {
			readErr = fmt.Errorf("postgres vault scan: %w", err)
			fmt.Fprintf(os.Stderr, "achilles: postgres vault scan failed: %v\n", err)
			return out
		}
		r.Kind = Kind(kind)
		r.Timestamp = r.Timestamp.UTC()
		if payload != nil {
			r.Payload = json.RawMessage(payload)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		readErr = fmt.Errorf("postgres vault read: %w", err)
		fmt.Fprintf(os.Stderr, "achilles: postgres vault read failed: %v\n", err)
	}
	return out
}

var (
	_ Store        = (*PostgresStore)(nil)
	_ Purger       = (*PostgresStore)(nil)
	_ ReadReporter = (*PostgresStore)(nil)
)
