// Package store persists engagement inputs, completed jobs, observations and record metadata
// in SQLite.
package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/fault"
)

const (
	applicationID = 0x52454331 // "REC1"
	schemaVersion = 1
	maxBatch      = 200
	maxBatchWait  = 100 * time.Millisecond
)

const schema = `
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE inputs(kind TEXT NOT NULL, value TEXT NOT NULL, added_at TEXT NOT NULL, PRIMARY KEY(kind, value));
CREATE TABLE jobs(procedure TEXT NOT NULL, key TEXT NOT NULL, completed_at TEXT NOT NULL, PRIMARY KEY(procedure, key));
CREATE TABLE records(kind TEXT NOT NULL, key TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                     current INTEGER NOT NULL, PRIMARY KEY(kind, key));
CREATE TABLE observations(kind TEXT NOT NULL, key TEXT NOT NULL, producer TEXT NOT NULL, job_key TEXT NOT NULL,
                          attrs TEXT NOT NULL, seen TEXT NOT NULL, PRIMARY KEY(kind, key, producer, job_key));
CREATE INDEX observations_job ON observations(producer, job_key);
`

// Options configure a Store.
type Options struct {
	Clock    func() time.Time
	Redactor *config.Redactor
}

// Obs is an observation produced by completing a job.
type Obs struct {
	Kind, Key string
	Attrs     map[string]any
}

// Record combines an entity's metadata with attributes merged from its current observations.
type Record struct {
	Kind, Key           string
	FirstSeen, LastSeen string
	Current             bool // true while any observation of the record exists
	Attrs               map[string]any
	Producers           []string // sorted procedures and analyses currently observing the record
}

// Str returns the string attribute k, or "" if it is absent or not a string.
func (r Record) Str(k string) string { s, _ := r.Attrs[k].(string); return s }

// ObsRow is the record key and job key of one stored observation.
type ObsRow struct{ Key, JobKey string }

// Input is a stored scope input or exclusion.
type Input struct{ Kind, Value, AddedAt string }

// op queues a job completion, or a flush barrier when done is set.
type op struct {
	procedure, job string
	obs            []Obs
	noJob          bool // an analysis's or the guard's write: no row in jobs
	done           chan error
}

// Store serialises writes through one goroutine and commits them in batches. Its methods are
// safe for concurrent use.
type Store struct {
	db    *sql.DB
	clock func() time.Time
	red   *config.Redactor

	ch chan op
	wg sync.WaitGroup
	// chMu keeps Close from closing ch while a sender holds a read lock. The writer never
	// takes this lock.
	chMu   sync.RWMutex
	closed bool       // guarded by chMu
	mu     sync.Mutex // guards err, onNew, versions
	err    error
	onNew  func(kind, key string, attrs map[string]any)
	// versions tracks committed changes per record kind for cache invalidation.
	versions map[string]uint64
	once     sync.Once
	stmts    writeStmts // the writer's statements, prepared once

	// shown caches the last baseline read or saved; shownKnown indicates whether the cache
	// is valid.
	shownMu    sync.Mutex
	shown      []ShownRow
	shownKnown bool
}

// writeStmts keeps prepared statements for repeated observation writes, avoiding SQL parsing on
// every commit.
type writeStmts struct {
	insertRecord, touchRecord, upsertObs, jobObs, deleteObs, refresh, complete *sql.Stmt
}

var writeSQL = []string{
	// The insert identifies first sightings; any newly observed record becomes current.
	"INSERT INTO records(kind,key,first_seen,last_seen,current) VALUES(?,?,?,?,1) ON CONFLICT(kind,key) DO NOTHING",
	"UPDATE records SET last_seen=?, current=1 WHERE kind=? AND key=?",
	`INSERT INTO observations(kind,key,producer,job_key,attrs,seen) VALUES(?,?,?,?,?,?)
		ON CONFLICT(kind,key,producer,job_key) DO UPDATE SET attrs=excluded.attrs, seen=excluded.seen`,
	"SELECT kind,key FROM observations WHERE producer=? AND job_key=?",
	"DELETE FROM observations WHERE kind=? AND key=? AND producer=? AND job_key=?",
	refreshSQL,
	"INSERT OR REPLACE INTO jobs(procedure,key,completed_at) VALUES(?,?,?)",
}

func (w *writeStmts) prepare(db *sql.DB) error {
	ptrs := []**sql.Stmt{&w.insertRecord, &w.touchRecord, &w.upsertObs, &w.jobObs, &w.deleteObs, &w.refresh, &w.complete}
	for i, q := range writeSQL {
		st, err := db.Prepare(q)
		if err != nil {
			w.close()
			return err
		}
		*ptrs[i] = st
	}
	return nil
}

func (w *writeStmts) close() {
	for _, st := range []*sql.Stmt{w.insertRecord, w.touchRecord, w.upsertObs, w.jobObs, w.deleteObs, w.refresh, w.complete} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// txStmts binds the prepared writer statements to one transaction.
type txStmts struct {
	insertRecord, touchRecord, upsertObs, jobObs, deleteObs, refresh, complete *sql.Stmt
}

func (w *writeStmts) in(tx *sql.Tx) txStmts {
	return txStmts{tx.Stmt(w.insertRecord), tx.Stmt(w.touchRecord), tx.Stmt(w.upsertObs), tx.Stmt(w.jobObs),
		tx.Stmt(w.deleteObs), tx.Stmt(w.refresh), tx.Stmt(w.complete)}
}

// Open opens or initialises the state database at path.
func Open(path string, o Options) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", dsn(path, q))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := initDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("state database %s: %w", path, err)
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &Store{db: db, clock: clock, red: o.Redactor, ch: make(chan op, 1024), versions: map[string]uint64{}}
	if err := s.stmts.prepare(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("state database %s: %w", path, err)
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// dsn escapes the database path before adding URI options. Otherwise SQLite would interpret ?,
// # and percent escapes as URI syntax.
func dsn(path string, q url.Values) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// ReadOnly opens existing state without a writer, so it cannot queue changes.
type ReadOnly struct {
	path string
	db   *sql.DB
	// stamp detects changes to an immutable-opened database. WAL connections leave it nil.
	stamp *fileStamp
}

type fileStamp struct {
	size int64
	mod  time.Time
}

// OpenReadOnly validates an existing nyx database without creating files or running migrations.
// An existing WAL is read normally. Without a WAL, it uses immutable mode to avoid creating
// -wal and -shm files; View handles a run starting later.
func OpenReadOnly(path string) (*ReadOnly, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("mode", "ro")
	var stamp *fileStamp
	if _, err := os.Stat(path + "-wal"); errors.Is(err, os.ErrNotExist) {
		q.Add("immutable", "1")
		stamp = &fileStamp{size: fi.Size(), mod: fi.ModTime()}
	}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "query_only(1)")
	db, err := sql.Open("sqlite", dsn(path, q))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	if err := checkDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("state database %s: %w", path, err)
	}
	return &ReadOnly{path: path, db: db, stamp: stamp}, nil
}

// View gives fn a consistent read transaction. An immutable connection cannot lock out a run
// that starts during reading, so View reopens and retries if the database changed or a WAL
// appeared. fn must rebuild its result from scratch on every call.
func (r *ReadOnly) View(fn func(Reader) error) error {
	for range 3 {
		err := r.view(fn)
		if !r.moved() {
			return err
		}
		n, oerr := OpenReadOnly(r.path)
		if oerr != nil {
			return oerr
		}
		_ = r.db.Close()
		*r = *n
	}
	return errors.New("the state database changed each time it was read")
}

func (r *ReadOnly) view(fn func(Reader) error) error {
	tx, err := r.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	return fn(Reader{tx})
}

// moved detects a new WAL or a file change since immutable open.
func (r *ReadOnly) moved() bool {
	if r.stamp == nil {
		return false
	}
	if _, err := os.Stat(r.path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		return true
	}
	fi, err := os.Stat(r.path)
	return err != nil || fi.Size() != r.stamp.size || !fi.ModTime().Equal(r.stamp.mod)
}

// Close closes the database.
func (r *ReadOnly) Close() error { return r.db.Close() }

// checkDB validates the database's nyx application ID and supported schema version.
func checkDB(db *sql.DB) error {
	appID, version, err := dbIDs(db)
	if err != nil {
		return err
	}
	return checkIDs(appID, version)
}

// dbIDs reads a database's application id and schema version.
func dbIDs(db *sql.DB) (appID, version int, err error) {
	if err := db.QueryRow("PRAGMA application_id").Scan(&appID); err != nil {
		return 0, 0, err
	}
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return 0, 0, err
	}
	return appID, version, nil
}

// checkIDs validates the application ID and schema version this binary can read.
func checkIDs(appID, version int) error {
	switch {
	case appID != applicationID:
		return errors.New("not a nyx state database")
	case version > schemaVersion:
		return fmt.Errorf("state database version %d is newer than this nyx understands (%d)", version, schemaVersion)
	}
	return nil
}

func initDB(db *sql.DB) error {
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&tables); err != nil {
		return err
	}
	appID, version, err := dbIDs(db)
	if err != nil {
		return err
	}
	if appID == 0 && version == 0 && tables == 0 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }() // a no-op after Commit
		if _, err := tx.Exec(schema); err != nil {
			return err
		}
		if _, err := tx.Exec(shownSchema); err != nil {
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA application_id=%d", applicationID)); err != nil {
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := checkIDs(appID, version); err != nil { // future migrations go after it, keyed on user_version
		return err
	}
	_, err = db.Exec(shownSchema)
	return err
}

func (s *Store) today() string { return s.clock().UTC().Format(time.DateOnly) }

// OnNew registers a writer-goroutine callback for first sightings, called after commit.
func (s *Store) OnNew(fn func(kind, key string, attrs map[string]any)) {
	s.mu.Lock()
	s.onNew = fn
	s.mu.Unlock()
}

// send queues an operation unless the store has closed.
func (s *Store) send(o op) bool {
	s.chMu.RLock()
	defer s.chMu.RUnlock()
	if s.closed {
		return false
	}
	s.ch <- o
	return true
}

// JobKey redacts a key into its stored form. Use this form when comparing Completed results
// or passing valid keys to FinishRedo.
func (s *Store) JobKey(job string) string { return s.red.Redact(job) }

// Complete queues the completion of a job with its observations.
func (s *Store) Complete(procedure, job string, obs []Obs) {
	s.send(op{procedure: procedure, job: s.JobKey(job), obs: obs})
}

// Put queues the observations an analysis or the guard produces under (producer, key), without
// recording a completed job.
func (s *Store) Put(producer, key string, obs []Obs) {
	s.send(op{procedure: producer, job: s.JobKey(key), obs: obs, noJob: true})
}

// Flush waits until everything queued so far is committed and returns the first write error.
func (s *Store) Flush() error {
	done := make(chan error, 1)
	if !s.send(op{done: done}) {
		return s.firstErr()
	}
	return <-done
}

func (s *Store) firstErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close flushes and closes the store. It is idempotent.
func (s *Store) Close() error {
	var err error
	s.once.Do(func() {
		err = s.Flush()
		s.chMu.Lock()
		s.closed = true
		close(s.ch)
		s.chMu.Unlock()
		s.wg.Wait()
		s.stmts.close()
		if cerr := s.db.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

func (s *Store) writer() {
	defer s.wg.Done()
	for first := range s.ch {
		batch := []op{first}
		if first.done == nil {
			timer := time.NewTimer(maxBatchWait)
		collect:
			for len(batch) < maxBatch {
				select {
				case o, ok := <-s.ch:
					if !ok {
						break collect
					}
					batch = append(batch, o)
					if o.done != nil {
						break collect
					}
				case <-timer.C:
					break collect
				}
			}
			timer.Stop()
		}
		s.commit(batch)
	}
}

// commit saves the batch, announces new records and releases flush barriers. Panics become a
// persistent store error and still release barriers so Flush cannot hang.
func (s *Store) commit(batch []op) {
	defer func() {
		if v := recover(); v != nil {
			s.setErr(fmt.Errorf("store writer: panic: %v", v))
		}
		err := s.firstErr()
		for _, o := range batch {
			if o.done != nil {
				o.done <- err
			}
		}
	}()
	var news []Obs
	if s.firstErr() == nil {
		news = s.commitOps(batch)
	}
	s.mu.Lock()
	cb, err := s.onNew, s.err
	s.mu.Unlock()
	if err == nil && cb != nil {
		for _, n := range news {
			cb(n.Kind, n.Key, n.Attrs)
		}
	}
}

// KindVersion invalidates cached data whenever a committed write changes the kind's
// observations. Flush first to include all queued writes.
func (s *Store) KindVersion(kind string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions[kind]
}

func (s *Store) bump(kinds map[string]bool) {
	s.mu.Lock()
	for k := range kinds {
		s.versions[k]++
	}
	s.mu.Unlock()
}

func (s *Store) setErr(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *Store) commitOps(batch []op) []Obs {
	tx, err := s.db.Begin()
	if err != nil {
		s.setErr(err)
		return nil
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	today := s.today()
	var news []Obs
	kinds := map[string]bool{}
	wrote := false
	st := s.stmts.in(tx)
	for _, o := range batch {
		if o.done != nil {
			continue
		}
		n, err := s.applyComplete(st, o, today, kinds)
		if err != nil {
			s.setErr(err)
			return nil
		}
		news = append(news, n...)
		wrote = true
	}
	if !wrote {
		return nil
	}
	fault.Point("in-job-tx")
	if err := tx.Commit(); err != nil {
		s.setErr(err)
		return nil
	}
	s.bump(kinds)
	fault.Point("after-commit")
	return news
}

// applyComplete records the kinds touched by a job completion for version updates.
func (s *Store) applyComplete(st txStmts, o op, today string, kinds map[string]bool) ([]Obs, error) {
	// For duplicate observations within a job, the last value wins.
	type rk struct{ kind, key string }
	seen := map[rk]Obs{}
	var order []rk
	for _, ob := range o.obs {
		ob.Kind, ob.Key = s.red.Redact(ob.Kind), s.red.Redact(ob.Key)
		k := rk{ob.Kind, ob.Key}
		if _, ok := seen[k]; !ok {
			order = append(order, k)
		}
		seen[k] = ob
	}
	var news []Obs
	for _, k := range order {
		ob := seen[k]
		attrs := ob.Attrs
		if attrs == nil {
			attrs = map[string]any{}
		}
		attrs, _ = s.red.Any(attrs).(map[string]any)
		blob, err := json.Marshal(attrs)
		if err != nil {
			return nil, fmt.Errorf("observation %s/%s attrs: %w", k.kind, k.key, err)
		}
		res, err := st.insertRecord.Exec(k.kind, k.key, today, today)
		if err != nil {
			return nil, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, err
		} else if n == 1 {
			news = append(news, Obs{k.kind, k.key, attrs})
		} else if _, err := st.touchRecord.Exec(today, k.kind, k.key); err != nil {
			return nil, err
		}
		if _, err := st.upsertObs.Exec(k.kind, k.key, o.procedure, o.job, string(blob), today); err != nil {
			return nil, err
		}
		kinds[k.kind] = true
	}
	// Remove observations this job no longer produces. Refresh affected records because
	// other jobs may still support them.
	rows, err := st.jobObs.Query(o.procedure, o.job)
	stored, err := scanAll(rows, err, func(r *sql.Rows) (k rk, err error) {
		err = r.Scan(&k.kind, &k.key)
		return k, err
	})
	if err != nil {
		return nil, err
	}
	for _, k := range stored {
		if _, ok := seen[k]; ok {
			continue
		}
		if _, err := st.deleteObs.Exec(k.kind, k.key, o.procedure, o.job); err != nil {
			return nil, err
		}
		if _, err := st.refresh.Exec(k.kind, k.key); err != nil {
			return nil, err
		}
		kinds[k.kind] = true
	}
	if o.noJob {
		return news, nil
	}
	_, err = st.complete.Exec(o.procedure, o.job, today)
	return news, err
}

// refreshSQL marks a record current while it has any stored observation.
const refreshSQL = `UPDATE records SET current = EXISTS(SELECT 1 FROM observations o WHERE o.kind=records.kind AND o.key=records.key)
		WHERE kind=? AND key=?`

func refreshCurrent(tx *sql.Tx, kind, key string) error {
	_, err := tx.Exec(refreshSQL, kind, key)
	return err
}

// Completed returns a procedure's completed keys in their stored JobKey form.
func (s *Store) Completed(procedure string) (map[string]struct{}, error) {
	keys, err := queryAll(s.db, scanString, "SELECT key FROM jobs WHERE procedure=?", procedure)
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out, err
}

// querier lets readers use either a database connection or a transaction.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// queryAll executes a query and decodes each row with scan.
func queryAll[T any](q querier, scan func(*sql.Rows) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.Query(query, args...)
	return scanAll(rows, err, scan)
}

// scanAll handles a query result and decodes each row with scan.
func scanAll[T any](rows *sql.Rows, err error, scan func(*sql.Rows) (T, error)) ([]T, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanString(r *sql.Rows) (s string, err error) {
	err = r.Scan(&s)
	return s, err
}

// Reader exposes committed records, inputs and observations. Store readers see committed state
// at each call; ReadOnly.View readers share one transaction snapshot.
type Reader struct{ q querier }

// Records includes current and non-current records. Current observations merge field by field
// in procedure order, with later procedures winning. Unlisted procedures sort first.
func (s *Store) Records(kind string, order []string) ([]Record, error) {
	return Reader{s.db}.Records(kind, order)
}

// Records reads all records of a kind using this reader's snapshot; see Store.Records.
func (rd Reader) Records(kind string, order []string) ([]Record, error) {
	rank := map[string]int{}
	for i, st := range order {
		rank[st] = i + 1
	}
	recs, err := queryAll(rd.q, func(rows *sql.Rows) (r Record, err error) {
		var cur int
		err = rows.Scan(&r.Key, &r.FirstSeen, &r.LastSeen, &cur)
		r.Kind, r.Attrs, r.Current = kind, map[string]any{}, cur == 1
		return r, err
	}, "SELECT key,first_seen,last_seen,current FROM records WHERE kind=? ORDER BY key", kind)
	if err != nil {
		return nil, err
	}
	idx := make(map[string]int, len(recs))
	for i, r := range recs {
		idx[r.Key] = i
	}

	type ob struct {
		key, procedure, job string
		attrs               map[string]any
	}
	obs, err := queryAll(rd.q, func(rows *sql.Rows) (o ob, err error) {
		var blob string
		if err = rows.Scan(&o.key, &o.procedure, &o.job, &blob); err == nil {
			_ = json.Unmarshal([]byte(blob), &o.attrs)
		}
		return o, err
	}, "SELECT key,producer,job_key,attrs FROM observations WHERE kind=?", kind)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(obs, func(a, b ob) int {
		return cmp.Or(cmp.Compare(rank[a.procedure], rank[b.procedure]), cmp.Compare(a.procedure, b.procedure), cmp.Compare(a.job, b.job))
	})
	for _, o := range obs {
		i, ok := idx[o.key]
		if !ok {
			continue
		}
		maps.Copy(recs[i].Attrs, o.attrs)
		if !slices.Contains(recs[i].Producers, o.procedure) {
			recs[i].Producers = append(recs[i].Producers, o.procedure)
		}
	}
	for i := range recs {
		slices.Sort(recs[i].Producers)
	}
	return recs, nil
}

// Observations lists the observations of a kind made by a procedure.
func (s *Store) Observations(kind, procedure string) ([]ObsRow, error) {
	return Reader{s.db}.Observations(kind, procedure)
}

// Observations lists the observations of a kind made by a procedure.
func (rd Reader) Observations(kind, procedure string) ([]ObsRow, error) {
	return queryAll(rd.q, func(rows *sql.Rows) (r ObsRow, err error) {
		err = rows.Scan(&r.Key, &r.JobKey)
		return r, err
	}, "SELECT key,job_key FROM observations WHERE kind=? AND producer=? ORDER BY key,job_key", kind, procedure)
}

// Observer is a completed job that observes a record.
type Observer struct{ Procedure, JobKey string }

// Observers lists completed supporting jobs by record key, ordered by procedure and job key.
// Redo removes completion markers before replacing old observations, so those stale
// observations do not count as current support.
func (s *Store) Observers(kind string) (map[string][]Observer, error) {
	type row struct {
		key string
		o   Observer
	}
	rows, err := queryAll(s.db, func(r *sql.Rows) (w row, err error) {
		err = r.Scan(&w.key, &w.o.Procedure, &w.o.JobKey)
		return w, err
	}, `SELECT o.key, o.producer, o.job_key FROM observations o
		JOIN jobs j ON j.procedure = o.producer AND j.key = o.job_key
		WHERE o.kind = ? ORDER BY o.key, o.producer, o.job_key`, kind)
	if err != nil {
		return nil, err
	}
	out := map[string][]Observer{}
	for _, w := range rows {
		out[w.key] = append(out[w.key], w.o)
	}
	return out, nil
}

// Meta reads a metadata value.
func (s *Store) Meta(key string) (string, bool) {
	var v string
	if err := s.db.QueryRow("SELECT value FROM meta WHERE key=?", key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

const setMetaSQL = "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"

// SetMeta writes a metadata value.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(setMetaSQL, key, value)
	return err
}

// AddInput stores an input unless it is already stored.
func (s *Store) AddInput(kind, value string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO inputs(kind,value,added_at) VALUES(?,?,?)", kind, value, s.today())
	return err
}

// Inputs lists the stored inputs ordered by kind then value.
func (s *Store) Inputs() ([]Input, error) { return Reader{s.db}.Inputs() }

// Inputs lists the stored inputs ordered by kind then value.
func (rd Reader) Inputs() ([]Input, error) {
	return queryAll(rd.q, func(r *sql.Rows) (in Input, err error) {
		err = r.Scan(&in.Kind, &in.Value, &in.AddedAt)
		return in, err
	}, "SELECT kind,value,added_at FROM inputs ORDER BY kind,value")
}

// Redo removes a procedure's completion markers and marks it for a sweep. Old observations remain
// until jobs rerun, but no longer count in Observers. Affected kind versions change to
// invalidate support caches.
func (s *Store) Redo(procedure string) error {
	return s.update(func(tx *sql.Tx) (map[string]bool, error) {
		if _, err := tx.Exec("DELETE FROM jobs WHERE procedure=?", procedure); err != nil {
			return nil, err
		}
		names, err := queryAll(tx, scanString, "SELECT DISTINCT kind FROM observations WHERE producer=?", procedure)
		if err != nil {
			return nil, err
		}
		kinds := map[string]bool{}
		for _, k := range names {
			kinds[k] = true
		}
		_, err = tx.Exec(setMetaSQL, "redo:"+procedure, s.today())
		return kinds, err
	})
}

// update flushes queued work before running fn in a transaction. After commit it increments
// versions for the kinds fn changed.
func (s *Store) update(fn func(*sql.Tx) (map[string]bool, error)) error {
	if err := s.Flush(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	kinds, err := fn(tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.bump(kinds)
	return nil
}

// PendingRedo lists procedures whose redo has not finished.
func (s *Store) PendingRedo() ([]string, error) {
	keys, err := queryAll(s.db, scanString, "SELECT key FROM meta WHERE key LIKE 'redo:%' ORDER BY key")
	for i, k := range keys {
		keys[i] = strings.TrimPrefix(k, "redo:")
	}
	return keys, err
}

// FinishRedo removes observations for jobs absent from valid and clears the pending-redo
// marker. valid needs every current job key in stored JobKey form. The result reports
// whether records changed.
func (s *Store) FinishRedo(procedure string, valid map[string]struct{}) (changed bool, err error) {
	err = s.update(func(tx *sql.Tx) (map[string]bool, error) {
		kinds, err := sweepObservations(tx, procedure, valid)
		if err != nil {
			return nil, err
		}
		changed = len(kinds) > 0
		_, err = tx.Exec("DELETE FROM meta WHERE key=?", "redo:"+procedure)
		return kinds, err
	})
	return changed && err == nil, err
}

// Retire removes obsolete completed jobs and their observations. This makes superseded
// evidence non-current and allows a removed job to run if it reappears. valid needs every
// current key in JobKey form. The result reports whether records changed.
func (s *Store) Retire(procedure string, valid map[string]struct{}) (changed bool, err error) {
	err = s.update(func(tx *sql.Tx) (map[string]bool, error) {
		kinds, err := sweepObservations(tx, procedure, valid)
		if err != nil {
			return nil, err
		}
		if err := retireJobs(tx, procedure, valid); err != nil {
			return nil, err
		}
		changed = len(kinds) > 0
		return kinds, nil
	})
	return changed && err == nil, err
}

func retireJobs(tx *sql.Tx, procedure string, valid map[string]struct{}) error {
	keys, err := queryAll(tx, scanString, "SELECT key FROM jobs WHERE procedure=?", procedure)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, ok := valid[k]; ok {
			continue
		}
		if _, err := tx.Exec("DELETE FROM jobs WHERE procedure=? AND key=?", procedure, k); err != nil {
			return err
		}
	}
	return nil
}

// sweepObservations removes obsolete observations, refreshes affected records and returns their
// kinds.
func sweepObservations(tx *sql.Tx, procedure string, valid map[string]struct{}) (map[string]bool, error) {
	type obsKey struct{ kind, key, job string }
	all, err := queryAll(tx, func(r *sql.Rows) (o obsKey, err error) {
		err = r.Scan(&o.kind, &o.key, &o.job)
		return o, err
	}, "SELECT kind,key,job_key FROM observations WHERE producer=?", procedure)
	if err != nil {
		return nil, err
	}
	kinds := map[string]bool{}
	for _, o := range all {
		if _, ok := valid[o.job]; ok {
			continue
		}
		if _, err := tx.Exec("DELETE FROM observations WHERE kind=? AND key=? AND producer=? AND job_key=?", o.kind, o.key, procedure, o.job); err != nil {
			return nil, err
		}
		if err := refreshCurrent(tx, o.kind, o.key); err != nil {
			return nil, err
		}
		kinds[o.kind] = true
	}
	return kinds, nil
}

// shownSchema stores the output baseline. Opening an older engagement creates this table if
// needed.
const shownSchema = `CREATE TABLE IF NOT EXISTS shown(kind TEXT NOT NULL, key TEXT NOT NULL, producers TEXT NOT NULL,
                  scope TEXT NOT NULL, severity TEXT NOT NULL, PRIMARY KEY(kind, key))`

// shownMeta records the date a baseline was saved, distinguishing an empty baseline from no
// baseline at all.
const shownMeta = "shown_saved"

// ShownRow preserves one previously visible output entry. Kind and Key identify its changes.csv
// row; procedures, scope and severity retain details that non-current records may lose.
type ShownRow struct {
	Kind, Key       string
	Producers       []string
	Scope, Severity string
}

func (r ShownRow) Equal(o ShownRow) bool {
	return r.Kind == o.Kind && r.Key == o.Key && r.Scope == o.Scope && r.Severity == o.Severity && slices.Equal(r.Producers, o.Producers)
}

// SaveShown atomically replaces the baseline. Once a baseline is cached by reading or saving
// it, only changed rows are written. Treat rows as immutable after the call.
func (s *Store) SaveShown(rows []ShownRow) error {
	s.shownMu.Lock()
	defer s.shownMu.Unlock()
	err := s.update(func(tx *sql.Tx) (map[string]bool, error) {
		var old map[shownKey]ShownRow // unknown baseline: replace all rows
		if s.shownKnown {
			old = make(map[shownKey]ShownRow, len(s.shown))
			for _, r := range s.shown {
				old[shownKey{r.Kind, r.Key}] = r
			}
		} else if _, err := tx.Exec("DELETE FROM shown"); err != nil {
			return nil, err
		}
		if err := writeShown(tx, old, rows); err != nil {
			return nil, err
		}
		_, err := tx.Exec(setMetaSQL, shownMeta, s.today())
		return nil, err
	})
	if err != nil {
		s.shown, s.shownKnown = nil, false // force a full rewrite on the next save
		return err
	}
	s.shown, s.shownKnown = rows, true
	return nil
}

type shownKey struct{ kind, key string }

// writeShown inserts or updates changed rows and removes rows absent from the new baseline.
func writeShown(tx *sql.Tx, old map[shownKey]ShownRow, rows []ShownRow) error {
	ins, err := tx.Prepare("INSERT OR REPLACE INTO shown(kind,key,producers,scope,severity) VALUES(?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, r := range rows {
		k := shownKey{r.Kind, r.Key}
		if o, ok := old[k]; ok {
			delete(old, k)
			if o.Equal(r) {
				continue
			}
		}
		if _, err := ins.Exec(r.Kind, r.Key, strings.Join(r.Producers, ","), r.Scope, r.Severity); err != nil {
			return err
		}
	}
	if len(old) == 0 {
		return nil
	}
	del, err := tx.Prepare("DELETE FROM shown WHERE kind=? AND key=?")
	if err != nil {
		return err
	}
	defer del.Close()
	for k := range old {
		if _, err := del.Exec(k.kind, k.key); err != nil {
			return err
		}
	}
	return nil
}

// Shown returns the baseline sorted by kind and key, plus whether one has ever been saved. An
// empty saved baseline differs from an older engagement with no baseline.
func (s *Store) Shown() (rows []ShownRow, saved bool, err error) {
	var day string
	switch err := s.db.QueryRow("SELECT value FROM meta WHERE key=?", shownMeta).Scan(&day); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	rows, err = queryAll(s.db, func(q *sql.Rows) (r ShownRow, err error) {
		var procedures string
		err = q.Scan(&r.Kind, &r.Key, &procedures, &r.Scope, &r.Severity)
		if procedures != "" {
			r.Producers = strings.Split(procedures, ",")
		}
		return r, err
	}, "SELECT kind,key,producers,scope,severity FROM shown ORDER BY kind,key")
	if err != nil {
		return nil, false, err
	}
	// Copy rows so callers cannot change the cached baseline used by SaveShown.
	s.shownMu.Lock()
	s.shown, s.shownKnown = slices.Clone(rows), true
	s.shownMu.Unlock()
	return rows, true, nil
}

// HasRecords includes non-current records. A store without any records has never run.
func (s *Store) HasRecords() (bool, error) {
	var one int
	err := s.db.QueryRow("SELECT 1 FROM records LIMIT 1").Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
