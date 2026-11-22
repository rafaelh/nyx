// Package store is the SQLite-backed engagement state: inputs, completed
// checks, records with per-stage observations and metadata.
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
CREATE TABLE checks(stage TEXT NOT NULL, key TEXT NOT NULL, completed_at TEXT NOT NULL, PRIMARY KEY(stage, key));
CREATE TABLE records(kind TEXT NOT NULL, key TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                     current INTEGER NOT NULL, PRIMARY KEY(kind, key));
CREATE TABLE observations(kind TEXT NOT NULL, key TEXT NOT NULL, stage TEXT NOT NULL, check_key TEXT NOT NULL,
                          attrs TEXT NOT NULL, seen TEXT NOT NULL, PRIMARY KEY(kind, key, stage, check_key));
CREATE INDEX observations_check ON observations(stage, check_key);
`

// Options configure a Store.
type Options struct {
	Clock    func() time.Time
	Redactor *config.Redactor
}

// Obs is an observation produced by completing a check.
type Obs struct {
	Kind, Key string
	Attrs     map[string]any
}

// Record is a record with its merged attributes.
type Record struct {
	Kind, Key           string
	FirstSeen, LastSeen string
	Current             bool // while at least one completed check still observes it
	Attrs               map[string]any
	Stages              []string // sorted stages currently observing the record
}

// Str returns the string attribute k, or "" if it is absent or not a string.
func (r Record) Str(k string) string { s, _ := r.Attrs[k].(string); return s }

// ObsRow is the record key and check key of one stored observation.
type ObsRow struct{ Key, CheckKey string }

// Input is a stored scope input or exclusion.
type Input struct{ Kind, Value, AddedAt string }

// op is a check's completion, or a barrier when done is set.
type op struct {
	stage, check string
	obs          []Obs
	done         chan error
}

// Store is safe for concurrent use. Writes go through a single writer
// goroutine that commits in batches.
type Store struct {
	db    *sql.DB
	clock func() time.Time
	red   *config.Redactor

	ch chan op
	wg sync.WaitGroup
	// chMu is read-held across every send on ch and write-held by Close, so ch
	// is never closed under a sender. The writer never takes it.
	chMu   sync.RWMutex
	closed bool       // guarded by chMu
	mu     sync.Mutex // guards err, onNew, versions
	err    error
	onNew  func(kind, key string, attrs map[string]any)
	// versions counts the committed transactions that changed records of a kind.
	versions map[string]uint64
	once     sync.Once
	stmts    writeStmts // the writer's statements, prepared once

	// shown is the baseline as the store last read or saved it, when shownKnown (see SaveShown).
	shownMu    sync.Mutex
	shown      []ShownRow
	shownKnown bool
}

// writeStmts are the statements the writer runs for every observation, prepared once when the
// store opens so a commit never parses SQL again.
type writeStmts struct {
	insertRecord, touchRecord, upsertObs, checkObs, deleteObs, refresh, complete *sql.Stmt
}

// writeSQL is the text of each of writeStmts, in field order.
var writeSQL = []string{
	// A record is new exactly when this inserts it; one observed now is current.
	"INSERT INTO records(kind,key,first_seen,last_seen,current) VALUES(?,?,?,?,1) ON CONFLICT(kind,key) DO NOTHING",
	"UPDATE records SET last_seen=?, current=1 WHERE kind=? AND key=?",
	`INSERT INTO observations(kind,key,stage,check_key,attrs,seen) VALUES(?,?,?,?,?,?)
		ON CONFLICT(kind,key,stage,check_key) DO UPDATE SET attrs=excluded.attrs, seen=excluded.seen`,
	"SELECT kind,key FROM observations WHERE stage=? AND check_key=?",
	"DELETE FROM observations WHERE kind=? AND key=? AND stage=? AND check_key=?",
	refreshSQL,
	"INSERT OR REPLACE INTO checks(stage,key,completed_at) VALUES(?,?,?)",
}

// prepare prepares the writer's statements on db.
func (w *writeStmts) prepare(db *sql.DB) error {
	ptrs := []**sql.Stmt{&w.insertRecord, &w.touchRecord, &w.upsertObs, &w.checkObs, &w.deleteObs, &w.refresh, &w.complete}
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
	for _, st := range []*sql.Stmt{w.insertRecord, w.touchRecord, w.upsertObs, w.checkObs, w.deleteObs, w.refresh, w.complete} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// txStmts are writeStmts bound to one transaction.
type txStmts struct {
	insertRecord, touchRecord, upsertObs, checkObs, deleteObs, refresh, complete *sql.Stmt
}

func (w *writeStmts) in(tx *sql.Tx) txStmts {
	return txStmts{tx.Stmt(w.insertRecord), tx.Stmt(w.touchRecord), tx.Stmt(w.upsertObs), tx.Stmt(w.checkObs),
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

// dsn is the database/sql name of the database at path with the query q.
// SQLite decodes %HH in URI filenames, so escaping keeps ?, # and % in path literal.
func dsn(path string, q url.Values) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// ReadOnly is an existing state database opened for reading only. It has no
// writer, so nothing can be written through it.
type ReadOnly struct {
	path string
	db   *sql.DB
	// stamp is the database file's size and modification time when it was
	// opened immutable, and nil when it was opened under WAL.
	stamp *fileStamp
}

type fileStamp struct {
	size int64
	mod  time.Time
}

// OpenReadOnly opens an existing state database for reading: it creates no
// file and never runs the schema. A database that is not nyx's is an error.
// While a run holds the database (it has a write-ahead log) the reads see the
// committed state under WAL. With no log file there is no run, and the
// database is opened immutable, because a read-only WAL connection would
// create -wal and -shm files beside it (see View for a run that starts).
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

// View runs fn with a Reader over a single read transaction, so everything fn
// reads is one consistent snapshot, whatever a run commits meanwhile. A
// database opened immutable takes no lock, so a run that starts while fn reads
// could checkpoint into the file under it: when the file changed or a log
// appeared, View opens the database again and calls fn again. fn must
// therefore start afresh on each call.
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

// moved reports whether a database opened immutable may have changed since:
// a run has a log beside it, or the file is not as it was opened.
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

// checkDB reports whether db is a nyx state database this version reads.
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

// checkIDs reports whether an application id and schema version are those of
// a nyx state database this version reads.
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

// OnNew registers a callback invoked (from the writer goroutine, after commit)
// for each record seen for the first time.
func (s *Store) OnNew(fn func(kind, key string, attrs map[string]any)) {
	s.mu.Lock()
	s.onNew = fn
	s.mu.Unlock()
}

// send queues o unless the store is closed, and reports whether it did.
func (s *Store) send(o op) bool {
	s.chMu.RLock()
	defer s.chMu.RUnlock()
	if s.closed {
		return false
	}
	s.ch <- o
	return true
}

// CheckKey is the form in which a check key is stored (redacted). Compare
// keys from Completed, and pass keys to FinishRedo, in this form.
func (s *Store) CheckKey(check string) string { return s.red.Redact(check) }

// Complete queues the completion of a check with its observations.
func (s *Store) Complete(stage, check string, obs []Obs) {
	s.send(op{stage: stage, check: s.CheckKey(check), obs: obs})
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

// commit commits the batch, calls the new-record callback and then releases
// the batch's barriers. A panic in the commit or the callback is the store's
// sticky error, so the barriers are still released and Flush returns it
// instead of waiting for ever.
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

// KindVersion changes whenever a committed write adds, updates or drops an
// observation of kind, so a caller can cache what it derives from the kind's
// records. Call it after Flush to see the writes made so far.
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
	fault.Point("in-check-tx")
	if err := tx.Commit(); err != nil {
		s.setErr(err)
		return nil
	}
	s.bump(kinds)
	fault.Point("after-commit")
	return news
}

// applyComplete adds the kind of every record it touches to kinds.
func (s *Store) applyComplete(st txStmts, o op, today string, kinds map[string]bool) ([]Obs, error) {
	// Later observations of the same record in one check win.
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
		// The record holds an observation once this commits, so it is current.
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
		if _, err := st.upsertObs.Exec(k.kind, k.key, o.stage, o.check, string(blob), today); err != nil {
			return nil, err
		}
		kinds[k.kind] = true
	}
	// Drop this check's observations that it no longer produces, and refresh the records that
	// lost one: another check may still observe them.
	rows, err := st.checkObs.Query(o.stage, o.check)
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
		if _, err := st.deleteObs.Exec(k.kind, k.key, o.stage, o.check); err != nil {
			return nil, err
		}
		if _, err := st.refresh.Exec(k.kind, k.key); err != nil {
			return nil, err
		}
		kinds[k.kind] = true
	}
	_, err = st.complete.Exec(o.stage, o.check, today)
	return news, err
}

// refreshSQL sets a record current exactly when an observation of it is stored.
const refreshSQL = `UPDATE records SET current = EXISTS(SELECT 1 FROM observations o WHERE o.kind=records.kind AND o.key=records.key)
		WHERE kind=? AND key=?`

func refreshCurrent(tx *sql.Tx, kind, key string) error {
	_, err := tx.Exec(refreshSQL, kind, key)
	return err
}

// Completed returns the keys of the completed checks of a stage, as CheckKey stores them.
func (s *Store) Completed(stage string) (map[string]struct{}, error) {
	keys, err := queryAll(s.db, scanString, "SELECT key FROM checks WHERE stage=?", stage)
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out, err
}

// querier is what a Reader reads through: the database or one transaction of it.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// queryAll runs query through q and returns its rows, each read by scan.
func queryAll[T any](q querier, scan func(*sql.Rows) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.Query(query, args...)
	return scanAll(rows, err, scan)
}

// scanAll reads the rows of a query that returned rows and err, each read by scan.
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

// scanString reads a row of one string column.
func scanString(r *sql.Rows) (s string, err error) {
	err = r.Scan(&s)
	return s, err
}

// Reader reads the records, inputs and observations of one view of the
// database: all of the store's committed state at the time of each call
// (Store.Records and the others), or the one snapshot of a ReadOnly.View.
type Reader struct{ q querier }

// Records returns every record of a kind (current or not). Attrs merge the
// current observations with stages later in order winning per field; stages
// not in order sort first.
func (s *Store) Records(kind string, order []string) ([]Record, error) {
	return Reader{s.db}.Records(kind, order)
}

// Records returns every record of a kind (current or not); see Store.Records.
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
		key, stage, check string
		attrs             map[string]any
	}
	obs, err := queryAll(rd.q, func(rows *sql.Rows) (o ob, err error) {
		var blob string
		if err = rows.Scan(&o.key, &o.stage, &o.check, &blob); err == nil {
			_ = json.Unmarshal([]byte(blob), &o.attrs)
		}
		return o, err
	}, "SELECT key,stage,check_key,attrs FROM observations WHERE kind=?", kind)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(obs, func(a, b ob) int {
		return cmp.Or(cmp.Compare(rank[a.stage], rank[b.stage]), cmp.Compare(a.stage, b.stage), cmp.Compare(a.check, b.check))
	})
	for _, o := range obs {
		i, ok := idx[o.key]
		if !ok {
			continue
		}
		maps.Copy(recs[i].Attrs, o.attrs)
		if !slices.Contains(recs[i].Stages, o.stage) {
			recs[i].Stages = append(recs[i].Stages, o.stage)
		}
	}
	for i := range recs {
		slices.Sort(recs[i].Stages)
	}
	return recs, nil
}

// Observations lists the observations of a kind made by a stage.
func (s *Store) Observations(kind, stage string) ([]ObsRow, error) {
	return Reader{s.db}.Observations(kind, stage)
}

// Observations lists the observations of a kind made by a stage.
func (rd Reader) Observations(kind, stage string) ([]ObsRow, error) {
	return queryAll(rd.q, func(rows *sql.Rows) (r ObsRow, err error) {
		err = rows.Scan(&r.Key, &r.CheckKey)
		return r, err
	}, "SELECT key,check_key FROM observations WHERE kind=? AND stage=? ORDER BY key,check_key", kind, stage)
}

// Observer is a completed check that observes a record.
type Observer struct{ Stage, CheckKey string }

// Observers lists, per record key, the completed checks that observe a record
// of the kind now, by stage and then check key. An observation whose check is
// not completed (a redo has forgotten it, and its stale observation awaits the
// check running again) does not count: the support is what a check found, not
// what an earlier run left behind.
func (s *Store) Observers(kind string) (map[string][]Observer, error) {
	type row struct {
		key string
		o   Observer
	}
	rows, err := queryAll(s.db, func(r *sql.Rows) (w row, err error) {
		err = r.Scan(&w.key, &w.o.Stage, &w.o.CheckKey)
		return w, err
	}, `SELECT o.key, o.stage, o.check_key FROM observations o
		JOIN checks c ON c.stage = o.stage AND c.key = o.check_key
		WHERE o.kind = ? ORDER BY o.key, o.stage, o.check_key`, kind)
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

// Redo forgets every completed check of a stage and marks the redo as pending.
// The records its observations belong to keep them until the checks run again,
// but they no longer count in Observers, so the version of each such kind moves.
func (s *Store) Redo(stage string) error {
	return s.update(func(tx *sql.Tx) (map[string]bool, error) {
		if _, err := tx.Exec("DELETE FROM checks WHERE stage=?", stage); err != nil {
			return nil, err
		}
		names, err := queryAll(tx, scanString, "SELECT DISTINCT kind FROM observations WHERE stage=?", stage)
		if err != nil {
			return nil, err
		}
		kinds := map[string]bool{}
		for _, k := range names {
			kinds[k] = true
		}
		_, err = tx.Exec(setMetaSQL, "redo:"+stage, s.today())
		return kinds, err
	})
}

// update flushes the queued writes, runs fn in a transaction and, once it
// commits, bumps the version of every kind fn reports changing.
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

// PendingRedo lists stages whose redo has not finished.
func (s *Store) PendingRedo() ([]string, error) {
	keys, err := queryAll(s.db, scanString, "SELECT key FROM meta WHERE key LIKE 'redo:%' ORDER BY key")
	for i, k := range keys {
		keys[i] = strings.TrimPrefix(k, "redo:")
	}
	return keys, err
}

// FinishRedo sweeps the stage's observations whose check is no longer
// produced (valid holds the CheckKey form of the keys it still produces) and
// clears the marker. valid must be the stage's complete set of checks. It
// reports whether the sweep changed any record.
func (s *Store) FinishRedo(stage string, valid map[string]struct{}) (changed bool, err error) {
	err = s.update(func(tx *sql.Tx) (map[string]bool, error) {
		kinds, err := sweepObservations(tx, stage, valid)
		if err != nil {
			return nil, err
		}
		changed = len(kinds) > 0
		_, err = tx.Exec("DELETE FROM meta WHERE key=?", "redo:"+stage)
		return kinds, err
	})
	return changed && err == nil, err
}

// Retire forgets the completed checks of a stage that are not in valid (the
// CheckKey form of every check the stage yields now), with their observations. Evidence from a superseded check, one whose key carries a hash
// of an entry that has since changed, so stops being current, and a check
// yielded again later is run again. valid must be the stage's complete set of
// checks. It reports whether the sweep changed any record.
func (s *Store) Retire(stage string, valid map[string]struct{}) (changed bool, err error) {
	err = s.update(func(tx *sql.Tx) (map[string]bool, error) {
		kinds, err := sweepObservations(tx, stage, valid)
		if err != nil {
			return nil, err
		}
		if err := retireChecks(tx, stage, valid); err != nil {
			return nil, err
		}
		changed = len(kinds) > 0
		return kinds, nil
	})
	return changed && err == nil, err
}

// retireChecks deletes the stage's completed checks whose key is not in valid.
func retireChecks(tx *sql.Tx, stage string, valid map[string]struct{}) error {
	keys, err := queryAll(tx, scanString, "SELECT key FROM checks WHERE stage=?", stage)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, ok := valid[k]; ok {
			continue
		}
		if _, err := tx.Exec("DELETE FROM checks WHERE stage=? AND key=?", stage, k); err != nil {
			return err
		}
	}
	return nil
}

// sweepObservations deletes the stage's observations whose check is not in
// valid, refreshes the records they belonged to and returns their kinds.
func sweepObservations(tx *sql.Tx, stage string, valid map[string]struct{}) (map[string]bool, error) {
	type obsKey struct{ kind, key, check string }
	all, err := queryAll(tx, func(r *sql.Rows) (o obsKey, err error) {
		err = r.Scan(&o.kind, &o.key, &o.check)
		return o, err
	}, "SELECT kind,key,check_key FROM observations WHERE stage=?", stage)
	if err != nil {
		return nil, err
	}
	kinds := map[string]bool{}
	for _, o := range all {
		if _, ok := valid[o.check]; ok {
			continue
		}
		if _, err := tx.Exec("DELETE FROM observations WHERE kind=? AND key=? AND stage=? AND check_key=?", o.kind, o.key, stage, o.check); err != nil {
			return nil, err
		}
		if err := refreshCurrent(tx, o.kind, o.key); err != nil {
			return nil, err
		}
		kinds[o.kind] = true
	}
	return kinds, nil
}

// shownSchema is the table of the baseline a run compares against (see
// SaveShown). It is created when missing, so an engagement an earlier nyx wrote
// gains it when it is opened.
const shownSchema = `CREATE TABLE IF NOT EXISTS shown(kind TEXT NOT NULL, key TEXT NOT NULL, stages TEXT NOT NULL,
                  scope TEXT NOT NULL, severity TEXT NOT NULL, PRIMARY KEY(kind, key))`

// shownMeta is the meta key that says a baseline was saved (its value is the day).
// A table with no rows is a baseline of nothing shown only while it is set.
const shownMeta = "shown_saved"

// ShownRow is one entry of the baseline a run compares against: something the
// output files showed at the last render, under the label (Kind) and Key the
// changes file lists it by, with the stages that observed it and the Scope and
// Severity it had, which the store cannot give back once a record is no longer
// current.
type ShownRow struct {
	Kind, Key       string
	Stages          []string
	Scope, Severity string
}

// Equal reports whether two rows hold the same values.
func (r ShownRow) Equal(o ShownRow) bool {
	return r.Kind == o.Kind && r.Key == o.Key && r.Scope == o.Scope && r.Severity == o.Severity && slices.Equal(r.Stages, o.Stages)
}

// SaveShown replaces the baseline with rows, in one transaction. Once the store has read the
// baseline (Shown) or saved one, it writes only the rows that differ from that one; rows must not
// be modified after the call.
func (s *Store) SaveShown(rows []ShownRow) error {
	s.shownMu.Lock()
	defer s.shownMu.Unlock()
	err := s.update(func(tx *sql.Tx) (map[string]bool, error) {
		var old map[shownKey]ShownRow // nil: the stored rows are not known, so all are replaced
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
		s.shown, s.shownKnown = nil, false // the next save rewrites the table
		return err
	}
	s.shown, s.shownKnown = rows, true
	return nil
}

type shownKey struct{ kind, key string }

// writeShown makes the shown table, which holds old, hold rows: it writes each row that is new or
// differs from old's, and deletes old's rows that rows lacks.
func writeShown(tx *sql.Tx, old map[shownKey]ShownRow, rows []ShownRow) error {
	ins, err := tx.Prepare("INSERT OR REPLACE INTO shown(kind,key,stages,scope,severity) VALUES(?,?,?,?,?)")
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
		if _, err := ins.Exec(r.Kind, r.Key, strings.Join(r.Stages, ","), r.Scope, r.Severity); err != nil {
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

// Shown returns the baseline, ordered by kind then key, and whether one was ever
// saved: an engagement last written by a nyx that kept none has no baseline,
// which is not the same as a baseline of nothing shown.
func (s *Store) Shown() (rows []ShownRow, saved bool, err error) {
	var day string
	switch err := s.db.QueryRow("SELECT value FROM meta WHERE key=?", shownMeta).Scan(&day); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	rows, err = queryAll(s.db, func(q *sql.Rows) (r ShownRow, err error) {
		var stages string
		err = q.Scan(&r.Kind, &r.Key, &stages, &r.Scope, &r.Severity)
		if stages != "" {
			r.Stages = strings.Split(stages, ",")
		}
		return r, err
	}, "SELECT kind,key,stages,scope,severity FROM shown ORDER BY kind,key")
	if err != nil {
		return nil, false, err
	}
	// A copy, so a caller that changes the rows it was given cannot change what SaveShown
	// compares with.
	s.shownMu.Lock()
	s.shown, s.shownKnown = slices.Clone(rows), true
	s.shownMu.Unlock()
	return rows, true, nil
}

// HasRecords reports whether the store holds a record of any kind, current or
// not: an engagement with none has not been run.
func (s *Store) HasRecords() (bool, error) {
	var one int
	err := s.db.QueryRow("SELECT 1 FROM records LIMIT 1").Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
