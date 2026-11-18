// Package store is the SQLite-backed engagement state: inputs, completed
// checks, records with per-stage observations, failures and metadata.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
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
CREATE TABLE failures(stage TEXT NOT NULL, key TEXT NOT NULL, error TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(stage, key));
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

// Failure is the last transient failure of a check.
type Failure struct{ Stage, Key, Error, At string }

type opKind int

const (
	opComplete opKind = iota
	opFail
	opBarrier
)

type op struct {
	kind         opKind
	stage, check string
	obs          []Obs
	errMsg       string
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
	s.send(op{kind: opComplete, stage: stage, check: s.CheckKey(check), obs: obs})
}

// Fail queues a record of a transient failure (not a completion).
func (s *Store) Fail(stage, check, errMsg string) {
	s.send(op{kind: opFail, stage: stage, check: s.CheckKey(check), errMsg: s.red.Redact(errMsg)})
}

// Flush waits until everything queued so far is committed and returns the first write error.
func (s *Store) Flush() error {
	done := make(chan error, 1)
	if !s.send(op{kind: opBarrier, done: done}) {
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
		if first.kind != opBarrier {
			timer := time.NewTimer(maxBatchWait)
		collect:
			for len(batch) < maxBatch {
				select {
				case o, ok := <-s.ch:
					if !ok {
						break collect
					}
					batch = append(batch, o)
					if o.kind == opBarrier {
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

type newRec struct {
	kind, key string
	attrs     map[string]any
}

func (s *Store) commit(batch []op) {
	s.commitAndNotify(batch)
	err := s.firstErr()
	for _, o := range batch {
		if o.kind == opBarrier {
			o.done <- err
		}
	}
}

// commitAndNotify commits the batch and calls the new-record callback. A panic
// in either is the store's sticky error, so the barriers are still released
// and Flush returns it instead of waiting for ever.
func (s *Store) commitAndNotify(batch []op) {
	defer func() {
		if v := recover(); v != nil {
			s.setErr(fmt.Errorf("store writer: panic: %v", v))
		}
	}()
	var news []newRec
	if s.firstErr() == nil {
		news = s.commitOps(batch)
	}
	s.mu.Lock()
	cb, err := s.onNew, s.err
	s.mu.Unlock()
	if err == nil && cb != nil {
		for _, n := range news {
			cb(n.kind, n.key, n.attrs)
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

func (s *Store) commitOps(batch []op) []newRec {
	tx, err := s.db.Begin()
	if err != nil {
		s.setErr(err)
		return nil
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	today := s.today()
	var news []newRec
	kinds := map[string]bool{}
	wrote := false
	for _, o := range batch {
		switch o.kind {
		case opComplete:
			n, err := s.applyComplete(tx, o, today, kinds)
			if err != nil {
				s.setErr(err)
				return nil
			}
			news = append(news, n...)
			wrote = true
		case opFail:
			if _, err := tx.Exec(`INSERT INTO failures(stage,key,error,at) VALUES(?,?,?,?)
				ON CONFLICT(stage,key) DO UPDATE SET error=excluded.error, at=excluded.at`, o.stage, o.check, o.errMsg, today); err != nil {
				s.setErr(err)
				return nil
			}
			wrote = true
		}
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
func (s *Store) applyComplete(tx *sql.Tx, o op, today string, kinds map[string]bool) ([]newRec, error) {
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
	var news []newRec
	touched := map[rk]bool{}
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
		var one int
		err = tx.QueryRow("SELECT 1 FROM records WHERE kind=? AND key=?", k.kind, k.key).Scan(&one)
		switch err {
		case sql.ErrNoRows:
			news = append(news, newRec{k.kind, k.key, attrs})
			_, err = tx.Exec("INSERT INTO records(kind,key,first_seen,last_seen,current) VALUES(?,?,?,?,1)", k.kind, k.key, today, today)
		case nil:
			_, err = tx.Exec("UPDATE records SET last_seen=? WHERE kind=? AND key=?", today, k.kind, k.key)
		}
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`INSERT INTO observations(kind,key,stage,check_key,attrs,seen) VALUES(?,?,?,?,?,?)
			ON CONFLICT(kind,key,stage,check_key) DO UPDATE SET attrs=excluded.attrs, seen=excluded.seen`,
			k.kind, k.key, o.stage, o.check, string(blob), today); err != nil {
			return nil, err
		}
		touched[k] = true
	}
	// Drop this check's observations that it no longer produces.
	rows, err := tx.Query("SELECT kind,key FROM observations WHERE stage=? AND check_key=?", o.stage, o.check)
	if err != nil {
		return nil, err
	}
	var stale []rk
	for rows.Next() {
		var k rk
		if err := rows.Scan(&k.kind, &k.key); err != nil {
			rows.Close()
			return nil, err
		}
		if _, ok := seen[k]; !ok {
			stale = append(stale, k)
		}
	}
	rows.Close()
	for _, k := range stale {
		if _, err := tx.Exec("DELETE FROM observations WHERE kind=? AND key=? AND stage=? AND check_key=?", k.kind, k.key, o.stage, o.check); err != nil {
			return nil, err
		}
		touched[k] = true
	}
	for k := range touched {
		if err := refreshCurrent(tx, k.kind, k.key); err != nil {
			return nil, err
		}
		kinds[k.kind] = true
	}
	if _, err := tx.Exec("INSERT OR REPLACE INTO checks(stage,key,completed_at) VALUES(?,?,?)", o.stage, o.check, today); err != nil {
		return nil, err
	}
	_, err = tx.Exec("DELETE FROM failures WHERE stage=? AND key=?", o.stage, o.check)
	return news, err
}

func refreshCurrent(tx *sql.Tx, kind, key string) error {
	_, err := tx.Exec(`UPDATE records SET current = EXISTS(SELECT 1 FROM observations o WHERE o.kind=records.kind AND o.key=records.key)
		WHERE kind=? AND key=?`, kind, key)
	return err
}

// Completed returns the keys of the completed checks of a stage, as CheckKey stores them.
func (s *Store) Completed(stage string) (map[string]struct{}, error) {
	rows, err := s.db.Query("SELECT key FROM checks WHERE stage=?", stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = struct{}{}
	}
	return out, rows.Err()
}

// CompletedCount is the number of completed checks of a stage.
func (s *Store) CompletedCount(stage string) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT count(*) FROM checks WHERE stage=?", stage).Scan(&n)
	return n, err
}

// Failures lists the last failure of each failed check of a stage.
func (s *Store) Failures(stage string) ([]Failure, error) {
	rows, err := s.db.Query("SELECT stage,key,error,at FROM failures WHERE stage=? ORDER BY key", stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Failure
	for rows.Next() {
		var f Failure
		if err := rows.Scan(&f.Stage, &f.Key, &f.Error, &f.At); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// querier is what a Reader reads through: the database or one transaction of it.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
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
	rows, err := rd.q.Query("SELECT key,first_seen,last_seen,current FROM records WHERE kind=? ORDER BY key", kind)
	if err != nil {
		return nil, err
	}
	var recs []Record
	idx := map[string]int{}
	for rows.Next() {
		r := Record{Kind: kind, Attrs: map[string]any{}}
		var cur int
		if err := rows.Scan(&r.Key, &r.FirstSeen, &r.LastSeen, &cur); err != nil {
			rows.Close()
			return nil, err
		}
		r.Current = cur == 1
		idx[r.Key] = len(recs)
		recs = append(recs, r)
	}
	rows.Close()

	type ob struct {
		key, stage, check string
		attrs             map[string]any
	}
	orows, err := rd.q.Query("SELECT key,stage,check_key,attrs FROM observations WHERE kind=?", kind)
	if err != nil {
		return nil, err
	}
	defer orows.Close()
	var obs []ob
	for orows.Next() {
		var o ob
		var blob string
		if err := orows.Scan(&o.key, &o.stage, &o.check, &blob); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(blob), &o.attrs)
		obs = append(obs, o)
	}
	sort.Slice(obs, func(i, j int) bool {
		if ri, rj := rank[obs[i].stage], rank[obs[j].stage]; ri != rj {
			return ri < rj
		}
		if obs[i].stage != obs[j].stage {
			return obs[i].stage < obs[j].stage
		}
		return obs[i].check < obs[j].check
	})
	stages := map[string]map[string]bool{}
	for _, o := range obs {
		i, ok := idx[o.key]
		if !ok {
			continue
		}
		for k, v := range o.attrs {
			recs[i].Attrs[k] = v
		}
		if stages[o.key] == nil {
			stages[o.key] = map[string]bool{}
		}
		stages[o.key][o.stage] = true
	}
	for k, set := range stages {
		for st := range set {
			recs[idx[k]].Stages = append(recs[idx[k]].Stages, st)
		}
		sort.Strings(recs[idx[k]].Stages)
	}
	return recs, nil
}

// Observations lists the observations of a kind made by a stage.
func (s *Store) Observations(kind, stage string) ([]ObsRow, error) {
	return Reader{s.db}.Observations(kind, stage)
}

// Observations lists the observations of a kind made by a stage.
func (rd Reader) Observations(kind, stage string) ([]ObsRow, error) {
	rows, err := rd.q.Query("SELECT key,check_key FROM observations WHERE kind=? AND stage=? ORDER BY key,check_key", kind, stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ObsRow
	for rows.Next() {
		var r ObsRow
		if err := rows.Scan(&r.Key, &r.CheckKey); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Observer is a completed check that observes a record.
type Observer struct{ Stage, CheckKey string }

// Observers lists, per record key, the completed checks that observe a record
// of the kind now, by stage and then check key. An observation whose check is
// not completed (a redo has forgotten it, and its stale observation awaits the
// check running again) does not count: the support is what a check found, not
// what an earlier run left behind.
func (s *Store) Observers(kind string) (map[string][]Observer, error) {
	rows, err := s.db.Query(`SELECT o.key, o.stage, o.check_key FROM observations o
		JOIN checks c ON c.stage = o.stage AND c.key = o.check_key
		WHERE o.kind = ? ORDER BY o.key, o.stage, o.check_key`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Observer{}
	for rows.Next() {
		var key string
		var o Observer
		if err := rows.Scan(&key, &o.Stage, &o.CheckKey); err != nil {
			return nil, err
		}
		out[key] = append(out[key], o)
	}
	return out, rows.Err()
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

// AddInput stores an input if it is new and reports whether it was added.
func (s *Store) AddInput(kind, value string) (bool, error) {
	res, err := s.db.Exec("INSERT OR IGNORE INTO inputs(kind,value,added_at) VALUES(?,?,?)", kind, value, s.today())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Inputs lists the stored inputs ordered by kind then value.
func (s *Store) Inputs() ([]Input, error) { return Reader{s.db}.Inputs() }

// Inputs lists the stored inputs ordered by kind then value.
func (rd Reader) Inputs() ([]Input, error) {
	rows, err := rd.q.Query("SELECT kind,value,added_at FROM inputs ORDER BY kind,value")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Input
	for rows.Next() {
		var in Input
		if err := rows.Scan(&in.Kind, &in.Value, &in.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// Redo forgets every completed check of a stage and marks the redo as pending.
// The records its observations belong to keep them until the checks run again,
// but they no longer count in Observers, so the version of each such kind moves.
func (s *Store) Redo(stage string) error {
	return s.update(func(tx *sql.Tx) (map[string]bool, error) {
		if _, err := tx.Exec("DELETE FROM checks WHERE stage=?", stage); err != nil {
			return nil, err
		}
		rows, err := tx.Query("SELECT DISTINCT kind FROM observations WHERE stage=?", stage)
		if err != nil {
			return nil, err
		}
		kinds := map[string]bool{}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return nil, err
			}
			kinds[k] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
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
	rows, err := s.db.Query("SELECT key FROM meta WHERE key LIKE 'redo:%' ORDER BY key")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, strings.TrimPrefix(k, "redo:"))
	}
	return out, rows.Err()
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
// CheckKey form of every check the stage yields now), with their observations
// and failures. Evidence from a superseded check, one whose key carries a hash
// of an entry that has since changed, so stops being current, and a check
// yielded again later is run again. valid must be the stage's complete set of
// checks. It reports whether the sweep changed any record.
func (s *Store) Retire(stage string, valid map[string]struct{}) (changed bool, err error) {
	err = s.update(func(tx *sql.Tx) (map[string]bool, error) {
		kinds, err := sweepObservations(tx, stage, valid)
		if err != nil {
			return nil, err
		}
		for _, table := range []string{"checks", "failures"} {
			if err := retireKeys(tx, table, stage, valid); err != nil {
				return nil, err
			}
		}
		changed = len(kinds) > 0
		return kinds, nil
	})
	return changed && err == nil, err
}

// retireKeys deletes the stage's rows of table whose key is not in valid.
func retireKeys(tx *sql.Tx, table, stage string, valid map[string]struct{}) error {
	rows, err := tx.Query("SELECT key FROM "+table+" WHERE stage=?", stage)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		if _, ok := valid[k]; !ok {
			gone = append(gone, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range gone {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE stage=? AND key=?", stage, k); err != nil {
			return err
		}
	}
	return nil
}

// sweepObservations deletes the stage's observations whose check is not in
// valid, refreshes the records they belonged to and returns their kinds.
func sweepObservations(tx *sql.Tx, stage string, valid map[string]struct{}) (map[string]bool, error) {
	rows, err := tx.Query("SELECT kind,key,check_key FROM observations WHERE stage=?", stage)
	if err != nil {
		return nil, err
	}
	type orphan struct{ kind, key, check string }
	var orphans []orphan
	for rows.Next() {
		var o orphan
		if err := rows.Scan(&o.kind, &o.key, &o.check); err != nil {
			rows.Close()
			return nil, err
		}
		if _, ok := valid[o.check]; !ok {
			orphans = append(orphans, o)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kinds := map[string]bool{}
	for _, o := range orphans {
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

// SaveShown replaces the baseline with rows, in one transaction.
func (s *Store) SaveShown(rows []ShownRow) error {
	return s.update(func(tx *sql.Tx) (map[string]bool, error) {
		if _, err := tx.Exec("DELETE FROM shown"); err != nil {
			return nil, err
		}
		ins, err := tx.Prepare("INSERT OR REPLACE INTO shown(kind,key,stages,scope,severity) VALUES(?,?,?,?,?)")
		if err != nil {
			return nil, err
		}
		defer ins.Close()
		for _, r := range rows {
			if _, err := ins.Exec(r.Kind, r.Key, strings.Join(r.Stages, ","), r.Scope, r.Severity); err != nil {
				return nil, err
			}
		}
		_, err = tx.Exec(setMetaSQL, shownMeta, s.today())
		return nil, err
	})
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
	q, err := s.db.Query("SELECT kind,key,stages,scope,severity FROM shown ORDER BY kind,key")
	if err != nil {
		return nil, false, err
	}
	defer q.Close()
	for q.Next() {
		var r ShownRow
		var stages string
		if err := q.Scan(&r.Kind, &r.Key, &stages, &r.Scope, &r.Severity); err != nil {
			return nil, false, err
		}
		if stages != "" {
			r.Stages = strings.Split(stages, ",")
		}
		rows = append(rows, r)
	}
	return rows, true, q.Err()
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
