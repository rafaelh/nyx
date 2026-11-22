package configedit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/setup"
)

// StoreOptions say which file a Store edits and what it may hold.
type StoreOptions struct {
	// Path is the config file.
	Path string
	// Env is the environment the file is checked in. Only HOME (for "~") is read from it: the NYX_*
	// variables and NVD_API_KEY are dropped, so what the file says is what is shown.
	Env config.Env
	// Sources and Stages are what the setup tabs list, handed back by Info.
	Sources []setup.Source
	Stages  []setup.Stage
	// SkipEntry is nyx recon's check of one skip entry: "" when the stage can be skipped, else its
	// message.
	SkipEntry func(name string) string
	// Getwd is the directory setup runs from, which a relative path is made absolute against. nil
	// means os.Getwd.
	Getwd func() (string, error)
	// NoFsync and Rename are SaveOptions, for tests.
	NoFsync bool
	Rename  func(oldpath, newpath string) error
}

// Store is a setup.Backend over one config file, except for testing a key. It re-reads the file
// whenever it is asked to save, so a change made behind its back is found.
type Store struct {
	o    StoreOptions
	path string // absolute
	env  config.Env
	last []byte // the file as last read or written: what Check puts a value into
}

// NewStore returns the Store for o. Like setup.Backend, its methods are called from one goroutine.
func NewStore(o StoreOptions) *Store {
	path := o.Path
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return &Store{o: o, path: path, env: config.FileOnlyEnv(o.Env)}
}

// Info is the config file's absolute path and what the setup tabs list.
func (s *Store) Info() setup.Info {
	return setup.Info{Path: s.path, Sources: s.o.Sources, Stages: s.o.Stages}
}

// fileToken is what a snapshot remembers of the file it was read from: its bytes, or that it was
// not there.
type fileToken struct {
	absent bool
	data   string
}

const (
	// unreadMessage marks a setting whose entry the loader reads as something other than what the
	// file seems to say, for example one merged from an anchor.
	unreadMessage = "the file's entry for this is not read as it is written (check how it is spelled in the file); edit or clear it"
	// relativeNote begins the line shown beside a path that resolves against the working directory.
	relativeNote = "Relative: resolves against the directory nyx runs from"
)

// read is the file's bytes, or absent when there is none (a link to nowhere included).
func (s *Store) read() (data []byte, absent bool, err error) {
	data, err = os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, true, nil
	}
	return data, false, err
}

func (s *Store) getwd() (string, error) {
	if s.o.Getwd != nil {
		return s.o.Getwd()
	}
	return os.Getwd()
}

// Open reads the file. A missing one is the defaults. A file that cannot be read or parsed, or
// holds an unknown key, is a *setup.FileError with every problem nyx recon would report for it.
func (s *Store) Open() (setup.Snapshot, error) {
	data, absent, err := s.read()
	if err != nil {
		return setup.Snapshot{}, &setup.FileError{Path: s.path, Problems: []string{config.FileReadMessage(s.path, err)}}
	}
	snap, err := s.snapshot(data, absent)
	if err == nil {
		s.last = data
	}
	return snap, err
}

// snapshot is the file's bytes as the setup tabs show them.
func (s *Store) snapshot(data []byte, absent bool) (setup.Snapshot, error) {
	snap := setup.Snapshot{
		Token:    fileToken{absent: absent, data: string(data)},
		Keys:     map[string]setup.KeyState{},
		Settings: map[string]setup.Value{},
	}
	if absent {
		data = nil
	}
	settings, cerr := config.Check(data, s.path, s.env)
	var probs clierr.Problems
	if cerr != nil {
		if p, ok := errors.AsType[clierr.Problems](cerr); ok {
			probs = p
		} else {
			probs = clierr.Problems{{Name: "config", Message: cerr.Error()}}
		}
	}
	doc, perr := Parse(data)
	if perr != nil && !fatal(probs) {
		probs = append(probs, clierr.Problem{Name: "config", Message: config.FileReadMessage(s.path, perr)})
	}
	if fatal(probs) {
		return setup.Snapshot{}, s.fileError(probs, doc, settings)
	}
	for _, src := range s.o.Sources {
		snap.Keys[src.Name] = s.keyState(doc, settings, src.Name)
	}
	for _, key := range setup.SettingKeys {
		snap.Settings[key] = s.value(doc, settings, probs, key)
	}
	s.skip(&snap, doc, settings, probs)
	return snap, nil
}

// fatal reports whether the problems stop the file being edited: one that is not about a setting.
func fatal(probs clierr.Problems) bool {
	return slices.ContainsFunc(probs, func(p clierr.Problem) bool { return p.Name == "config" || p.Name == "" })
}

// minRedacted is the shortest key value hidden from a decoding error: the loader's message holds
// the value it could not decode, which may be a key, and a shorter one would mangle the message.
const minRedacted = 4

// fileError is the whole problem set of a file that cannot be edited: what the loader reports, then
// what the skip list adds.
func (s *Store) fileError(probs clierr.Problems, doc *Doc, settings config.Settings) *setup.FileError {
	var secrets []string
	for _, v := range settings.Keys {
		secrets = append(secrets, v.Reveal())
	}
	if doc != nil {
		secrets = append(secrets, scalarsUnder(doc, "keys")...)
	}
	secrets = slices.DeleteFunc(secrets, func(v string) bool { return len(v) < minRedacted })
	red := config.NewRedactor(secrets...)
	fe := &setup.FileError{Path: s.path}
	for _, p := range probs {
		fe.Problems = append(fe.Problems, red.Redact(p.Message))
	}
	if doc != nil {
		if entries, ok := skipEntries(doc.Lookup("skip").Node); ok {
			for _, e := range entries {
				if msg := s.skipEntry(e); msg != "" {
					fe.Problems = append(fe.Problems, msg)
				}
			}
		}
	}
	return fe
}

// scalarsUnder is every scalar in the blocks of the document named name, in any case.
func scalarsUnder(d *Doc, name string) []string {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	for _, i := range find(d.root, name) {
		walk(d.root.Content[i+1])
	}
	return out
}

func (s *Store) skipEntry(name string) string {
	if s.o.SkipEntry == nil {
		return ""
	}
	return s.o.SkipEntry(name)
}

// twice is the message for a setting the file spells in more than one case.
func twice(variants []string) string {
	q := make([]string, len(variants))
	for i, v := range variants {
		q[i] = "`" + v + "`"
	}
	list := q[0]
	if n := len(q); n > 1 {
		list = strings.Join(q[:n-1], ", ") + " and " + q[n-1]
	}
	return "set twice in the file, as " + list
}

func (s *Store) keyState(doc *Doc, settings config.Settings, name string) setup.KeyState {
	e := doc.Lookup(setup.KeyPrefix + name)
	var ks setup.KeyState
	text := ""
	if e.Node != nil {
		var ok bool
		text, ok = DecodedText(e.Node)
		ks.Value = config.Secret(text)
		if !ok {
			ks.Problem = unreadMessage
		}
	}
	switch {
	case e.Variants != nil:
		ks.Problem = twice(e.Variants)
	case settings.Keys[name].Reveal() != text:
		ks.Problem = unreadMessage
	}
	if text != "" {
		ks.Record = readRecord(doc, name, text)
	}
	return ks
}

// recordsKey is the block nyx setup records key tests in: key_tests.<source> holds the result, the
// day and the fingerprint of the key it was given for.
const recordsKey = "key_tests"

// recordDay is how a record's day is written.
const recordDay = "2006-01-02"

// fingerprint identifies a key value in its record without holding the key: the first 8 hex digits
// of its SHA-256. A key changed by hand no longer matches its record.
func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

// readRecord is the file's record of source's key, which is key: nil when there is none, it cannot
// be read, or it was made for another key.
func readRecord(doc *Doc, source, key string) *setup.KeyRecord {
	// A field is read as the text it is written as: an unquoted date is a timestamp to YAML.
	field := func(name string) string {
		e := doc.Lookup(recordsKey + "." + source + "." + name)
		n := e.Node
		for n != nil && n.Kind == yaml.AliasNode {
			n = n.Alias
		}
		if e.Variants != nil || n == nil || n.Kind != yaml.ScalarNode {
			return ""
		}
		return strings.TrimSpace(n.Value)
	}
	result := field("result")
	if result != setup.RecordAccepted && result != setup.RecordRejected && result != setup.RecordNotTested {
		return nil
	}
	day, err := time.Parse(recordDay, field("date"))
	if err != nil || field("key") != fingerprint(key) {
		return nil
	}
	return &setup.KeyRecord{Result: result, Day: day}
}

// records writes the records of edits and removes the record of each known source whose key the
// document no longer holds.
func (s *Store) records(doc *Doc, edits setup.Edits) error {
	for _, src := range s.o.Sources {
		at := recordsKey + "." + src.Name
		key := ""
		if e := doc.Lookup(setup.KeyPrefix + src.Name); e.Node != nil {
			key, _ = DecodedText(e.Node)
		}
		rec, ok := edits.Records[src.Name]
		switch {
		case key == "":
			doc.Clear(at)
		case ok:
			for _, f := range [][2]string{
				{"result", rec.Result}, {"date", rec.Day.Format(recordDay)}, {"key", fingerprint(key)},
			} {
				if err := doc.SetString(at+"."+f[0], f[1]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// number reads text as the loader does, giving its canonical form: ok is false when it is not one.
func number(key, text string) (string, bool) {
	text = strings.TrimSpace(text)
	if key == "concurrency" {
		n, err := strconv.Atoi(text)
		return strconv.Itoa(n), err == nil
	}
	f, err := strconv.ParseFloat(text, 64)
	return strconv.FormatFloat(f, 'f', -1, 64), err == nil
}

func isPath(key string) bool {
	return key == "output_dir" || key == "wordlist" || key == "sensitive_paths"
}

// value is how the file holds one non-key setting.
func (s *Store) value(doc *Doc, settings config.Settings, probs clierr.Problems, key string) setup.Value {
	v := setup.Value{Default: config.DefaultText(key)}
	e := doc.Lookup(key)
	if e.Node != nil && e.Node.Kind == yaml.ScalarNode && e.Node.Tag == "!!null" {
		// "concurrency:" with no value: the loader treats it as not set.
		e.Node = nil
	}
	text, readable := "", true
	if e.Node != nil {
		v.Set = true
		text, readable = DecodedText(e.Node)
		v.Text = text
	}
	var shown string // what the file says, in the form the loader's result is compared in
	switch {
	case isPath(key):
		shown = config.ExpandHome(text, s.env)
		if !v.Set && key == "output_dir" {
			shown = config.DefaultText(key)
		}
	case !v.Set:
		shown = v.Default
	default:
		var ok bool
		if shown, ok = number(key, text); ok {
			v.Text = shown
		} else {
			shown = text
		}
	}
	switch msg := problemFor(probs, key); {
	case e.Variants != nil:
		v.Problem = twice(e.Variants)
	case msg != "":
		v.Problem = msg
	case !readable || shown != config.SettingText(settings, key):
		v.Problem = unreadMessage
	}
	if isPath(key) {
		v.Relative = s.relative(shown)
	}
	return v
}

// problemFor is the loader's message for the setting named key, or "".
func problemFor(probs clierr.Problems, key string) string {
	for _, p := range probs {
		if p.Name == key {
			return p.Message
		}
	}
	return ""
}

// relative is the line beside the path p (as value works it out, "~" expanded) when it resolves
// against the directory nyx is run from: the unset output_dir, and a relative path the file holds.
func (s *Store) relative(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return ""
	}
	cwd, err := s.getwd()
	if err != nil {
		return relativeNote
	}
	return relativeNote + ", e.g. " + filepath.Join(cwd, p)
}

// skipEntries reads the node of a skip setting as the loader does: a sequence's items, or one
// scalar split on commas, as config.SkipNames gives them. It is false when the node is neither.
func skipEntries(n *yaml.Node) ([]string, bool) {
	var items []string
	switch {
	case n == nil:
	case n.Kind == yaml.SequenceNode:
		for _, c := range n.Content {
			t, ok := DecodedText(c)
			if !ok {
				return nil, false
			}
			items = append(items, t)
		}
	default:
		t, ok := DecodedText(n)
		if !ok {
			return nil, false
		}
		if t != "" {
			items = strings.Split(t, ",")
		}
	}
	names, _ := config.SkipNames(items)
	return names, true
}

// skip fills the skip list and its problems.
func (s *Store) skip(snap *setup.Snapshot, doc *Doc, settings config.Settings, probs clierr.Problems) {
	e := doc.Lookup(setup.SkipKey)
	names, ok := skipEntries(e.Node)
	for _, name := range names {
		if msg := s.skipEntry(name); msg != "" {
			snap.SkipProblems = append(snap.SkipProblems, setup.SkipProblem{Entry: name, Message: msg})
		} else {
			snap.Skip = append(snap.Skip, name)
		}
	}
	switch msg := problemFor(probs, setup.SkipKey); {
	case e.Variants != nil:
		snap.SkipListProblem = twice(e.Variants)
	case msg != "":
		snap.SkipListProblem = msg
	case !ok || (len(names)+len(settings.Skip) > 0 && !slices.Equal(names, settings.Skip)):
		snap.SkipListProblem = unreadMessage
	}
}

// Check validates one non-key setting as it is entered, with the message nyx recon gives for a
// file that holds it, and returns what to store: a relative path made absolute against the
// directory setup runs from, anything else as given.
func (s *Store) Check(key, value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s: the value is not valid UTF-8", key)
	}
	if strings.HasPrefix(key, setup.KeyPrefix) {
		return value, nil
	}
	stored := value
	if isPath(key) && value != "~" && !strings.HasPrefix(value, "~/") && !filepath.IsAbs(value) {
		cwd, err := s.getwd()
		if err != nil {
			return "", fmt.Errorf("%s: cannot find the working directory: %s", key, config.ErrorText(err))
		}
		stored = filepath.Join(cwd, value)
	}
	doc, err := Parse(s.last)
	if err != nil {
		doc, _ = Parse(nil)
	}
	if err := doc.SetString(key, stored); err != nil {
		return "", err
	}
	// Only key's problem counts, so the lists of the other settings are not read.
	for _, list := range []string{"wordlist", "sensitive_paths"} {
		if list != key {
			doc.Clear(list)
		}
	}
	data, err := doc.Bytes()
	if err != nil {
		return "", fmt.Errorf("%s: %s", key, config.ErrorText(err))
	}
	_, cerr := config.Check(data, s.path, s.env)
	if p, ok := errors.AsType[clierr.Problems](cerr); ok {
		if msg := problemFor(p, key); msg != "" {
			return "", errors.New(msg)
		}
	}
	return stored, nil
}

// Save applies edits to the file the snapshot was read from. When the file differs from the
// snapshot it writes nothing and returns setup.ErrConflict. On any other error the file is
// unchanged.
func (s *Store) Save(snap setup.Snapshot, edits setup.Edits) (setup.Snapshot, error) {
	tok, ok := snap.Token.(fileToken)
	if !ok {
		return snap, setup.ErrConflict
	}
	data, absent, err := s.read()
	if err != nil {
		return snap, &SaveError{Path: s.path, Err: err}
	}
	if (fileToken{absent: absent, data: string(data)}) != tok {
		return snap, setup.ErrConflict
	}
	return s.apply(snap, data, edits)
}

// Overwrite applies edits to the file as it is now, whatever changed since it was read. A file that
// cannot be read, parsed or opened (an unknown key) has nothing left to keep: it is replaced by one
// holding just the edits.
func (s *Store) Overwrite(edits setup.Edits) (setup.Snapshot, error) {
	data, absent, err := s.read()
	if _, serr := s.snapshot(data, absent); err != nil || serr != nil {
		data = nil
	}
	return s.apply(setup.Snapshot{}, data, edits)
}

// apply puts edits into the document of data, saves it and reads the file back.
func (s *Store) apply(prev setup.Snapshot, data []byte, edits setup.Edits) (setup.Snapshot, error) {
	if !edits.Empty() {
		doc, err := Parse(data)
		if err != nil {
			doc, _ = Parse(nil)
		}
		if err := s.edit(doc, edits); err != nil {
			return prev, err
		}
		out, err := doc.Bytes()
		if err != nil {
			return prev, &SaveError{Path: s.path, Err: err}
		}
		if err := Save(s.path, out, SaveOptions{NoFsync: s.o.NoFsync, Rename: s.o.Rename}); err != nil {
			return prev, err
		}
	}
	snap, err := s.Open()
	if err != nil {
		return prev, err
	}
	return snap, nil
}

// edit applies the edits to doc: clears first, then values in the order the tabs list them, then
// the skip list.
func (s *Store) edit(doc *Doc, edits setup.Edits) error {
	for _, key := range edits.Clear {
		doc.Clear(key)
	}
	keys := slices.Sorted(maps.Keys(edits.Set))
	rank := func(key string) int {
		if name, ok := strings.CutPrefix(key, setup.KeyPrefix); ok {
			if i := slices.IndexFunc(s.o.Sources, func(src setup.Source) bool { return src.Name == name }); i >= 0 {
				return i
			}
			return len(s.o.Sources)
		}
		if i := slices.Index(setup.SettingKeys, key); i >= 0 {
			return len(s.o.Sources) + 1 + i
		}
		return len(s.o.Sources) + 1 + len(setup.SettingKeys)
	}
	slices.SortStableFunc(keys, func(a, b string) int { return rank(a) - rank(b) })
	for _, key := range keys {
		if err := doc.SetString(key, edits.Set[key]); err != nil {
			return err
		}
	}
	if edits.Skip != nil {
		if err := doc.SetList(setup.SkipKey, edits.Skip); err != nil {
			return err
		}
	}
	return s.records(doc, edits)
}
