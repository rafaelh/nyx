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

// StoreOptions supplies the config path and supported fields.
type StoreOptions struct {
	// Path is the config file.
	Path string
	// Env supplies HOME for tilde expansion during validation.
	Env config.Env
	// Sources and Procedures provide setup tab metadata through Info.
	Sources    []setup.Source
	Procedures []setup.Procedure
	// SkipEntry returns recon's reason for an invalid/unskippable procedure, or "" when
	// accepted.
	SkipEntry func(name string) string
	// Getwd resolves relative edits from setup's working directory; nil uses os.Getwd.
	Getwd func() (string, error)
	// NoFsync and Rename are SaveOptions, for tests.
	NoFsync bool
	Rename  func(oldpath, newpath string) error
}

// Store implements setup's file backend, excluding key tests. It rereads before saving to
// detect external edits.
type Store struct {
	o    StoreOptions
	path string // absolute
	env  config.Env
	last []byte // last document used to validate proposed edits
}

// NewStore expects single-goroutine access, matching setup.Backend.
func NewStore(o StoreOptions) *Store {
	path := o.Path
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return &Store{o: o, path: path, env: o.Env}
}

// Info returns the absolute config path and tab metadata.
func (s *Store) Info() setup.Info {
	return setup.Info{Path: s.path, Sources: s.o.Sources, Procedures: s.o.Procedures}
}

// fileToken records original bytes or absence for conflict detection.
type fileToken struct {
	absent bool
	data   string
}

const (
	// unreadMessage flags values whose loader interpretation differs from their apparent
	// YAML text, such as merged anchors.
	unreadMessage = "the file's entry for this is not read as it is written (check how it is spelled in the file); edit or clear it"
	// relativeNote introduces working-directory path resolution guidance.
	relativeNote = "Relative: resolves against the directory nyx runs from"
)

// read distinguishes file bytes from absence, including dangling symlinks.
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

// Open returns defaults for a missing file. Read, parse and unknown-key failures become
// setup.FileError with the same validation problems as recon.
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

// snapshot converts file bytes into setup's displayed state.
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

// fatal identifies whole-file problems that prevent editing.
func fatal(probs clierr.Problems) bool {
	return slices.ContainsFunc(probs, func(p clierr.Problem) bool { return p.Name == "config" || p.Name == "" })
}

// minRedacted avoids exposing keys in decoding errors. Values shorter than this are not masked
// because they would make error messages unreadable.
const minRedacted = 4

// fileError combines loader and skip-validation problems for an uneditable file.
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

// scalarsUnder searches case-insensitive document blocks for scalar values.
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

// twice explains conflicting case-variant settings.
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

// recordsKey stores per-source test result, date and key fingerprint under key_tests.
const recordsKey = "key_tests"

// recordDay is how a record's day is written.
const recordDay = "2006-01-02"

// fingerprint uses the first eight SHA-256 hex digits to associate a key-test record with a key
// without storing the key itself. Manual changes invalidate the match.
func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

// readRecord returns a readable record only when its fingerprint matches the current key.
func readRecord(doc *Doc, source, key string) *setup.KeyRecord {
	// Decode record fields as written text; unquoted YAML dates otherwise become
	// timestamps.
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

// records applies test-result edits and removes known-source records when their keys were
// cleared.
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

// number reproduces the loader's canonical numeric text, rejecting nonnumeric values.
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

// value converts a stored non-key setting to display/edit state.
func (s *Store) value(doc *Doc, settings config.Settings, probs clierr.Problems, key string) setup.Value {
	v := setup.Value{Default: config.DefaultText(key)}
	e := doc.Lookup(key)
	if e.Node != nil && e.Node.Kind == yaml.ScalarNode && e.Node.Tag == "!!null" {
		// Valueless YAML entries use loader defaults.
		e.Node = nil
	}
	text, readable := "", true
	if e.Node != nil {
		v.Set = true
		text, readable = DecodedText(e.Node)
		v.Text = text
	}
	var shown string // normalised YAML text for comparison with loader output
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

// problemFor selects one setting's loader diagnostic, or "".
func problemFor(probs clierr.Problems, key string) string {
	for _, p := range probs {
		if p.Name == key {
			return p.Message
		}
	}
	return ""
}

// relative explains how an unset output_dir or stored relative path resolves from nyx's working
// directory, after tilde expansion.
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

// skipEntries accepts a YAML sequence or comma-separated scalar and normalises it with
// config.SkipNames. Other node types return false.
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

// Check validates an entered non-key setting with recon's rules. It makes relative paths
// absolute from setup's working directory and preserves other valid text.
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
	// Validate only the edited setting instead of loading unrelated list files.
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

// Save applies edits only if the file still matches the snapshot. Conflicts return
// setup.ErrConflict; all errors leave the file unchanged.
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

// Overwrite applies edits to the latest readable document. If the file cannot be read, parsed
// or accepted because of unknown keys, it replaces it with a document containing only the
// edits.
func (s *Store) Overwrite(edits setup.Edits) (setup.Snapshot, error) {
	data, absent, err := s.read()
	if _, serr := s.snapshot(data, absent); err != nil || serr != nil {
		data = nil
	}
	return s.apply(setup.Snapshot{}, data, edits)
}

// apply writes the requested edits, saves the document atomically and reads it back.
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

// edit applies clears, tab-ordered values and the complete skip list in that order.
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
