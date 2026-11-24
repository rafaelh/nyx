// Package setup implements the full-screen config editor as a Bubble Tea model. A Backend
// performs file access, validation and key tests; the UI itself does no file or network I/O.
// The CLI wires configedit, config and keycheck into that backend.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/palette"
)

// Settings tab keys in display order. API keys use "keys.<source>" on a separate tab; skip has
// its own tab.
var SettingKeys = []string{"output_dir", "concurrency", "rate.per_host", "rate.per_source", "rate.dns", "wordlist", "sensitive_paths"}

// SkipKey is the setting key of the skip list.
const SkipKey = "skip"

// KeyPrefix starts the key of a key source: "keys.shodan".
const KeyPrefix = "keys."

// Source is one key source the Keys tab lists.
type Source struct {
	Name  string // lower case: "shodan"
	Turns string // one-line explanation of key use, including optional credentials
}

// Stage describes a skippable stage on the Skip tab.
type Stage struct {
	Name string
	Does string // its one-line description, as nyx help stages gives it
}

// Info supplies tab metadata fixed for an editor session.
type Info struct {
	Path    string   // the config file's absolute path, as the header shows it
	Sources []Source // in display order
	Stages  []Stage  // the skippable stages, in registry order
	// ThreatUnavailable explains why updates have no storage directory. The Threat data tab
	// displays it and refuses updates while it is nonempty.
	ThreatUnavailable string
}

// ThreatList describes one active list for the Threat data tab.
type ThreatList struct {
	Source string // "spamhaus" or "ipapi.is"
	List   string // "drop_v4", "drop_v6", "asndrop", "networks" or "asns"
	// Date is preformatted by source: second-precision RFC3339 UTC for Spamhaus and
	// YYYY-MM-DD for ipapi.is.
	Date    string
	Entries int
	// Downloaded selects the active downloaded copy; false means embedded data.
	Downloaded bool
	// Note adds list context, such as falling back to built-in data after an unreadable
	// download.
	Note string
	// Copyright and Terms hold source credit for the tab footer. Only the list carrying
	// that credit, currently Spamhaus drop_v4, sets them.
	Copyright, Terms string
}

// ThreatOutcome is how an update ended for one list.
type ThreatOutcome int

// The ways an update ends for a list.
const (
	// ThreatUpdated is a list replaced by a newer download.
	ThreatUpdated ThreatOutcome = iota
	// ThreatCurrent is a list that was already current.
	ThreatCurrent
	// ThreatSkipped indicates the source's contact cooldown is still active.
	ThreatSkipped
	// ThreatFailed is a list whose source failed.
	ThreatFailed
)

// ThreatListResult is one list after an update.
type ThreatListResult struct {
	// ThreatList describes the active copy after an update.
	ThreatList
	Outcome ThreatOutcome
	// Text describes the update outcome, including current, skipped cooldown or failed
	// reason.
	Text string
}

// ThreatResult holds one threat-data update outcome.
type ThreatResult struct {
	// Lists holds one entry for each list ThreatData gives, in the same order.
	Lists []ThreatListResult
}

// Value describes one stored non-key setting.
type Value struct {
	// Text preserves the loader-decoded value for editing, not necessarily its YAML
	// spelling. Empty means unset.
	Text string
	// Set is whether the file holds an entry for the setting.
	Set bool
	// Default supplies the unset-setting display value or built-in list label.
	Default string
	// Relative explains how a stored path resolves from nyx's working directory. It is set
	// for relative paths and an unset output_dir.
	Relative string
	// Problem blocks saving until this invalid setting is edited or cleared.
	Problem string
}

// KeyState describes one stored source credential and its test record.
type KeyState struct {
	// Value preserves the stored key, with empty for unset/empty entries.
	Value config.Secret
	// Problem marks invalid key entries, including duplicate case variants.
	Problem string
	// Record holds the last test matching the current key. Nil means no readable record
	// exists or the key was changed outside setup.
	Record *KeyRecord
}

// Stored key-test status strings.
const (
	RecordAccepted  = "accepted"
	RecordRejected  = "rejected"
	RecordNotTested = "not tested" // entered, and not tested since
)

// KeyRecord records the last test result, or an untested state, with its date.
type KeyRecord struct {
	Result string    // RecordAccepted, RecordRejected or RecordNotTested
	Day    time.Time // midnight UTC of the calendar day
}

// SkipProblem is an entry of skip that is unknown or cannot be skipped.
type SkipProblem struct {
	Entry   string
	Message string // recon's message for it
}

// Snapshot represents the backend's last file read.
type Snapshot struct {
	// Token identifies the bytes read, or "absent". The model returns it on save so the
	// backend can detect external edits.
	Token any
	// Keys holds one entry for each of Info.Sources, by source name.
	Keys map[string]KeyState
	// Settings holds one entry for each of SettingKeys, by key.
	Settings map[string]Value
	// Skip preserves normalised toggleable stages in file order.
	Skip []string
	// SkipProblems lists individually removable unknown/required stage entries.
	SkipProblems []SkipProblem
	// SkipListProblem flags invalid combinations such as none with stage names;
	// editing/clearing resolves it.
	SkipListProblem string
}

// Edits records changes relative to a snapshot for conflict-checked saving.
type Edits struct {
	// Set holds final entered values by dotted key. Keys are trimmed; paths are absolute or
	// tilde-prefixed.
	Set map[string]string
	// Clear lists the keys whose entry is removed from the file.
	Clear []string
	// Skip replaces the full list when non-nil. An empty slice removes the setting.
	// Unchanged entries, including invalid ones, remain in the list.
	Skip []string
	// Records supplies key-test records by source. Removing a key also removes its test
	// record, even without an entry here.
	Records map[string]KeyRecord
}

// Empty reports whether e changes nothing.
func (e Edits) Empty() bool {
	return len(e.Set) == 0 && len(e.Clear) == 0 && e.Skip == nil && len(e.Records) == 0
}

// ErrConflict is returned by Save when the file differs from the snapshot's Token.
var ErrConflict = errors.New("the config file changed on disk")

// FileError collects reload failures for unreadable, invalid or unknown-key files, together
// with their path.
type FileError struct {
	Path     string
	Problems []string
}

func (e *FileError) Error() string { return fmt.Sprintf("%s: %d problem(s)", e.Path, len(e.Problems)) }

// TestStatus is how a key test ended.
type TestStatus int

// The ways a key test ends.
const (
	// TestAccepted is "accepted".
	TestAccepted TestStatus = iota
	// TestRejected is "rejected".
	TestRejected
	// TestUnknown is "could not check: <Reason>".
	TestUnknown
)

// TestResult includes a sanitised, redacted one-line Reason only for TestUnknown.
type TestResult struct {
	Status TestStatus
	Reason string
}

// String is the text the Keys tab shows.
func (r TestResult) String() string {
	switch r.Status {
	case TestAccepted:
		return "accepted"
	case TestRejected:
		return "rejected"
	case TestUnknown:
	}
	return "could not check: " + r.Reason
}

// Backend handles work outside terminal rendering. Methods run on the model goroutine except
// asynchronous Test and UpdateThreatData commands.
type Backend interface {
	// Info describes supported config fields and static tab metadata.
	Info() Info
	// Open reads a snapshot, returning defaults and Token="absent" for missing files.
	// Invalid, unreadable or unknown-key files return *FileError.
	Open() (Snapshot, error)
	// Check validates an entered non-key setting using recon's rules and returns its
	// storage value, making relative paths absolute. The model handles empty entries as
	// clears before calling this method.
	Check(key, value string) (string, error)
	// Save applies edits and returns the updated snapshot. A changed Token yields
	// ErrConflict. Errors leave the file unchanged.
	Save(snap Snapshot, edits Edits) (Snapshot, error)
	// Overwrite applies edits to current disk state without checking the original snapshot.
	Overwrite(edits Edits) (Snapshot, error)
	// Test makes one authenticated source request. Its 15-second context limit produces
	// TestUnknown with a timeout reason.
	Test(ctx context.Context, source string, key config.Secret) TestResult
	// ThreatData is the five threat-data lists in use, in display order.
	ThreatData() []ThreatList
	// UpdateThreatData refreshes lists as the non-interactive update command does. It runs
	// in a Cmd, honours cancellation and returns each list's resulting state.
	UpdateThreatData(ctx context.Context) ThreatResult
}

// Options supplies UI dependencies beyond Backend.
type Options struct {
	In  io.Reader // the terminal's input (the raw stdin)
	Out io.Writer // the terminal's output (the raw stdout); a terminal when it is an *os.File
	Env []string  // the environment the Program reads TERM and the like from
	// Depth is the colour depth nyx detected for stdout.
	Depth palette.Depth
	// Width/Height supply positive test dimensions when Out cannot report terminal size.
	Width, Height int
	// TestTimeout is how long a key test may take; 0 means 15 seconds.
	TestTimeout time.Duration
	// Now dates records using its local calendar day. Nil uses time.Now.
	Now func() time.Time
	// OnSecret registers entered/stored keys for caller redaction before an error can
	// expose them.
	OnSecret func(value string)
	// OnProgram receives a thread-safe stop/restore function before the Program starts.
	OnProgram func(kill func())
}
