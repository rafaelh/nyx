// Package setup is the full-screen terminal UI of nyx setup: a Bubble Tea model that edits the keys,
// the common settings and the skip list of one config file. It does no file or network I/O itself.
// It gets a Backend, which reads, checks and saves the file and tests a key, and the cli wires one
// from configedit, config and keycheck.
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

// The setting keys the Settings tab lists, in the order it shows them, as the config file names
// them. Keys of the Keys tab are "keys.<source>"; skip has its own tab.
var SettingKeys = []string{"output_dir", "concurrency", "rate.per_host", "rate.per_source", "rate.dns", "wordlist", "sensitive_paths"}

// SkipKey is the setting key of the skip list.
const SkipKey = "skip"

// KeyPrefix starts the key of a key source: "keys.shodan".
const KeyPrefix = "keys."

// Source is one key source the Keys tab lists.
type Source struct {
	Name  string // lower case: "shodan"
	Turns string // what the key turns on, one line (for certspotter it says it also works without one)
}

// Stage is a stage the Skip tab offers: one that can be skipped.
type Stage struct {
	Name string
	Does string // its one-line description, as nyx help stages gives it
}

// Info is what stays the same while setup is open.
type Info struct {
	Path    string   // the config file's absolute path, as the header shows it
	Sources []Source // in display order
	Stages  []Stage  // the skippable stages, in registry order
}

// Value is how one non-key setting stands in the file.
type Value struct {
	// Text is the value config.Check decoded ("16" for "concurrency: 0x10"), "" when the file does
	// not set the setting. It is what an edit starts from.
	Text string
	// Set is whether the file holds an entry for the setting.
	Set bool
	// Default is what the row shows when the file does not set the setting: the default value, or
	// the built-in list's label.
	Default string
	// Relative, when not empty, is the line shown beside the value for a path that resolves against
	// the directory nyx is run from ("Relative: resolves against the directory nyx runs from, e.g.
	// /work/out"). It is set for an unset output_dir and for a relative path in the file.
	Relative string
	// Problem, when not empty, marks the value invalid with that message; saving is blocked until
	// the setting is edited or cleared.
	Problem string
}

// KeyState is how one key source stands in the file.
type KeyState struct {
	// Value is the key as the file holds it; empty when it is unset or empty in the file.
	Value config.Secret
	// Problem, when not empty, marks the entry invalid (a key set twice under case variants).
	Problem string
	// Record is the file's record of the key's last test. It is nil when the file holds none it can
	// read, or holds one made for another value of the key (the key was changed by hand since).
	Record *KeyRecord
}

// The results a key record gives, as the file spells them.
const (
	RecordAccepted  = "accepted"
	RecordRejected  = "rejected"
	RecordNotTested = "not tested" // entered, and not tested since
)

// KeyRecord is the file's record of a key: the result of its last test, or that it has not been
// tested since it was entered, and the day that was so.
type KeyRecord struct {
	Result string    // RecordAccepted, RecordRejected or RecordNotTested
	Day    time.Time // midnight UTC of the calendar day
}

// SkipProblem is an entry of skip that is unknown or cannot be skipped.
type SkipProblem struct {
	Entry   string
	Message string // recon's message for it
}

// Snapshot is the file as the Backend read it.
type Snapshot struct {
	// Token identifies the bytes read ("absent" for a missing file). The Backend compares it with
	// the file at save time, to find a change made since. The model keeps it and hands it back.
	Token any
	// Keys holds one entry for each of Info.Sources, by source name.
	Keys map[string]KeyState
	// Settings holds one entry for each of SettingKeys, by key.
	Settings map[string]Value
	// Skip is the stages the file skips that can be toggled, lower case, in file order.
	Skip []string
	// SkipProblems are the entries that are unknown or cannot be skipped, each removable on its own.
	SkipProblems []SkipProblem
	// SkipListProblem is a problem with the list as a whole ("none" beside stage names); it is
	// cleared by editing or clearing the list.
	SkipListProblem string
}

// Edits are the changes to write, each against the snapshot they were made on.
type Edits struct {
	// Set holds each entered value by key ("keys.shodan", "concurrency"). A value is final: a path
	// is absolute (or starts with "~"), a key is trimmed.
	Set map[string]string
	// Clear lists the keys whose entry is removed from the file.
	Clear []string
	// Skip, when not nil, is the whole skip list to write, in order, and an empty non-nil slice
	// removes the setting. Entries the user left in place (including problem entries) are in it.
	Skip []string
	// Records holds the record to write for a key, by source. A key that is not set once the other
	// edits are applied has its record removed, whether or not it is listed here.
	Records map[string]KeyRecord
}

// Empty reports whether e changes nothing.
func (e Edits) Empty() bool {
	return len(e.Set) == 0 && len(e.Clear) == 0 && e.Skip == nil && len(e.Records) == 0
}

// ErrConflict is returned by Save when the file differs from the snapshot's Token.
var ErrConflict = errors.New("the config file changed on disk")

// FileError is a problem the Backend found in the file on a reload: it could not be read, parsed or
// held an unknown key. It carries every problem message, and Path.
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

// TestResult is the outcome of testing a key. Reason is already sanitised, to one line, with the key
// masked, and is used only for TestUnknown.
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

// Backend is everything setup does outside the terminal. Each method is called from the model's
// goroutine, except Test, which runs in a Cmd.
type Backend interface {
	// Info is the static description of the config file and what it can hold.
	Info() Info
	// Open reads the file. A missing file is not an error: it is a Snapshot of defaults whose Token
	// means "absent". An unreadable, unparseable or unknown-key file is a *FileError.
	Open() (Snapshot, error)
	// Check validates one non-key setting as entered, with the same rules and messages as nyx recon
	// gives for the file, and returns the value to store (a relative path made absolute). The value
	// is never empty: an empty entry is a clear, handled by the model. An error's text is the message.
	Check(key, value string) (string, error)
	// Save applies edits to the file the snapshot was read from and returns the file's new snapshot.
	// It returns ErrConflict, writing nothing, when the file differs from snap.Token. On any other
	// error the file is unchanged.
	Save(snap Snapshot, edits Edits) (Snapshot, error)
	// Overwrite is Save without the conflict check: it applies edits to the file as it is now.
	Overwrite(edits Edits) (Snapshot, error)
	// Test sends one authenticated request to source with key and classifies the answer. ctx
	// carries the 15 second limit; an expired ctx gives TestUnknown with reason "timed out".
	Test(ctx context.Context, source string, key config.Secret) TestResult
}

// Options are what Run needs besides the Backend.
type Options struct {
	In  io.Reader // the terminal's input (the raw stdin)
	Out io.Writer // the terminal's output (the raw stdout); a terminal when it is an *os.File
	Env []string  // the environment the Program reads TERM and the like from
	// Depth is the colour depth nyx detected for stdout.
	Depth palette.Depth
	// Width and Height, when positive, are the window's size, for a test that gives a buffer as Out.
	Width, Height int
	// TestTimeout is how long a key test may take; 0 means 15 seconds.
	TestTimeout time.Duration
	// Now is the clock key records are dated by, in the time zone whose calendar day they record;
	// nil means time.Now.
	Now func() time.Time
	// OnSecret, when set, is called with every key value the user enters or the file holds, before
	// it can reach an error, so the caller can redact it.
	OnSecret func(value string)
	// OnProgram, when set, is called with a function that kills the Program and restores the terminal
	// from any goroutine, before the Program starts.
	OnProgram func(kill func())
}
