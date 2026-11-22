package output_test

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/output"
)

func rows(rs ...output.Row) func(output.Snapshot) []output.Row {
	return func(output.Snapshot) []output.Row { return rs }
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readCSV(t *testing.T, dir, name string) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(read(t, dir, name))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func newDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, ".nyx"), 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// TXT lists current records only, sorted; CSV lists all with date and currency columns.
func TestTXTAndCSV(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	rs := rows(
		output.Row{Cells: []string{"b.example.com", "x"}, Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-02"},
		output.Row{Cells: []string{"a.example.com", "y"}, Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-01"},
		output.Row{Cells: []string{"gone.example.com", "z"}, Current: false, FirstSeen: "2026-10-01", LastSeen: "2026-10-05"},
	)
	files := []output.File{
		{Name: "list.txt", Format: output.TXT, Rows: rs},
		{Name: "table.csv", Format: output.CSV, Columns: []string{"host", "src"}, Rows: rs},
	}
	if err := output.Render(dir, files, output.Snapshot{}, true); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "list.txt"); got != "a.example.com\nb.example.com\n" {
		t.Errorf("txt = %q", got)
	}
	recs := readCSV(t, dir, "table.csv")
	want := [][]string{
		{"host", "src", "current", "first_seen", "last_seen"},
		{"a.example.com", "y", "true", "2026-11-01", "2026-11-01"},
		{"b.example.com", "x", "true", "2026-11-01", "2026-11-02"},
		{"gone.example.com", "z", "false", "2026-10-01", "2026-10-05"},
	}
	if !slices.EqualFunc(recs, want, slices.Equal) {
		t.Errorf("csv = %v, want %v", recs, want)
	}
}

// A file's Order replaces the sort by cells; without one the cells decide.
func TestFileOrder(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	rs := rows(
		output.Row{Cells: []string{"b", "1"}, Current: true},
		output.Row{Cells: []string{"a", "3"}, Current: true},
		output.Row{Cells: []string{"c", "2"}, Current: false},
	)
	byNumberDesc := func(a, b output.Row) int { return strings.Compare(b.Cells[1], a.Cells[1]) }
	files := []output.File{
		{Name: "ordered.csv", Format: output.CSV, Columns: []string{"v", "n"}, Rows: rs, Order: byNumberDesc},
		{Name: "plain.csv", Format: output.CSV, Columns: []string{"v", "n"}, Rows: rs},
	}
	if err := output.Render(dir, files, output.Snapshot{}, false); err != nil {
		t.Fatal(err)
	}
	firstCells := func(name string) string {
		var out []string
		for _, r := range readCSV(t, dir, name)[1:] {
			out = append(out, r[0])
		}
		return strings.Join(out, "")
	}
	if got := firstCells("ordered.csv"); got != "acb" {
		t.Errorf("ordered.csv order = %s, want acb", got)
	}
	if got := firstCells("plain.csv"); got != "abc" {
		t.Errorf("plain.csv order = %s, want abc", got)
	}
}

// A file with no rows is not written, and one that had rows is removed once it has none.
// A TXT file lists current rows only, so one with no current rows counts as empty.
func TestEmptyFilesNotWritten(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	gone := output.Row{Cells: []string{"gone.example.com"}, Current: false}
	files := []output.File{
		{Name: "e.txt", Format: output.TXT, Rows: rows()},
		{Name: "stale.txt", Format: output.TXT, Rows: rows(gone)},
		{Name: "e.csv", Format: output.CSV, Columns: []string{"a"}, Rows: rows()},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.Name), []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.Render(dir, files, output.Snapshot{}, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f.Name)); !os.IsNotExist(err) {
			t.Errorf("%s: want no file, got err %v", f.Name, err)
		}
	}
	if err := output.Render(dir, files, output.Snapshot{}, false); err != nil {
		t.Errorf("rendering again with nothing to remove: %v", err)
	}
}

// CSV injection and control characters.
func TestCSVSafety(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	files := []output.File{{Name: "t.csv", Format: output.CSV, Columns: []string{"a", "b"}, Rows: rows(
		output.Row{Cells: []string{"=cmd()", "+1"}, Current: true},
		output.Row{Cells: []string{"-2", "@sum"}, Current: true},
		output.Row{Cells: []string{"\tx", "\rx"}, Current: true},
		output.Row{Cells: []string{"ok\x1b[31mred\x00", "line\nbreak"}, Current: true},
		output.Row{Cells: []string{"\x00=cmd()", "\x1b[0m+1"}, Current: true},
		output.Row{Cells: []string{"a\u202eb", "c"}, Current: true},
	)}}
	if err := output.Render(dir, files, output.Snapshot{}, false); err != nil {
		t.Fatal(err)
	}
	recs := readCSV(t, dir, "t.csv")
	got := map[string]bool{}
	for _, r := range recs[1:] {
		got[r[0]+"|"+r[1]] = true
	}
	for _, w := range []string{"'=cmd()|'+1", "'-2|'@sum", " x|x", "okred|linebreak", "ab|c"} {
		if !got[w] {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	for _, r := range recs {
		for _, c := range r {
			if strings.ContainsAny(c, "\x00\x1b\n\t\u202e") {
				t.Errorf("control character survived in %q", c)
			}
		}
	}
}

// Rendered through .nyx/tmp then renamed; no leftovers; sweep clears stale temp files.
func TestAtomicRenderAndSweep(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	f := output.File{Name: "a.txt", Format: output.TXT, Rows: rows(output.Row{Cells: []string{"one"}, Current: true})}
	if err := output.Render(dir, []output.File{f}, output.Snapshot{}, false); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".nyx", "tmp"))
	if len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
	// A stale partial file from a crash.
	if err := os.MkdirAll(filepath.Join(dir, ".nyx", "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".nyx", "tmp", "a.txt")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := output.Sweep(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("sweep should remove stale temp files")
	}
	if read(t, dir, "a.txt") != "one\n" {
		t.Error("sweep must not touch rendered files")
	}
}

// Every default file is registered, in order, and every CSV has columns.
func TestDefaultRegistry(t *testing.T) {
	t.Parallel()
	var names []string
	for _, f := range output.Default() {
		names = append(names, f.Name)
		if f.Format == output.CSV {
			if len(f.Columns) == 0 {
				t.Errorf("%s has no columns", f.Name)
			}
		}
	}
	if strings.Join(names, ",") != "scope.csv,candidates.csv,excluded.csv,subdomains.txt,resolutions.csv,unresolved.txt,wildcard-excluded.txt,ips.csv,provider-hosts.csv,web-services.csv,urls.csv,open-ports.csv,email-posture.csv,third-parties.csv,code-mentions.csv,storage-unattributed.csv,risk-takeover.csv,risk-storage.csv,risk-sensitive-paths.csv,risk-email.csv,risk-ports.csv,risk-certificates.csv,risk-web-posture.csv,risk-origin-exposure.csv,risk-eol-software.csv,risk-abusive-network.csv,changes.csv" {
		t.Errorf("default files = %v", names)
	}
}

// changes.csv lists the snapshot's changes, new then returned then gone, then by
// kind and key; a gone row is not current. It is removed when a run has none.
func TestChangesFile(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	changes := file(t, "changes.csv")
	snap := output.Snapshot{Changes: []output.Change{
		{Change: "gone", Kind: "finding", Key: "takeover|x", Scope: "", Severity: "high", Current: false, FirstSeen: "2026-10-01", LastSeen: "2026-10-30"},
		{Change: "new", Kind: "web service", Key: "https://b.a.com", Scope: "in-scope", Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-01"},
		{Change: "returned", Kind: "hostname", Key: "c.a.com", Scope: "in-scope", Current: true, FirstSeen: "2026-09-01", LastSeen: "2026-11-01"},
		{Change: "new", Kind: "hostname", Key: "=cmd()", Scope: "in-scope", Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-01"},
	}}
	if err := output.Render(dir, []output.File{changes}, snap, false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"change,kind,key,scope,severity,current,first_seen,last_seen",
		"new,hostname,'=cmd(),in-scope,,true,2026-11-01,2026-11-01",
		"new,web service,https://b.a.com,in-scope,,true,2026-11-01,2026-11-01",
		"returned,hostname,c.a.com,in-scope,,true,2026-09-01,2026-11-01",
		"gone,finding,takeover|x,,high,false,2026-10-01,2026-10-30",
	}
	if got := read(t, dir, "changes.csv"); got != strings.Join(want, "\n")+"\n" {
		t.Errorf("changes.csv =\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	if err := output.Render(dir, []output.File{changes}, output.Snapshot{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "changes.csv")); !os.IsNotExist(err) {
		t.Errorf("a snapshot with no changes left changes.csv: %v", err)
	}
}

// A Writer replaces a file only when its contents change, or when the file has gone since it
// wrote it; a new Writer writes every file.
func TestWriter_RewritesOnlyChangedFiles(t *testing.T) {
	t.Parallel()
	dir := newDir(t)
	host := "a.example.com"
	files := []output.File{
		{Name: "fixed.txt", Format: output.TXT, Rows: rows(output.Row{Cells: []string{"fixed"}, Current: true})},
		{Name: "moving.txt", Format: output.TXT, Rows: func(output.Snapshot) []output.Row {
			return []output.Row{{Cells: []string{host}, Current: true}}
		}},
	}
	stat := func(name string) os.FileInfo {
		t.Helper()
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	w := output.NewWriter(dir, false)
	if err := w.Render(files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	fixed, moving := stat("fixed.txt"), stat("moving.txt")

	host = "b.example.com"
	if err := w.Render(files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fixed, stat("fixed.txt")) {
		t.Error("fixed.txt was rewritten with the same contents")
	}
	if os.SameFile(moving, stat("moving.txt")) || read(t, dir, "moving.txt") != "b.example.com\n" {
		t.Errorf("moving.txt was not rewritten: %q", read(t, dir, "moving.txt"))
	}

	if err := os.Remove(filepath.Join(dir, "fixed.txt")); err != nil {
		t.Fatal(err)
	}
	if err := w.Render(files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "fixed.txt"); got != "fixed\n" {
		t.Errorf("a removed file was not written again: %q", got)
	}

	fixed = stat("fixed.txt")
	if err := output.NewWriter(dir, false).Render(files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(fixed, stat("fixed.txt")) {
		t.Error("a new Writer did not write every file")
	}
}
