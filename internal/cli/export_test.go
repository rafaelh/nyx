package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// exportWorld is an engagement "a.com" recorded by a run, and the procedures it was
// recorded with.
type exportWorld struct {
	h       *harness
	dropOld *atomic.Bool // the disc procedure no longer finds old.a.com
	title   atomic.Value // the title disc gives the web service on www.a.com
}

// newExportWorld covers placements, visibility, merged attributes and historical records in one
// engagement.
func newExportWorld(t *testing.T) *exportWorld {
	t.Helper()
	w := &exportWorld{dropOld: &atomic.Bool{}}
	w.title.Store("Welcome")
	// Use registry order opposite name order so the winning title reveals which merge order
	// was used.
	zeta := finder("zeta", obs("web_service", "https://shared.a.com", "url", "https://shared.a.com", "host", "shared.a.com",
		"title", "from zeta", "server", "zeta-server"))
	alpha := finder("alpha", obs("web_service", "https://shared.a.com", "url", "https://shared.a.com", "host", "shared.a.com",
		"title", "from alpha"))
	disc := &testkit.Procedure{ProcedureName: "disc", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			out := []run.Observation{
				obs("hostname", "www.a.com"), obs("hostname", "admin.a.com"), obs("hostname", "evil.example"),
				obs("root", "b.org"),
				obs("netblock", "198.51.100.0/24", "org", "Acme"), obs("netblock", "203.0.113.0/24"),
				obs("ip", "198.51.100.5"),
				obs("excluded", "192.0.2.9", "reason", "dialled an excluded address"),
				obs("web_service", "https://www.a.com", "url", "https://www.a.com", "host", "www.a.com", "port", float64(443),
					"title", w.title.Load().(string)),
				obs("web_service", "https://evil.example", "url", "https://evil.example", "host", "evil.example"),
			}
			if !w.dropOld.Load() {
				out = append(out, obs("hostname", "old.a.com"),
					obs("web_service", "https://old.a.com", "url", "https://old.a.com", "host", "old.a.com", "title", "Old site"))
			}
			return out, nil
		}}
	h := newHarness(t, newASN(), zeta, alpha, disc)
	prefix := "198.51.100.0/24"
	asnServer(t, h, &prefix)
	w.h = h
	if code := h.exec("a.com", "--org", "Acme Corp", "--asn", "64500", "-x", "admin.a.com", "-x", "192.0.2.0/24", "--authorised"); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr.String())
	}
	return w
}

// markOldGone re-runs disc without old.a.com, so that record is not current.
func (w *exportWorld) markOldGone(t *testing.T) {
	t.Helper()
	w.dropOld.Store(true)
	if code := w.h.exec("-e", "a.com", "--redo", "disc"); code != 0 {
		t.Fatalf("second run exit %d: %s", code, w.h.stderr.String())
	}
}

// exported is the result of one export.
type exported struct {
	code           int
	stdout, stderr string
}

// export runs `nyx recon export` through the harness and returns what it wrote.
func export(h *harness, args ...string) exported {
	h.t.Helper()
	code := h.exportExec(args...)
	return exported{code, h.stdout.String(), h.stderr.String()}
}

// exLine is one exported line.
type exLine = event

func (l exLine) attrs() map[string]any {
	m, _ := l["attrs"].(map[string]any)
	return m
}

// procedures is the line's procedures list, nil when the line has none or it is not a list of
// names.
func (l exLine) procedures() []string {
	list, _ := l["procedures"].([]any)
	var out []string
	for _, s := range list {
		name, _ := s.(string)
		out = append(out, name)
	}
	return out
}

// hasProcedures reports whether the line has a procedures key holding a list, empty or not.
func (l exLine) hasProcedures() bool {
	_, ok := l["procedures"].([]any)
	return ok
}

func (e exported) lines(t *testing.T) []exLine {
	t.Helper()
	return jsonLines(t, e.stdout)
}

// exportLine returns the one line of the kind and key.
func exportLine(t *testing.T, lines []exLine, kind, key string) exLine {
	t.Helper()
	var got []exLine
	for _, l := range lines {
		if l.str("kind") == kind && l.str("key") == key {
			got = append(got, l)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s %q line, got %d", kind, key, len(got))
	}
	return got[0]
}

func TestExport_EveryRecordOnce(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	w.markOldGone(t)
	h := w.h
	e := export(h, "-e", "a.com")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	lines := e.lines(t)

	checkExportedRecordSet(t, h, lines)
	checkExportOrder(t, lines)
	checkExportPlacement(t, lines)
	checkExportRecordFields(t, lines)
	checkExportInputs(t, lines)
	checkExportNothingElse(t, e.stdout, lines)
}

// isInputLine reports whether an exported line is an input or an exclusion rather than a record.
func isInputLine(l exLine) bool { return l.str("kind") == "input" || l.str("kind") == "exclusion" }

// checkExportedRecordSet checks that every record of the state database is
// exported once: the same set of kind and key, not-current ones included.
func checkExportedRecordSet(t *testing.T, h *harness, lines []exLine) {
	t.Helper()
	want := queryStrings(t, h.openDB("a.com"), "SELECT kind||'|'||key FROM records")
	var got []string
	for _, l := range lines {
		if !isInputLine(l) {
			got = append(got, l.str("kind")+"|"+l.str("key"))
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("exported records differ from the database\n got %v\nwant %v", got, want)
	}
}

// checkExportOrder checks that records are written in kind order, then key
// order, after the inputs.
func checkExportOrder(t *testing.T, lines []exLine) {
	t.Helper()
	var order []string
	for _, l := range lines {
		if !isInputLine(l) {
			order = append(order, l.str("kind")+"\x00"+l.str("key"))
		}
	}
	if !slices.IsSorted(order) {
		t.Errorf("records are not in kind and key order: %q", order)
	}
	seenRecord := false
	for _, l := range lines {
		if !isInputLine(l) {
			seenRecord = true
		} else if seenRecord {
			t.Errorf("input line %v after a record", l)
		}
	}
}

// checkExportPlacement checks that entities carry scope and every other kind
// carries shown, never both.
func checkExportPlacement(t *testing.T, lines []exLine) {
	t.Helper()
	for _, c := range []struct{ kind, key, scope string }{
		{"hostname", "www.a.com", "in-scope"},
		{"hostname", "old.a.com", "in-scope"},
		{"hostname", "admin.a.com", "excluded"},
		{"hostname", "evil.example", "candidate"},
		{"root", "b.org", "candidate"},
		{"netblock", "198.51.100.0/24", "in-scope"}, // expanded from the input ASN
		{"netblock", "203.0.113.0/24", "candidate"},
		{"excluded", "192.0.2.9", "excluded"},
	} {
		l := exportLine(t, lines, c.kind, c.key)
		if l.str("scope") != c.scope {
			t.Errorf("%s %s: scope = %q, want %q", c.kind, c.key, l.str("scope"), c.scope)
		}
		if _, has := l["shown"]; has {
			t.Errorf("%s %s has shown as well as scope", c.kind, c.key)
		}
	}
	for _, c := range []struct {
		kind, key string
		shown     bool
	}{
		{"web_service", "https://www.a.com", true},
		{"web_service", "https://shared.a.com", true},
		{"web_service", "https://evil.example", false}, // its host is not in scope
		{"ip", "198.51.100.5", true},
	} {
		l := exportLine(t, lines, c.kind, c.key)
		if shown, ok := l["shown"].(bool); !ok || shown != c.shown {
			t.Errorf("%s %s: shown = %v, want %v", c.kind, c.key, l["shown"], c.shown)
		}
		if _, has := l["scope"]; has {
			t.Errorf("%s %s has scope as well as shown", c.kind, c.key)
		}
	}
}

// checkExportRecordFields verifies merged attributes, empty historical records and
// derived-record sources.
func checkExportRecordFields(t *testing.T, lines []exLine) {
	t.Helper()
	www := exportLine(t, lines, "hostname", "www.a.com")
	if www["current"] != true || !slices.Equal(www.procedures(), []string{"disc"}) ||
		www.str("first_seen") != "2026-11-01" || www.str("last_seen") != "2026-11-01" {
		t.Errorf("www.a.com = %v", www)
	}
	// Non-current records have no current observations, attributes or observing procedures.
	for _, k := range []struct{ kind, key string }{{"hostname", "old.a.com"}, {"web_service", "https://old.a.com"}} {
		old := exportLine(t, lines, k.kind, k.key)
		if old["current"] != false || !old.hasProcedures() || len(old.procedures()) != 0 || old["attrs"] == nil || len(old.attrs()) != 0 {
			t.Errorf("%s %s should be not current with no procedures or attributes: %v", k.kind, k.key, old)
		}
	}
	nb := exportLine(t, lines, "netblock", "198.51.100.0/24")
	if !slices.Equal(nb.procedures(), []string{"asn", "disc"}) || nb.attrs()["asn"] != "AS64500" || nb.attrs()["org"] != "Acme" {
		t.Errorf("netblock attributes and procedures are the merge of asn and disc: %v", nb)
	}
	ws := exportLine(t, lines, "web_service", "https://www.a.com")
	if ws.attrs()["port"] != float64(443) || ws.attrs()["title"] != "Welcome" {
		t.Errorf("web service attrs = %v", ws.attrs())
	}

	// A record an analysis produces is exported like the rest, naming the analysis.
	rank := exportLine(t, lines, "candidate_rank", kinds.CandidateRank.Key(kinds.CandidateRankAttrs{Type: "hostname", Value: "evil.example"}))
	if !rank.hasProcedures() || len(rank.procedures()) != 0 || rank.str("analysis") != "candidate-rank" {
		t.Errorf("candidate rank procedures = %v, analysis = %v, want none and candidate-rank", rank["procedures"], rank["analysis"])
	}
}

// checkExportInputs checks that inputs and exclusions are lines of their own.
func checkExportInputs(t *testing.T, lines []exLine) {
	t.Helper()
	in := map[string]exLine{}
	for _, l := range lines {
		if l.str("kind") == "input" {
			in[l.str("type")+"|"+l.str("value")] = l
		}
	}
	for _, k := range []string{"root|a.com", "org|Acme Corp", "asn|AS64500"} {
		if l, ok := in[k]; !ok || l.str("added") != "2026-11-01" {
			t.Errorf("input %s = %v", k, l)
		}
	}
	var excl []string
	for _, l := range lines {
		if l.str("kind") != "exclusion" {
			continue
		}
		excl = append(excl, l.str("value"))
		if l.str("added") != "2026-11-01" {
			t.Errorf("exclusion %v has no added date", l)
		}
	}
	if !slices.Equal(excl, []string{"192.0.2.0/24", "admin.a.com"}) {
		t.Errorf("exclusions = %v", excl)
	}
}

// checkExportNothingElse rejects settings/approvals and any undocumented record kind or field.
func checkExportNothingElse(t *testing.T, stdout string, lines []exLine) {
	t.Helper()
	known := map[string]bool{"input": true, "exclusion": true}
	for _, k := range kinds.All() {
		known[k.Name] = true
	}
	for _, l := range lines {
		if !known[l.str("kind")] {
			t.Errorf("unknown kind in line %v", l)
		}
	}
	for _, s := range []string{"ack_at", "netblock_approved", "concurrency", "authorised"} {
		if strings.Contains(stdout, s) {
			t.Errorf("the export mentions %q", s)
		}
	}
	for _, l := range lines {
		if isInputLine(l) {
			continue
		}
		want := []string{"attrs", "current", "first_seen", "key", "kind", "last_seen", "procedures"}
		if _, ok := l["analysis"]; ok {
			want = append(want, "analysis")
		}
		if _, ok := l["scope"]; ok {
			want = append(want, "scope")
		} else {
			want = append(want, "shown")
		}
		slices.Sort(want)
		if keys := slices.Sorted(maps.Keys(l)); !slices.Equal(keys, want) {
			t.Errorf("%s %s has fields %v, want %v", l.str("kind"), l.str("key"), keys, want)
		}
	}
}

// missingInOrder returns the first of fields that raw lacks after the fields before it, or "" when
// raw has them all in order.
func missingInOrder(raw string, fields []string) string {
	for _, f := range fields {
		i := strings.Index(raw, f)
		if i < 0 {
			return f
		}
		raw = raw[i+1:]
	}
	return ""
}

// A line names its fields in the order the docs give them.
func TestExport_FieldOrder(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	e := export(w.h, "-e", "a.com", "--kind", "hostname", "--kind", "web_service")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	for raw := range strings.SplitSeq(strings.TrimSpace(e.stdout), "\n") {
		if strings.HasPrefix(raw, `{"kind":"hostname","key":`) {
			fields := []string{`,"attrs":`, `,"current":`, `,"first_seen":`, `,"last_seen":`, `,"procedures":`, `,"scope":`}
			if f := missingInOrder(raw, fields); f != "" {
				t.Fatalf("%q lacks %s after the fields before it", raw, f)
			}
			continue
		}
		if !strings.HasPrefix(raw, `{"kind":"web_service","key":`) || !strings.Contains(raw, `,"shown":`) {
			t.Errorf("unexpected line %q", raw)
		}
	}
}

// Merged attributes follow the registry's procedure order, as a run's do.
func TestExport_MergeFollowsRegistryOrder(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	l := exportLine(t, export(w.h, "-e", "a.com").lines(t), "web_service", "https://shared.a.com")
	if l.attrs()["title"] != "from alpha" || l.attrs()["server"] != "zeta-server" {
		t.Errorf("attrs = %v: the later procedure in the registry wins a field, and an earlier one's other fields stay", l.attrs())
	}
	if !slices.Equal(l.procedures(), []string{"alpha", "zeta"}) {
		t.Errorf("procedures = %v", l.procedures())
	}
	// The same attributes as the run's own CSV.
	rows := csvRows(t, w.h.readOut("a.com", "web-services.csv"))
	title := slices.Index(rows[0], "title")
	i := slices.IndexFunc(rows, func(r []string) bool { return r[0] == "https://shared.a.com" })
	if title < 0 || i < 0 || rows[i][title] != "from alpha" {
		t.Errorf("the run's own file shows another merge: %v", rows)
	}
}

func TestExport_Filters(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	w.markOldGone(t)
	h := w.h
	kindsOf := func(e exported) map[string]int {
		m := map[string]int{}
		for _, l := range e.lines(t) {
			m[l.str("kind")]++
		}
		return m
	}

	all := export(h, "-e", "a.com")
	cur := export(h, "-e", "a.com", "--current")
	if cur.code != 0 {
		t.Fatalf("exit %d: %s", cur.code, cur.stderr)
	}
	for _, l := range cur.lines(t) {
		if k := l.str("kind"); k != "input" && k != "exclusion" && l["current"] != true {
			t.Errorf("--current exported a not-current record: %v", l)
		}
	}
	if len(cur.lines(t)) >= len(all.lines(t)) {
		t.Errorf("--current dropped nothing (%d of %d lines)", len(cur.lines(t)), len(all.lines(t)))
	}
	if slices.ContainsFunc(cur.lines(t), func(l exLine) bool { return l.str("key") == "old.a.com" }) {
		t.Error("--current exported old.a.com")
	}

	by := export(h, "-e", "a.com", "--kind", "hostname", "--kind", "web_service")
	if by.code != 0 {
		t.Fatalf("exit %d: %s", by.code, by.stderr)
	}
	got := kindsOf(by)
	if len(got) != 2 || got["hostname"] == 0 || got["web_service"] == 0 {
		t.Errorf("--kind hostname --kind web_service gave %v", got)
	}
	if !slices.ContainsFunc(by.lines(t), func(l exLine) bool { return l.str("key") == "old.a.com" }) {
		t.Error("--kind alone drops not-current records")
	}

	both := export(h, "-e", "a.com", "--kind", "hostname", "--current")
	for _, l := range both.lines(t) {
		if l.str("kind") != "hostname" || l["current"] != true {
			t.Errorf("--kind hostname --current exported %v", l)
		}
	}
	if len(both.lines(t)) == 0 || len(both.lines(t)) >= len(by.lines(t)) {
		t.Errorf("both filters: %d lines, with --kind alone %d", len(both.lines(t)), len(by.lines(t)))
	}

	// The inputs and exclusions are kinds of their own for --kind.
	ins := export(h, "-e", "a.com", "--kind", "input", "--kind", "exclusion")
	if got := kindsOf(ins); len(got) != 2 || got["input"] == 0 || got["exclusion"] == 0 {
		t.Errorf("--kind input --kind exclusion gave %v", got)
	}
	if got := kindsOf(export(h, "-e", "a.com", "--kind", "root")); got["input"] != 0 || got["exclusion"] != 0 {
		t.Errorf("--kind root still exported inputs: %v", got)
	}
}

func TestExport_UnknownKind(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	e := export(w.h, "-e", "a.com", "--kind", "hostname", "--kind", "hostnames")
	if e.code != 2 {
		t.Errorf("exit %d, want 2", e.code)
	}
	if e.stdout != "" {
		t.Errorf("nothing is exported for an unknown kind: %q", e.stdout)
	}
	if !strings.Contains(e.stderr, "hostnames") {
		t.Errorf("the unknown kind is named: %q", e.stderr)
	}
}

func TestExport_RequiresEngagementName(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	if e := export(w.h); e.code != 2 || e.stdout != "" {
		t.Errorf("exit %d stdout %q, want 2 and nothing", e.code, e.stdout)
	}
}

func TestExport_HelpListsKinds(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	e := export(h, "--help")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	var names []string
	for _, k := range kinds.All() {
		names = append(names, k.Name)
	}
	if want := "Kinds accepted by --kind: " + strings.Join(append(names, "input", "exclusion"), ", "); !strings.Contains(e.stdout, want) {
		t.Errorf("help does not list the kinds as %q:\n%s", want, e.stdout)
	}
	// The root lists export, and adding a subcommand does not bring in Cobra's own
	// completion command, which offers shells nyx does not support.
	var root bytes.Buffer
	d := h.deps()
	d.Stdout = &root
	if code := cli.Execute(context.Background(), []string{"--help"}, d); code != 0 || !strings.Contains(root.String(), "export") ||
		strings.Contains(root.String(), "powershell") || strings.Contains(root.String(), "fish") {
		t.Errorf("root help (exit %d):\n%s", code, root.String())
	}
}

func TestExport_OutputFile(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	h := w.h
	stdout := export(h, "-e", "a.com")
	dir := t.TempDir()
	target := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(target, []byte("old contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := export(h, "-e", "a.com", "--output", target)
	if e.code != 0 || e.stdout != "" {
		t.Fatalf("exit %d, stdout %q: %s", e.code, e.stdout, e.stderr)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != stdout.stdout {
		t.Errorf("the file differs from the stdout export:\n%s", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temporary file was left beside the target: %v", entries)
	}

	// A failure to write exits 1, leaves an existing file as it was and leaves nothing behind.
	if err := os.WriteFile(target, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The target is a directory, so the rename fails after the file has been written.
	asDir := filepath.Join(dir, "taken")
	if err := os.Mkdir(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory that does not exist is a usage error; a rename that fails is not.
	for bad, want := range map[string]int{asDir: 1, filepath.Join(dir, "no-such-dir", "export.jsonl"): 2} {
		if e := export(h, "-e", "a.com", "--output", bad); e.code != want {
			t.Errorf("--output %s: exit %d, want %d", bad, e.code, want)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep me\n" {
		t.Errorf("an unrelated file changed: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".") || strings.Contains(en.Name(), "tmp") {
			t.Errorf("a temporary file was left: %s", en.Name())
		}
	}
	if len(entries) != 2 {
		t.Errorf("directory has %v", entries)
	}
}

// A failure part-way through must not leave a half-written file in place of
// the old one.
func TestExport_OutputReplacesAtomically(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ino := func() uint64 {
		fi, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		return inode(fi)
	}
	before := ino()
	if e := export(w.h, "-e", "a.com", "--output", target); e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	if ino() == before {
		t.Error("the file was rewritten in place, not replaced by a rename")
	}
}

func TestExport_NoSecrets(t *testing.T) {
	t.Parallel()
	const secret = "tok_Zq81xYw3"
	// Recorded by a run that had no key configured, so the store did not redact it.
	seen := finder("leaky",
		obs("hostname", "www.a.com"),
		obs("web_service", "https://www.a.com/?k="+secret, "url", "https://www.a.com/?k="+secret, "host", "www.a.com",
			"title", "key "+secret, "server", "nginx"))
	h := newHarness(t, seen)
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(strings.Join(queryStrings(t, h.openDB("a.com"), "SELECT attrs FROM observations"), ""), secret) {
		t.Fatal("the test needs the value in the database")
	}

	h.setKey("shodan", secret)
	e := export(h, "-e", "a.com")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	if strings.Contains(e.stdout, secret) || strings.Contains(e.stderr, secret) {
		t.Errorf("the key is in the export: %s", e.stdout)
	}
	if !strings.Contains(e.stdout, "****") {
		t.Errorf("the key is masked, not removed: %s", e.stdout)
	}
	// The key's URL-encoded form is masked too, and so is a key in the record's key.
	if l := e.lines(t); !slices.ContainsFunc(l, func(l exLine) bool { return strings.Contains(l.str("key"), "k=****") }) {
		t.Errorf("a key in a record key is not masked: %s", e.stdout)
	}
}

func TestExport_SanitisesTargetText(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	w.title.Store("\x1b[31mred\x1b[0m title\x1b]0;owned\x07 \u202eevil\x00")
	if code := w.h.exec("-e", "a.com", "--redo", "disc"); code != 0 {
		t.Fatalf("run exit %d: %s", code, w.h.stderr.String())
	}
	e := export(w.h, "-e", "a.com")
	l := exportLine(t, e.lines(t), "web_service", "https://www.a.com")
	if got := l.attrs()["title"]; got != "red title evil" {
		t.Errorf("title = %q", got)
	}
	for _, bad := range []string{`\u001b`, `\u0007`, "\u202e", `\u0000`, "\x1b"} {
		if strings.Contains(e.stdout, bad) {
			t.Errorf("the export has %q", bad)
		}
	}
}

// The export reads while a run holds the engagement, and sees the state as of
// one moment.
func TestExport_WhileRunning(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	h := w.h
	before := export(h, "-e", "a.com")
	if before.code != 0 {
		t.Fatalf("exit %d: %s", before.code, before.stderr)
	}

	// A second run of the same engagement, held inside a job.
	started, release := make(chan struct{}), make(chan struct{})
	blocker := &testkit.Procedure{ProcedureName: "blocker", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("b", 1) },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			close(started)
			<-release
			return []run.Observation{obs("hostname", "late.a.com")}, nil
		}}
	h2 := newHarness(t, blocker)
	h2.out = h.out
	done := make(chan int)
	go func() { done <- h2.exec("-e", "a.com") }()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	<-started

	// A run holds the lock, so a second run is refused, but an export is not.
	if code := h.exec("-e", "a.com"); code != 1 {
		t.Fatalf("the engagement is not locked by the run: exit %d", code)
	}
	during := export(h, "-e", "a.com")
	if during.code != 0 {
		t.Fatalf("export while running: exit %d: %s", during.code, during.stderr)
	}
	if during.stdout != before.stdout {
		t.Errorf("the export is not the state the run started from:\n%s\nwant\n%s", during.stdout, before.stdout)
	}
	close(release)
	if code := <-done; code != 0 {
		t.Fatalf("run exit %d: %s", code, h2.stderr.String())
	}
	if after := export(h, "-e", "a.com"); !strings.Contains(after.stdout, "late.a.com") {
		t.Errorf("the export after the run lacks its record: %s", after.stdout)
	}
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExport_NeverWrites(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	h := w.h
	before := snapshotDir(t, h.out)
	for _, args := range [][]string{{"-e", "a.com"}, {"-e", "a.com", "--current"}, {"-e", "a.com", "--kind", "hostname"}} {
		if e := export(h, args...); e.code != 0 {
			t.Fatalf("%v: exit %d: %s", args, e.code, e.stderr)
		}
	}
	if after := snapshotDir(t, h.out); !maps.Equal(before, after) {
		t.Errorf("the engagement changed: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	if h.network() != 0 {
		t.Errorf("export made %d network requests", h.network())
	}
}

func TestExport_NoEngagement(t *testing.T) {
	t.Parallel()
	h := newHarness(t, &testkit.Procedure{ProcedureName: "s", Kind: run.ThirdParty})

	if e := export(h, "-e", "missing"); e.code != 3 {
		t.Errorf("missing engagement: exit %d, want 3", e.code)
	} else if !strings.Contains(e.stderr, "missing") {
		t.Errorf("the error does not name the engagement: %q", e.stderr)
	}
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		t.Errorf("export created %v", entries)
	}

	// Populated foreign directories are invalid; empty directories represent a missing
	// engagement.
	other := filepath.Join(h.out, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(h.out, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "notes.txt"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"other": 2, "empty": 3} {
		if e := export(h, "-e", name); e.code != want || e.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q, want %d and nothing", name, e.code, e.stdout, want)
		}
	}
	// A .nyx directory without a state database is an engagement that was never finished.
	if err := os.MkdirAll(filepath.Join(h.out, "hollow", ".nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, h.out)
	if e := export(h, "-e", "hollow"); e.code != 3 {
		t.Errorf("hollow: exit %d, want 3", e.code)
	}
	if after := snapshotDir(t, h.out); !maps.Equal(before, after) {
		t.Errorf("export changed the directory: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	if h.network() != 0 {
		t.Errorf("export made %d network requests", h.network())
	}
}

// inode identifies the file a path names, so a replacement by rename shows.
func inode(fi fs.FileInfo) uint64 {
	st, _ := fi.Sys().(*syscall.Stat_t)
	if st == nil {
		return 0
	}
	return st.Ino
}

// Export resolves configured output_dir the same way as recon.
func TestExport_FindsEngagementUnderConfiguredOutputDir(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	w.h.set("output_dir", w.h.out)
	var stdout, stderr bytes.Buffer
	d := w.h.deps()
	d.Stdout, d.Stderr = &stdout, &stderr
	if code := cli.Execute(context.Background(), []string{"recon", "export", "-e", "a.com", "--kind", "root"}, d); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"key":"b.org"`) {
		t.Errorf("export = %q", stdout.String())
	}
}

// producersWorld is an engagement "a.com" whose records come from a real procedure (asn), fake
// procedures and every analysis:
//   - seed observes www.a.com, old.a.com (until dropOld), a CNAME from site.a.com to a SaaS
//     platform and the third party that CNAME implies, an open RDP port (a finding) and a
//     candidate hostname (a candidate rank);
//   - dialler, a target procedure, dials an excluded address, so egress refuses and the guard
//     records it as excluded;
//   - gone observes gone.a.com.
type producersWorld struct {
	h       *harness
	dropOld *atomic.Bool
	gone    run.Procedure
}

// The keys of the records producersWorld names.
const (
	producersRefused    = "198.51.100.9"
	producersThirdParty = "a.com|cname|github.io"
)

func newProducersWorld(t *testing.T) *producersWorld {
	t.Helper()
	w := &producersWorld{dropOld: &atomic.Bool{}}
	seed := &testkit.Procedure{ProcedureName: "seed", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			out := []run.Observation{
				obs("hostname", "www.a.com"), obs("hostname", "site.a.com"), obs("hostname", "evil.example"),
				resolutionObs("site.a.com", "CNAME", "acme.github.io"),
				kinds.ThirdPartyObs("a.com", kinds.MechanismCNAME, "github.io", 0),
				obs("ip", "198.51.100.5"),
				obs("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", ""),
			}
			if !w.dropOld.Load() {
				out = append(out, obs("hostname", "old.a.com"))
			}
			return out, nil
		}}
	dialler := diallerProcedure(producersRefused, nil)
	w.gone = finder("gone", obs("hostname", "gone.a.com"))
	h := newHarness(t, newASN(), seed, dialler, w.gone)
	prefix := "198.51.100.0/24"
	asnServer(t, h, &prefix)
	w.h = h
	if code := h.exec("a.com", "--asn", "64500", "-x", producersRefused+"/32", "--authorised"); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr.String())
	}
	db := h.openDB("a.com")
	for _, c := range []struct{ what, q string }{
		{"no finding", "SELECT key FROM records WHERE kind='finding' AND current=1"},
		{"no candidate rank", "SELECT key FROM records WHERE kind='candidate_rank' AND current=1"},
		{"egress did not refuse the dial", "SELECT key FROM records WHERE kind='excluded' AND current=1 AND key='" + producersRefused + "'"},
		{"no third party from both seed and a CNAME", "SELECT producer FROM observations WHERE kind='third_party' AND key='" + producersThirdParty + "' AND producer='seed'"},
		{"no third party from a CNAME", "SELECT producer FROM observations WHERE kind='third_party' AND key='" + producersThirdParty + "' AND producer<>'seed'"},
	} {
		if got := queryStrings(t, db, c.q); len(got) == 0 {
			t.Fatalf("precondition: %s", c.what)
		}
	}
	return w
}

// secondRun runs the engagement again a day later, without old.a.com and with gone taken out of
// the registry.
func (w *producersWorld) secondRun(t *testing.T) {
	t.Helper()
	w.dropOld.Store(true)
	w.h.procedures = slices.DeleteFunc(slices.Clone(w.h.procedures), func(p run.Procedure) bool { return p == w.gone })
	w.h.now = w.h.now.Add(24 * time.Hour)
	if code := w.h.exec("-e", "a.com", "--redo", "seed"); code != 0 {
		t.Fatalf("second run exit %d: %s", code, w.h.stderr.String())
	}
	if got := queryStrings(t, w.h.openDB("a.com"), "SELECT key FROM records WHERE kind='hostname' AND key='old.a.com' AND current=0"); len(got) != 1 {
		t.Fatal("precondition: old.a.com is still current after the second run")
	}
}

// analysisOf is the line's analysis, and whether it has the key at all.
func analysisOf(l exLine) (string, bool) {
	v, ok := l["analysis"]
	s, _ := v.(string)
	return s, ok
}

// checkProducers checks that a line names these procedures (an empty list for none) and this
// analysis ("" for no analysis key).
func checkProducers(t *testing.T, l exLine, procedures []string, analysis string) {
	t.Helper()
	if !l.hasProcedures() || !slices.Equal(l.procedures(), procedures) {
		t.Errorf("%s %s: procedures = %v, want %q", l.str("kind"), l.str("key"), l["procedures"], procedures)
	}
	got, has := analysisOf(l)
	switch {
	case analysis == "" && has:
		t.Errorf("%s %s has an analysis key %v, want none", l.str("kind"), l.str("key"), l["analysis"])
	case analysis != "" && got != analysis:
		t.Errorf("%s %s: analysis = %v, want %q", l.str("kind"), l.str("key"), l["analysis"], analysis)
	}
}

// Each record line names the registry's procedures that observe it now and, apart from them, the
// analysis that produces it now.
func TestExport_ProceduresAndAnalysis(t *testing.T) {
	t.Parallel()
	w := newProducersWorld(t)
	w.secondRun(t)
	if got := queryStrings(t, w.h.openDB("a.com"), "SELECT key FROM observations WHERE kind='hostname' AND producer='gone'"); len(got) == 0 {
		t.Fatal("precondition: the procedure taken out of the registry has no observation left")
	}
	e := export(w.h, "-e", "a.com")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	lines := e.lines(t)

	checkProducers(t, exportLine(t, lines, "hostname", "www.a.com"), []string{"seed"}, "")
	checkProducers(t, exportLine(t, lines, "third_party", producersThirdParty), []string{"seed"}, run.AnalysisThirdPartyCNAME)
	checkProducers(t, exportLine(t, lines, "excluded", producersRefused), []string{}, run.AnalysisGuard)
	checkProducers(t, exportLine(t, lines, "hostname", "old.a.com"), []string{}, "")
	// A producer that is neither in the registry nor an analysis is left out.
	checkProducers(t, exportLine(t, lines, "hostname", "gone.a.com"), []string{}, "")

	var findings, ranks int
	registry := procedureNameSet(w.h.procedures)
	for _, l := range lines {
		if isInputLine(l) {
			continue
		}
		if _, has := l["stages"]; has {
			t.Errorf("%s %s has a stages key", l.str("kind"), l.str("key"))
		}
		if !l.hasProcedures() {
			t.Errorf("%s %s has no procedures list: %v", l.str("kind"), l.str("key"), l)
		}
		for _, p := range l.procedures() {
			if !registry[p] {
				t.Errorf("%s %s lists %q, which is not a procedure of the registry", l.str("kind"), l.str("key"), p)
			}
		}
		if l["current"] != true {
			if _, has := l["analysis"]; has || len(l.procedures()) != 0 {
				t.Errorf("not current %s %s has procedures %v and analysis %v", l.str("kind"), l.str("key"), l["procedures"], l["analysis"])
			}
			continue
		}
		switch l.str("kind") {
		case "finding":
			findings++
			checkProducers(t, l, []string{}, run.AnalysisFindings)
		case "candidate_rank":
			ranks++
			checkProducers(t, l, []string{}, run.AnalysisCandidateRank)
		}
	}
	if findings == 0 || ranks == 0 {
		t.Errorf("exported %d current findings and %d current candidate ranks, want some of each", findings, ranks)
	}
}

// procedureNameSet is the set of the procedures' names.
func procedureNameSet(procedures []run.Procedure) map[string]bool {
	out := map[string]bool{}
	for _, p := range procedures {
		out[p.Name()] = true
	}
	return out
}

// diallerProcedure is a target procedure, dialler, whose one job dials port 22 of addr. Excluding
// addr makes egress refuse the dial, so the guard records the address; refused, if not nil, says
// whether it did.
func diallerProcedure(addr string, refused *atomic.Bool) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: "dialler", Kind: run.Target,
		JobsFn: func(run.View) []run.Job { return []run.Job{{Key: addr + ":22"}} },
		RunFn: func(ctx context.Context, _ run.Job, e egress.Clients) ([]run.Observation, error) {
			if e.TCP == nil {
				return nil, errors.New("no TCP client")
			}
			res, err := e.TCP.Connect(ctx, netip.MustParseAddr(addr), 22)
			if err != nil {
				return nil, err
			}
			if refused != nil {
				_, ok := res.(egress.Refused)
				refused.Store(ok)
			}
			return nil, nil
		}}
}

// The procedures come before the analysis, and both before scope or shown.
func TestExport_ProducerFieldOrder(t *testing.T) {
	t.Parallel()
	w := newProducersWorld(t)
	e := export(w.h, "-e", "a.com", "--kind", "third_party", "--kind", "excluded", "--kind", "hostname")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	prefix := []string{`,"attrs":`, `,"current":`, `,"first_seen":`, `,"last_seen":`, `,"procedures":`}
	want := map[string][]string{
		`{"kind":"third_party","key":"` + producersThirdParty + `",`: append(slices.Clone(prefix), `,"analysis":"thirdparty-cname"`, `,"shown":`),
		`{"kind":"excluded","key":"` + producersRefused + `",`:       append(slices.Clone(prefix), `,"analysis":"guard"`, `,"scope":`),
		`{"kind":"hostname","key":"www.a.com",`:                      append(slices.Clone(prefix), `,"scope":`),
	}
	seen := map[string]bool{}
	for raw := range strings.SplitSeq(strings.TrimSpace(e.stdout), "\n") {
		for start, fields := range want {
			if !strings.HasPrefix(raw, start) {
				continue
			}
			seen[start] = true
			if f := missingInOrder(raw, fields); f != "" {
				t.Errorf("%q lacks %s after the fields before it", raw, f)
			}
			if !strings.Contains(start, "third_party") && !strings.Contains(start, "excluded") && strings.Contains(raw, `"analysis"`) {
				t.Errorf("%q has an analysis key", raw)
			}
		}
	}
	for start := range want {
		if !seen[start] {
			t.Errorf("no line starts %s", start)
		}
	}
}

// A second run of the same engagement leaves each line's procedures and analysis as they were.
func TestExport_ProducersUnchangedByASecondRun(t *testing.T) {
	t.Parallel()
	w := newProducersWorld(t)
	lines := func() map[string]exLine {
		t.Helper()
		e := export(w.h, "-e", "a.com")
		if e.code != 0 {
			t.Fatalf("exit %d: %s", e.code, e.stderr)
		}
		out := map[string]exLine{}
		for _, l := range e.lines(t) {
			if isInputLine(l) {
				continue
			}
			if !l.hasProcedures() {
				t.Errorf("%s %s has no procedures list", l.str("kind"), l.str("key"))
			}
			l = maps.Clone(l)
			delete(l, "last_seen")
			out[l.str("kind")+"|"+l.str("key")] = l
		}
		return out
	}
	before := lines()
	if _, has := analysisOf(before["third_party|"+producersThirdParty]); !has {
		t.Errorf("before the second run, the third party has no analysis: %v", before["third_party|"+producersThirdParty])
	}

	w.h.now = w.h.now.Add(48 * time.Hour)
	if code := w.h.exec("-e", "a.com"); code != 0 {
		t.Fatalf("second run exit %d: %s", code, w.h.stderr.String())
	}
	after := lines()
	for k, b := range before {
		if a, ok := after[k]; !ok || !reflect.DeepEqual(a, b) {
			t.Errorf("%s changed with the second run:\nbefore %v\nafter  %v", k, b, a)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s is new after the second run", k)
		}
	}
}
