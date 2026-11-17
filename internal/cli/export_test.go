package cli_test

import (
	"bytes"
	"context"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// exportWorld is an engagement "a.com" recorded by a run, and the stages it was
// recorded with.
type exportWorld struct {
	h       *harness
	dropOld *atomic.Bool // the disc stage no longer finds old.a.com
	title   atomic.Value // the title disc gives the web service on www.a.com
}

// newExportWorld records an engagement with every sort of line the export has:
// entities of each scope, shown and hidden web records, a record merged from
// stages that disagree, inputs and exclusions. A second run, after
// markOldGone, makes old.a.com not current.
func newExportWorld(t *testing.T) *exportWorld {
	t.Helper()
	w := &exportWorld{dropOld: &atomic.Bool{}}
	w.title.Store("Welcome")
	one := func(name string, obs ...run.Observation) *testkit.Stage {
		return &testkit.Stage{StageName: name, Kind: run.ThirdParty,
			ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
			RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
				return obs, nil
			}}
	}
	// zeta comes before alpha in the registry, and after it by name, so a merge
	// that follows the registry gives alpha's title and one that follows the
	// names gives zeta's.
	zeta := one("zeta", obs("web_service", "https://shared.a.com", "url", "https://shared.a.com", "host", "shared.a.com",
		"title", "from zeta", "server", "zeta-server"))
	alpha := one("alpha", obs("web_service", "https://shared.a.com", "url", "https://shared.a.com", "host", "shared.a.com",
		"title", "from alpha"))
	disc := &testkit.Stage{StageName: "disc", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
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

// export runs `nyx recon export` with its own output buffers, so it can run while
// another run uses the harness's.
func export(h *harness, args ...string) exported {
	var stdout, stderr bytes.Buffer
	d := h.deps()
	d.Stdout, d.Stderr = &stdout, &stderr
	full := append([]string{"recon", "export", "--output-dir", h.out}, args...)
	code := cli.Execute(context.Background(), full, d)
	return exported{code, stdout.String(), stderr.String()}
}

// exLine is one exported line.
type exLine = event

func (l exLine) attrs() map[string]any {
	m, _ := l["attrs"].(map[string]any)
	return m
}
func (l exLine) stages() []string {
	var out []string
	for _, s := range l["stages"].([]any) {
		out = append(out, s.(string))
	}
	return out
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

	// Every record of the state database is exported once: the same set of kind
	// and key, not-current ones included.
	want := queryStrings(t, h.openDB("a.com"), "SELECT kind||'|'||key FROM records")
	var got []string
	for _, l := range lines {
		if k := l.str("kind"); k != "input" && k != "exclusion" {
			got = append(got, k+"|"+l.str("key"))
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Fatalf("exported records differ from the database\n got %v\nwant %v", got, want)
	}

	// Records are written in kind order, then key order, after the inputs.
	var order []string
	for _, l := range lines {
		if k := l.str("kind"); k != "input" && k != "exclusion" {
			order = append(order, k+"\x00"+l.str("key"))
		}
	}
	if !sort.StringsAreSorted(order) {
		t.Errorf("records are not in kind and key order: %q", order)
	}
	seenRecord := false
	for _, l := range lines {
		isInput := l.str("kind") == "input" || l.str("kind") == "exclusion"
		if !isInput {
			seenRecord = true
		} else if seenRecord {
			t.Errorf("input line %v after a record", l)
		}
	}

	// Entities carry scope and every other kind carries shown, never both.
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

	// A record that is current names the stages observing it and carries its
	// merged attributes and dates; one that is not has neither.
	www := exportLine(t, lines, "hostname", "www.a.com")
	if www["current"] != true || !slices.Equal(www.stages(), []string{"disc"}) ||
		www.str("first_seen") != "2026-11-01" || www.str("last_seen") != "2026-11-01" {
		t.Errorf("www.a.com = %v", www)
	}
	// The store keeps attributes only from current observations, so a record
	// that was found and is not current any more has none, and no stages.
	for _, k := range []struct{ kind, key string }{{"hostname", "old.a.com"}, {"web_service", "https://old.a.com"}} {
		old := exportLine(t, lines, k.kind, k.key)
		if old["current"] != false || len(old.stages()) != 0 || old["attrs"] == nil || len(old.attrs()) != 0 {
			t.Errorf("%s %s should be not current with no stages or attributes: %v", k.kind, k.key, old)
		}
	}
	nb := exportLine(t, lines, "netblock", "198.51.100.0/24")
	if !slices.Equal(nb.stages(), []string{"asn", "disc"}) || nb.attrs()["asn"] != "AS64500" || nb.attrs()["org"] != "Acme" {
		t.Errorf("netblock attributes and stages are the merge of asn and disc: %v", nb)
	}
	ws := exportLine(t, lines, "web_service", "https://www.a.com")
	if ws.attrs()["port"] != float64(443) || ws.attrs()["title"] != "Welcome" {
		t.Errorf("web service attrs = %v", ws.attrs())
	}

	// Derived records are exported like the rest, from their pseudo-stage.
	rank := exportLine(t, lines, "candidate_rank", kinds.CandidateRankKey("hostname", "evil.example"))
	if !slices.Equal(rank.stages(), []string{"candidate-rank"}) {
		t.Errorf("candidate rank stages = %v", rank.stages())
	}

	// Inputs and exclusions are lines of their own.
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
		if l.str("kind") == "exclusion" {
			excl = append(excl, l.str("value"))
			if l.str("added") != "2026-11-01" {
				t.Errorf("exclusion %v has no added date", l)
			}
		}
	}
	if !slices.Equal(excl, []string{"192.0.2.0/24", "admin.a.com"}) {
		t.Errorf("exclusions = %v", excl)
	}

	// The acknowledgement, netblock approval and settings are not exported, and
	// nothing else is: every line is a known kind with the fields it is documented to have.
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
		if strings.Contains(e.stdout, s) {
			t.Errorf("the export mentions %q", s)
		}
	}
	for _, l := range lines {
		if l.str("kind") == "input" || l.str("kind") == "exclusion" {
			continue
		}
		if keys := slices.Sorted(maps.Keys(l)); len(keys) != 8 {
			t.Errorf("%s %s has fields %v", l.str("kind"), l.str("key"), keys)
		}
	}
}

// A line names its fields in the order the README gives them.
func TestExport_FieldOrder(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	e := export(w.h, "-e", "a.com", "--kind", "hostname", "--kind", "web_service")
	if e.code != 0 {
		t.Fatalf("exit %d: %s", e.code, e.stderr)
	}
	for _, raw := range strings.Split(strings.TrimSpace(e.stdout), "\n") {
		if strings.HasPrefix(raw, `{"kind":"hostname","key":`) {
			for _, f := range []string{`,"attrs":`, `,"current":`, `,"first_seen":`, `,"last_seen":`, `,"stages":`, `,"scope":`} {
				i := strings.Index(raw, f)
				if i < 0 {
					t.Fatalf("%q lacks %s", raw, f)
				}
				raw = raw[i+1:]
			}
			continue
		}
		if !strings.HasPrefix(raw, `{"kind":"web_service","key":`) || !strings.Contains(raw, `,"shown":`) {
			t.Errorf("unexpected line %q", raw)
		}
	}
}

// Merged attributes follow the registry's stage order, as a run's do.
func TestExport_MergeFollowsRegistryOrder(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	l := exportLine(t, export(w.h, "-e", "a.com").lines(t), "web_service", "https://shared.a.com")
	if l.attrs()["title"] != "from alpha" || l.attrs()["server"] != "zeta-server" {
		t.Errorf("attrs = %v: the later stage in the registry wins a field, and an earlier one's other fields stay", l.attrs())
	}
	if !slices.Equal(l.stages(), []string{"alpha", "zeta"}) {
		t.Errorf("stages = %v", l.stages())
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
	// export is the only command the root lists beside help: adding it brings no
	// completion command.
	var root bytes.Buffer
	d := h.deps()
	d.Stdout = &root
	if code := cli.Execute(context.Background(), []string{"--help"}, d); code != 0 || !strings.Contains(root.String(), "export") ||
		strings.Contains(root.String(), "completion") {
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
	seen := &testkit.Stage{StageName: "leaky", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			// Recorded by a run that had no key configured, so the store did not redact it.
			return []run.Observation{
				obs("hostname", "www.a.com"),
				obs("web_service", "https://www.a.com/?k="+secret, "url", "https://www.a.com/?k="+secret, "host", "www.a.com",
					"title", "key "+secret, "server", "nginx"),
			}, nil
		}}
	h := newHarness(t, seen)
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(strings.Join(queryStrings(t, h.openDB("a.com"), "SELECT attrs FROM observations"), ""), secret) {
		t.Fatal("the test needs the value in the database")
	}

	h.setenv("NYX_KEYS_SHODAN", secret)
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

	// A second run of the same engagement, held inside a check.
	started, release := make(chan struct{}), make(chan struct{})
	blocker := &testkit.Stage{StageName: "blocker", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("b", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
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
	h := newHarness(t, &testkit.Stage{StageName: "s", Kind: run.ThirdParty})

	if e := export(h, "-e", "missing"); e.code != 1 {
		t.Errorf("missing engagement: exit %d, want 1", e.code)
	} else if !strings.Contains(e.stderr, "missing") {
		t.Errorf("the error does not name the engagement: %q", e.stderr)
	}
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		t.Errorf("export created %v", entries)
	}

	// A directory that is not an engagement, empty or not.
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
	for _, name := range []string{"other", "empty"} {
		if e := export(h, "-e", name); e.code != 1 || e.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q, want 1 and nothing", name, e.code, e.stdout)
		}
	}
	// A .nyx directory without a state database is not an engagement either.
	if err := os.MkdirAll(filepath.Join(h.out, "hollow", ".nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, h.out)
	if e := export(h, "-e", "hollow"); e.code != 1 {
		t.Errorf("hollow: exit %d, want 1", e.code)
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
	return uint64(st.Ino)
}

// The engagement is found under output_dir from the configuration, as for a run.
func TestExport_FindsEngagementUnderConfiguredOutputDir(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	w.h.setenv("NYX_OUTPUT_DIR", w.h.out)
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
