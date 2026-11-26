package cli_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// src provides editable observations per job under a real source name.
type src struct {
	*testkit.Procedure
	finds map[string][]run.Observation
}

func newSrc(name string, finds map[string][]run.Observation) *src {
	s := &src{finds: finds}
	s.Procedure = &testkit.Procedure{ProcedureName: name, Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job {
			var out []run.Job
			for _, k := range slices.Sorted(maps.Keys(s.finds)) {
				out = append(out, run.Job{Key: k})
			}
			return out
		},
		RunFn: func(_ context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			return s.finds[c.Key], nil
		}}
	return s
}

// realFamilies are the families the real procedures name for their sources.
var realFamilies = run.CandidateFamilies(cli.DefaultDeps().Procedures)

// CandidateSources gives fake procedures the same evidence families as their real counterparts.
func (*src) CandidateSources() map[string]string {
	m := map[string]string{}
	for _, s := range realFamilies.Sources() {
		m[s] = realFamilies.Of(s)
	}
	return m
}

// pivot simulates setting-bearing keys while Evidence separates stable source/item identity.
type pivot struct{ *src }

func (pivot) Evidence(key string) (source, item string) {
	source, item, _ = strings.Cut(key, ":")
	item, _, _ = strings.Cut(item, "|")
	return source, item
}

func root(v string) run.Observation { return obs("root", v) }
func host(v string) run.Observation { return obs("hostname", v) }
func block(v string) run.Observation {
	return obs("netblock", v)
}

func finds(keyAndObs ...any) map[string][]run.Observation {
	m := map[string][]run.Observation{}
	for i := 0; i+1 < len(keyAndObs); i += 2 {
		found, _ := keyAndObs[i+1].([]run.Observation) // nil: the job finds nothing
		m[keyAndObs[i].(string)] = found
	}
	return m
}

func list(o ...run.Observation) []run.Observation { return o }

func values(rows []map[string]string) string {
	var out []string
	for _, r := range rows {
		out = append(out, r["value"])
	}
	return strings.Join(out, " ")
}

func rowOf(t *testing.T, rows []map[string]string, value string) map[string]string {
	t.Helper()
	r := find(rows, "value", value)
	if r == nil {
		t.Fatalf("no candidates.csv row for %s in %v", value, rows)
	}
	return r
}

func wantRow(t *testing.T, r map[string]string, sources, count, confidence string) {
	t.Helper()
	if r["sources"] != sources || r["evidence_count"] != count || r["confidence"] != confidence {
		t.Errorf("%s: sources=%q evidence_count=%q confidence=%q, want %q %q %q", r["value"], r["sources"], r["evidence_count"], r["confidence"], sources, count, confidence)
	}
}

// candidates.csv has sources, evidence_count and confidence in place of
// found_by, and is sorted high first, then by evidence, then by value.
func TestCandidates_ColumnsAndOrder(t *testing.T) {
	t.Parallel()
	h := newHarness(t,
		newSrc("whoisxml", finds("Acme", list(root("high.org"), root("med.org")))),
		newSrc("certspotter", finds("k1", list(root("high.org")))),
		newSrc("wayback", finds("k2", list(root("three.org")))),
		newSrc("crtsh", finds("k3", list(root("three.org")), "k5", list(root("low.org")), "k6", list(root("low.org")))),
		newSrc("otx", finds("k4", list(root("three.org")))),
	)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if hdr, _, _ := strings.Cut(h.readOut("a.com", "candidates.csv"), "\n"); hdr != "type,value,sources,evidence_count,confidence,current,first_seen,last_seen" {
		t.Errorf("header = %s", hdr)
	}
	rows := h.table("a.com", "candidates.csv")
	if got := values(rows); got != "three.org high.org med.org low.org" {
		t.Errorf("order = %s", got)
	}
	wantRow(t, rowOf(t, rows, "three.org"), "crtsh;otx;wayback", "3", "high")   // three families
	wantRow(t, rowOf(t, rows, "high.org"), "certspotter;whoisxml", "2", "high") // registrant match plus another family
	wantRow(t, rowOf(t, rows, "med.org"), "whoisxml", "1", "medium")            // registrant match alone
	wantRow(t, rowOf(t, rows, "low.org"), "crtsh", "2", "low")                  // two items, one family
	if r := rowOf(t, rows, "three.org"); r["type"] != "root" || r["current"] != "true" || r["first_seen"] != "2026-11-01" {
		t.Errorf("row = %v", r)
	}
}

// A row that is not current is last, with the confidence it last had; it is
// not listed in the summary.
func TestCandidates_NotCurrentSortsLastWithLastConfidence(t *testing.T) {
	t.Parallel()
	pv := pivot{newSrc("pivot", finds("crtsh:a", list(root("x.org")), "wayback:b", list(root("x.org")), "otx:c", list(root("x.org"))))}
	h := newHarness(t, pv, newSrc("crtsh", finds("k", list(root("y.org")))))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := h.table("a.com", "candidates.csv")
	if values(rows) != "x.org y.org" {
		t.Fatalf("first run order = %s", values(rows))
	}
	wantRow(t, rows[0], "crtsh;otx;wayback", "3", "high")

	pv.finds = finds("crtsh:a", nil, "wayback:b", nil, "otx:c", nil) // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "pivot", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows = h.table("a.com", "candidates.csv")
	if values(rows) != "y.org x.org" {
		t.Fatalf("a not-current row sorts last whatever it had: %s", values(rows))
	}
	if rows[0]["current"] != "true" || rows[1]["current"] != "false" {
		t.Errorf("current = %s, %s", rows[0]["current"], rows[1]["current"])
	}
	wantRow(t, rows[1], "crtsh;otx;wayback", "3", "high")
	for _, c := range h.envelope().Data.Candidates {
		if c.Value == "x.org" {
			t.Errorf("a candidate that is not current is not listed: %+v", c)
		}
	}
}

// Preserve rank while redo support is temporarily absent, including when another procedure triggers
// derivation first.
func TestCandidates_NotCurrentAfterRedoKeepsTheRankItHadWhileSupported(t *testing.T) {
	t.Parallel()
	early := newSrc("asn", finds("k1", nil))
	who := newSrc("whoisxml", finds("Acme", list(root("x.org"))))
	h := newHarness(t, early, who)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "whoisxml", "1", "medium")

	early.finds = finds("k1", nil, "k2", nil) // does work before whoisxml runs again
	who.finds = finds("Acme", nil)            // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "whoisxml"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	r := rowOf(t, h.table("a.com", "candidates.csv"), "x.org")
	if r["current"] != "false" {
		t.Fatalf("x.org should no longer be current: %v", r)
	}
	wantRow(t, r, "whoisxml", "1", "medium")
}

// Inherited hostname evidence does not replace a root's pending direct support during redo.
func TestCandidates_RootAwaitingRedoKeepsItsRankDespiteItsHostnames(t *testing.T) {
	t.Parallel()
	early := newSrc("asn", finds("k1", nil))
	who := newSrc("whoisxml", finds("Acme", list(root("x.org"))))
	h := newHarness(t, early, who, newSrc("httpprobe", finds("a.com:443", list(host("www.x.org")))))
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "httpprobe;whoisxml", "2", "high")

	early.finds = finds("k1", nil, "k2", nil) // does work before whoisxml runs again
	who.finds = finds("Acme", nil)            // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "whoisxml"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	r := rowOf(t, h.table("a.com", "candidates.csv"), "x.org")
	if r["current"] != "false" {
		t.Fatalf("x.org should no longer be current: %v", r)
	}
	wantRow(t, r, "httpprobe;whoisxml", "2", "high")
}

// After a redo of a supporting procedure that no longer finds the candidate, the
// candidate drops a level.
func TestCandidates_RedoLowersALevel(t *testing.T) {
	t.Parallel()
	cs := newSrc("certspotter", finds("k", list(root("x.org"))))
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), cs)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "certspotter;whoisxml", "2", "high")

	cs.finds = finds("k", nil)
	if code := h.exec("-e", "a.com", "--redo", "certspotter"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "whoisxml", "1", "medium")
}

// Confidence follows the evidence of every run: a procedure that finds the
// candidate later raises it, with no redo.
func TestCandidates_RecomputedOnEveryRun(t *testing.T) {
	t.Parallel()
	cs := newSrc("certspotter", finds())
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), cs)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "whoisxml", "1", "medium")

	cs.finds = finds("k", list(root("x.org")))
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "certspotter;whoisxml", "2", "high")
}

// Without --org, registrant evidence receives no organisation-match confidence boost.
func TestCandidates_NoOrgInput(t *testing.T) {
	t.Parallel()
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "whoisxml", "1", "low")
}

// A candidate root also counts the evidence of the candidate hostnames under
// it; each hostname keeps its own rank.
func TestCandidates_HostnameEvidenceRaisesItsRoot(t *testing.T) {
	t.Parallel()
	h := newHarness(t,
		newSrc("whoisxml", finds("Acme", list(root("other.org")))),
		newSrc("httpprobe", finds("a.com:443", list(host("www.other.org")))),
	)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := h.table("a.com", "candidates.csv")
	wantRow(t, rowOf(t, rows, "other.org"), "httpprobe;whoisxml", "2", "high")
	wantRow(t, rowOf(t, rows, "www.other.org"), "httpprobe", "1", "low")
}

// Evidence removes settings from support identity so changed job settings cannot inflate
// confidence.
func TestCandidates_EvidencerSetsSourceAndItem(t *testing.T) {
	t.Parallel()
	probe := newSrc("httpprobe", finds("a.com:80", list(host("h1.other.org")), "a.com:443", list(host("h1.other.org"))))
	pv := pivot{newSrc("pivot", finds("crtsh:https://a.com|depth=2", list(host("h2.other.org")), "crtsh:https://a.com|depth=3", list(host("h2.other.org"))))}
	h := newHarness(t, probe, pv)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := h.table("a.com", "candidates.csv")
	wantRow(t, rowOf(t, rows, "h1.other.org"), "httpprobe", "2", "low") // two keys, two pairs
	wantRow(t, rowOf(t, rows, "h2.other.org"), "crtsh", "1", "low")     // two keys, one item, source named by the procedure
}

// A change to an evidence kind alone still re-derives the findings, with the
// candidate ranks unchanged.
func TestCandidates_FindingsStillDerivedWhenOnlyEvidenceChanges(t *testing.T) {
	t.Parallel()
	spf := ""
	posture := &testkit.Procedure{ProcedureName: "posture", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("p", 1) },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("email_posture", "a.com", "mx", "mail.a.com", "spf", spf, "spf_records", 0,
				"dmarc", "v=DMARC1; p=reject", "dmarc_policy", "reject")}, nil
		}}
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), posture)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	spfRows := func() []map[string]string {
		return slices.DeleteFunc(h.table("a.com", "risk-email.csv"), func(r map[string]string) bool { return r["type"] != "spf-missing" })
	}
	if rows := spfRows(); len(rows) != 1 || rows[0]["current"] != "true" {
		t.Fatalf("first run: spf-missing rows = %v\n%s", rows, h.readOut("a.com", "risk-email.csv"))
	}
	spf = "v=spf1 -all"
	if code := h.exec("-e", "a.com", "--redo", "posture"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if rows := spfRows(); len(rows) != 1 || rows[0]["current"] != "false" {
		t.Errorf("the finding is no longer derived once the evidence changes: %v", rows)
	}
	wantRow(t, rowOf(t, h.table("a.com", "candidates.csv"), "x.org"), "whoisxml", "1", "medium")
}

// highSet is 23 high candidates (a netblock and 22 roots), one medium root and
// one low root.
func highSet() []*src {
	roots := list()
	for i := range 22 {
		roots = append(roots, root(fmt.Sprintf("r%02d.org", i)))
	}
	return []*src{
		newSrc("whoisxml", finds("Acme", append(list(root("mid.org")), roots...))),
		newSrc("org-asn", finds("Acme", list(block("198.51.100.0/24")))),
		newSrc("certspotter", finds("k", roots)),
		newSrc("otx", finds("k", list(block("198.51.100.0/24"), root("low.org")))),
	}
}

func highHarness(t *testing.T) *harness {
	t.Helper()
	var procedures []run.Procedure
	for _, s := range highSet() {
		procedures = append(procedures, s)
	}
	return newHarness(t, procedures...)
}

// The console caps high-confidence candidates at 20 and includes promotion inputs and an
// overflow count.
func TestCandidates_ConsoleSummary(t *testing.T) {
	t.Parallel()
	h := highHarness(t)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	out := h.stdout.String()
	if !strings.Contains(out, "promote: --cidr 198.51.100.0/24") || !strings.Contains(out, "promote: r00.org") || !strings.Contains(out, "promote: r18.org") {
		t.Errorf("high candidates are listed with their promoting input:\n%s", out)
	}
	for _, v := range []string{"r19.org", "r20.org", "r21.org"} {
		if strings.Contains(out, v) {
			t.Errorf("%s is past the 20 listed:\n%s", v, out)
		}
	}
	if !strings.Contains(out, "and 3 more in candidates.csv") {
		t.Errorf("missing the overflow line:\n%s", out)
	}
	if strings.Contains(out, "mid.org") || strings.Contains(out, "low.org") {
		t.Errorf("medium and low candidates are not listed:\n%s", out)
	}
}

// JSON preserves ranked candidate order, source lists and total count while capping displayed
// entries.
func TestCandidates_JSONEnvelope(t *testing.T) {
	t.Parallel()
	h := highHarness(t)
	if code := h.exec("a.com", "--org", "Acme", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	d := h.envelope().Data
	if d.CandidatesTotal != 23 || len(d.Candidates) != 20 {
		t.Fatalf("%d candidates listed of %d, want 20 of 23", len(d.Candidates), d.CandidatesTotal)
	}
	var nb *report.CandidateRow
	for i, c := range d.Candidates {
		if c.Confidence != "high" {
			t.Errorf("only high candidates: %+v", c)
		}
		if c.Value == "198.51.100.0/24" {
			nb = &d.Candidates[i]
		}
	}
	if nb == nil || nb.Kind != "netblock" || nb.Promote != "--cidr 198.51.100.0/24" ||
		!slices.Equal(nb.Sources, []string{"org-asn", "otx"}) || nb.EvidenceCount != 2 {
		t.Errorf("netblock row = %+v", nb)
	}
	if got := len(ofType(h.events(), "candidate")); got != 0 {
		t.Errorf("%d candidate events: the candidates are in the envelope", got)
	}
	// The rest are in candidates.csv: 23 high rows in all.
	high := 0
	for _, r := range h.table("a.com", "candidates.csv") {
		if r["confidence"] == "high" {
			high++
		}
	}
	if high != 23 {
		t.Errorf("candidates.csv has %d high rows, want 23", high)
	}
}

// Procedure-declared and retired families remain grouped; undeclared sources stay independent.
func TestCandidates_FamiliesOfTheRealSources(t *testing.T) {
	t.Parallel()
	for source, want := range map[string]string{
		"crtsh": "certificate transparency", "certspotter": "certificate transparency", "censys": "certificate transparency",
		"ct-org": "certificate transparency", "wayback": "web archive", "commoncrawl": "web archive",
		"otx": "passive dns", "virustotal": "passive dns", "securitytrails": "passive dns", "shodan": "passive dns",
		"shodan-dns": "passive dns", "shodan-host": "passive dns",
		"chaos": "passive dns", "urlscan": "passive dns", "anubis": "passive dns", "hackertarget": "passive dns",
		"reverseip": "reverse ip",
		"rdap":      "registrant", "whoisxml": "registrant", "org-asn": "registrant",
		"shared-ns": "shared infrastructure", "shared-mx": "shared infrastructure",
		"identifier-pivot": "web identifier", "identifier-pivot:G-AAAAAA1": "web identifier",
		"httpprobe": "httpprobe", "rdns": "rdns", "crawl": "crawl", "jsparse": "jsparse",
		"spf": "spf",
	} {
		if got := realFamilies.Of(source); got != want {
			t.Errorf("family of %q = %q, want %q", source, got, want)
		}
	}
}

// New candidate sources need documentation so sources-column values stay discoverable.
func TestCandidates_DocsListEverySource(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	for _, s := range realFamilies.Sources() {
		if !strings.Contains(docs, "`"+s+"`") {
			t.Errorf("the docs do not list the candidate source `%s`", s)
		}
	}
}
