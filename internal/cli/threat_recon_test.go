package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/testkit"
)

// Recon DROP tests cover matching, origin-AS lookup, active-copy selection and fallback
// warnings.

// Keep built-in/download fixture dates within the harness clock's fresh window.
var (
	builtInAt    = time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	downloadedAt = time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC)
)

const (
	builtInDay    = "2026-10-20"
	downloadedDay = "2026-10-30"
)

// rowsOf are every row of the risk file for the address, current or not.
func (x *abWorld) rowsOf(addr string) []map[string]string {
	var out []map[string]string
	for _, r := range x.table(eng, abusiveFile) {
		if r["ip"] == addr {
			out = append(out, r)
		}
	}
	return out
}

// foundOf is the found event the last call announced for the abusive-network finding of the
// address, nil when there is none.
func (x *abWorld) foundOf(addr string) event {
	for _, e := range ofType(x.h.events(), "found") {
		if strings.HasSuffix(e.str("category"), "abusive-network") && e.str("value") == addr {
			return e
		}
	}
	return nil
}

// DROP networks produce high findings; ASN-DROP produces medium, with source details/dates in
// files and summary.
func TestThreatRecon_DropMatchesAreFindings(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("net.example.com", "asn.example.com", "both.example.com")
	x.host("net.example.com", "203.0.113.20")
	x.owner("203.0.113.20", 64500, "ACME-NET")
	x.host("asn.example.com", "192.0.2.10")
	x.owner("192.0.2.10", 64998, "BAD-AS")
	x.host("both.example.com", "203.0.113.40")
	x.owner("203.0.113.40", 64500, "ACME-NET")
	// The lists' timestamps are given in UTC+10: the risk file writes them in UTC.
	aest := time.FixedZone("AEST", 10*3600)
	x.h.drop = dropListsOn(t, time.Date(2026, 10, 20, 8, 30, 5, 0, aest), time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC),
		time.Date(2026, 10, 21, 23, 59, 59, 0, time.UTC),
		[]spamhaus.NetworkEntry{dropNet("203.0.113.0/27", "SBL5", "lacnic"), dropNet("203.0.113.16/28", "SBL6", "ripencc"), dropNet("203.0.113.40/32", "SBL7", "arin")},
		[]spamhaus.ASNEntry{dropASN(64998, "BAD-AS", "RU", "bad.example", "ripencc")})
	x.h.abusive = abSnapshotOn("2026-10-18", "2026-10-17",
		[]abusive.NetworkEntry{abNet(9, "203.0.113.40", "203.0.113.40", "High", 70, "Both Org", "isp")}, nil)
	x.mustPassive()

	net := x.row("203.0.113.20")
	if net["type"] != "drop-network" || net["severity"] != "high" {
		t.Errorf("203.0.113.20 = %v, want a high drop-network finding", net)
	}
	if want := "203.0.113.16/28 SBL6 (ripencc);203.0.113.0/27 SBL5 (lacnic)"; net["drop_networks"] != want {
		t.Errorf("drop_networks = %q, want %q (the most specific first)", net["drop_networks"], want)
	}
	if net["drop_networks_updated"] != "2026-10-19T22:30:05Z" || net["drop_asn"] != "" || net["drop_asn_updated"] != "" {
		t.Errorf("203.0.113.20 = %v, want DROP's date in RFC 3339 UTC and no ASN-DROP entry", net)
	}
	asn := x.row("192.0.2.10")
	if asn["type"] != "drop-asn" || asn["severity"] != "medium" || asn["drop_networks"] != "" {
		t.Errorf("192.0.2.10 = %v, want a medium drop-asn finding", asn)
	}
	if asn["drop_asn"] != "AS64998 BAD-AS RU bad.example (ripencc)" || asn["drop_asn_updated"] != "2026-10-21T23:59:59Z" {
		t.Errorf("192.0.2.10 = %v, want the ASN-DROP entry and its list's date", asn)
	}
	both := x.row("203.0.113.40")
	if both["type"] != "drop-network" || both["severity"] != "high" || both["drop_networks"] != "203.0.113.40/32 SBL7 (arin)" ||
		!strings.Contains(both["networks"], "Both Org") || both["networks_updated"] != "2026-10-18" {
		t.Errorf("203.0.113.40 = %v, want one drop-network finding naming both lists' entries", both)
	}
	if n := len(x.rowsOf("203.0.113.40")); n != 1 {
		t.Errorf("203.0.113.40 has %d rows, want one finding", n)
	}
	targets := map[string]string{}
	for _, f := range summaryFindingsOf(x.h) {
		if f["category"] == "abusive-network" {
			targets[f["target"].(string)] = f["severity"].(string)
		}
	}
	for addr, sev := range map[string]string{"203.0.113.20": "high", "192.0.2.10": "medium", "203.0.113.40": "high"} {
		if targets[addr] != sev {
			t.Errorf("the summary has %s as %q, want %s: %v", addr, targets[addr], sev, targets)
		}
	}
	if e := x.foundOf("203.0.113.20"); e == nil || e.str("severity") != "high" ||
		e.str("text") != "address 203.0.113.20 in Spamhaus DROP network 203.0.113.16/28 (SBL6)" {
		t.Errorf("found event = %v", e)
	}
}

// ASN-DROP uses the same address/unit ownership lookup as abuse-AS matching.
func TestThreatRecon_TheOriginASIsCheckedAgainstASNDrop(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("app.example.com")
	x.host("app.example.com", "192.0.2.10")
	x.owner("192.0.2.10", 64998, "BAD-AS")
	x.dns.PTR("198.51.100.5", "p5.example.com")
	x.dns.PTR("198.51.100.9", "p9.example.com")
	x.origin("198.51.100.0", 64999)
	x.dns.PTR("198.51.101.5", "q5.example.com")
	x.origin("198.51.101.0", 64500) // not listed
	x.h.drop = dropListsAt(t, builtInAt, nil, []spamhaus.ASNEntry{
		dropASN(64998, "BAD-AS", "RU", "bad.example", "ripencc"), dropASN(64999, "WORSE-AS", "NL", "worse.example", "ripencc")})
	x.mustPassive("--cidr", "198.51.100.0/23")
	want := []string{"192.0.2.10=medium", "198.51.100.5=medium", "198.51.100.9=medium"}
	if got := x.flagged(); !slices.Equal(got, want) {
		t.Errorf("flagged %v, want %v", got, want)
	}
	for _, addr := range []string{"198.51.100.5", "198.51.100.9"} {
		if r := x.row(addr); r["type"] != "drop-asn" || r["drop_asn"] != "AS64999 WORSE-AS NL worse.example (ripencc)" {
			t.Errorf("%s = %v, want the unit's AS64999 as a drop-asn finding", addr, r)
		}
	}
	if r := x.row("192.0.2.10"); r["type"] != "drop-asn" || !strings.HasPrefix(r["drop_asn"], "AS64998 BAD-AS") {
		t.Errorf("192.0.2.10 = %v, want its AS64998 as a drop-asn finding", r)
	}
}

// nyx help findings lists the two DROP types with the other finding types and their severities.
func TestThreatHelp_FindingsListTheDropTypes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, cli.DefaultDeps().Procedures...)
	if code := h.execRoot("help", "findings"); code != 0 {
		t.Fatalf("help findings: exit %d", code)
	}
	want := map[string]string{"drop-network": "high", "drop-asn": "medium", "network": "medium", "asn": "low"}
	got := map[string]string{}
	for line := range strings.SplitSeq(h.stdout.String(), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "abusive-network" {
			got[f[1]] = f[2]
		}
	}
	for typ, sev := range want {
		if got[typ] != sev {
			t.Errorf("nyx help findings lists abusive-network %s as %q, want %s:\n%s", typ, got[typ], sev, h.stdout.String())
		}
	}
}

// New local data updates, escalates, downgrades or retires one stable finding per address
// without requests.
func TestThreatRecon_ANewerCopyReachesTheNextRun(t *testing.T) { // mutation target
	t.Parallel()
	x := newAbWorld(t)
	x.names("rise.example.com", "weak.example.com", "gone.example.com")
	for h, a := range map[string]string{"rise.example.com": "203.0.113.1", "weak.example.com": "203.0.113.2", "gone.example.com": "203.0.113.3"} {
		x.host(h, a)
		x.owner(a, 64500, "ACME-NET")
	}
	canaries := newThreatCanaries(t, x.h)
	// Built in: ipapi.is lists .1 and .2; DROP holds .2 and .3.
	x.h.abusive = abSnapshotOn(builtInDay, builtInDay, []abusive.NetworkEntry{
		abNet(1, "203.0.113.1", "203.0.113.1", "High", 70, "Rise Org", "isp"),
		abNet(2, "203.0.113.2", "203.0.113.2", "High", 71, "Weak Org", "isp"),
	}, nil)
	x.h.drop = dropListsAt(t, builtInAt, []spamhaus.NetworkEntry{dropNet("203.0.113.2/32", "SBL2002", "ripencc"), dropNet("203.0.113.3/32", "SBL2003", "ripencc")}, nil)
	x.mustPassive()
	if got, want := x.flagged(), []string{"203.0.113.1=medium", "203.0.113.2=high", "203.0.113.3=high"}; !slices.Equal(got, want) {
		t.Fatalf("after run 1: %v, want %v", got, want)
	}
	queries, hits := x.dns.Total(), x.h.network()

	// Downloaded, and newer: DROP holds only .1.
	writeDownloadedDrop(t, x.h, downloadedAt, []spamhaus.NetworkEntry{dropNet("203.0.113.1/32", "SBL3001", "ripencc")}, nil)
	x.mustPassive()
	if got := x.dns.Total() - queries; got != 0 {
		t.Errorf("the second run sent %d DNS queries, want none", got)
	}
	if x.h.network() != hits {
		t.Error("a network canary was hit by the second run")
	}
	canaries.untouched(t, "the second run")
	if r := x.row("203.0.113.1"); r == nil || r["type"] != "drop-network" || r["severity"] != "high" || r["drop_networks"] != "203.0.113.1/32 SBL3001 (ripencc)" {
		t.Errorf("203.0.113.1 (risen) = %v, want a current high drop-network finding", r)
	}
	if e := x.foundOf("203.0.113.1"); e == nil || e.str("severity") != "high" {
		t.Errorf("the rise of 203.0.113.1 was not announced as high: %v (announced %v)", e, x.foundFindings())
	}
	weak := x.rowsOf("203.0.113.2")
	if len(weak) != 1 || weak[0]["current"] != "true" || weak[0]["type"] != "network" || weak[0]["severity"] != "medium" {
		t.Errorf("203.0.113.2 (weakened) = %v, want one current medium network finding", weak)
	}
	if e := x.foundOf("203.0.113.2"); e != nil {
		t.Errorf("the weakened finding was announced: %v", e)
	}
	if r := x.rowsOf("203.0.113.3"); len(r) != 1 || r[0]["current"] != "false" {
		t.Errorf("203.0.113.3 (no match left) = %v, want one finding that is not current", r)
	}
}

// Load threat data once per run so replacements affect only later runs.
func TestThreatRecon_ARunUsesTheDataItStartedWith(t *testing.T) { // mutation target
	t.Parallel()
	x := newAbWorld(t)
	x.names("first.example.com", "second.example.com")
	x.host("first.example.com", "203.0.113.7")
	x.host("second.example.com", "203.0.113.8")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.owner("203.0.113.8", 64500, "ACME-NET")
	x.h.drop = dropListsAt(t, builtInAt, nil, nil)
	writeDownloadedDrop(t, x.h, downloadedAt, []spamhaus.NetworkEntry{dropNet("203.0.113.7/32", "SBL7007", "arin")}, nil)
	later := downloadedAt.Add(24 * time.Hour)
	rewrite := &testkit.Procedure{ProcedureName: "rewrite", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return []run.Job{{Key: "rewrite"}} },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			writeDownloadedDrop(t, x.h, later, []spamhaus.NetworkEntry{dropNet("203.0.113.8/32", "SBL8008", "arin")}, nil)
			return []run.Observation{{Kind: "hostname", Key: "late.example.com"}}, nil
		}}
	x.h.procedures = append(x.h.procedures, rewrite)
	x.mustPassive()
	if b, err := os.ReadFile(filepath.Join(threatDir(x.h), "spamhaus.jsonl")); err != nil || !strings.Contains(string(b), "SBL8008") {
		t.Fatalf("the stage did not rewrite the downloaded copy (%v)", err)
	}
	if got, want := x.flagged(), []string{"203.0.113.7=high"}; !slices.Equal(got, want) {
		t.Errorf("after the run that rewrote the copy: %v, want %v (the copy loaded at the start)", got, want)
	}
	// The next run loads the rewritten copy.
	x.mustPassive()
	if got, want := x.flagged(), []string{"203.0.113.8=high"}; !slices.Equal(got, want) {
		t.Errorf("after the next run: %v, want %v", got, want)
	}
}

// Export preserves last-run findings without reading threat data or warning about later
// corruption.
func TestThreatRecon_ExportReadsNoThreatData(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.h.drop = dropListsAt(t, builtInAt, nil, nil)
	writeDownloadedDrop(t, x.h, downloadedAt, []spamhaus.NetworkEntry{dropNet("203.0.113.7/32", "SBL7007", "arin")}, nil)
	x.mustPassive()
	if got, want := x.flagged(), []string{"203.0.113.7=high"}; !slices.Equal(got, want) {
		t.Fatalf("after the run: %v, want %v", got, want)
	}
	writeThreatFile(t, x.h, "spamhaus.jsonl", "this is not a bundle\n")
	writeThreatFile(t, x.h, "ipapi.json", "{")
	for _, args := range [][]string{{"-e", eng, "--kind", "finding"}, {"-e", eng, "--kind", "finding", "--json"}} {
		e := export(x.h, args...)
		if e.code != 0 {
			t.Fatalf("export %v: exit %d: %s", args, e.code, e.stderr)
		}
		if strings.Contains(e.stderr, "unreadable") || strings.Contains(e.stderr, "--update-threat-data") || strings.Contains(e.stdout, "unreadable") {
			t.Errorf("export %v said something of the threat data:\nstdout %s\nstderr %s", args, e.stdout, e.stderr)
		}
	}
	e := export(x.h, "-e", eng, "--kind", "finding")
	var got []string
	for _, l := range e.lines(t) {
		if ip, ok := strings.CutPrefix(l.str("key"), "abusive-network|"); ok && l["current"] == true {
			got = append(got, ip+"="+strings.TrimSpace(anyString(l.attrs()["type"])))
		}
	}
	if want := []string{"203.0.113.7=drop-network"}; !slices.Equal(got, want) {
		t.Errorf("exported current abusive-network findings %v, want %v", got, want)
	}
}

func anyString(v any) string { s, _ := v.(string); return s }

// unreadableDrop supplies newer corrupt downloads with an address absent from built-ins.
var unreadableDrop = []struct{ name, body string }{
	{"not a bundle", "this is not a bundle\n"},
	{"drop_v6 without its metadata row", dropBundleText(
		dropFileText(downloadedAt, dropRows([]spamhaus.NetworkEntry{dropFillerV4, dropNet("203.0.113.6/32", "SBL6006", "arin")})),
		strings.Join(dropRows([]spamhaus.NetworkEntry{dropFillerV6}), "\n")+"\n",
		dropFileText(downloadedAt, asnDropRows([]spamhaus.ASNEntry{dropFillerASN})))},
	{"an entry listed twice", dropBundleText(
		dropFileText(downloadedAt, dropRows([]spamhaus.NetworkEntry{dropFillerV4, dropNet("203.0.113.6/32", "SBL6006", "arin"), dropNet("203.0.113.6/32", "SBL6006", "arin")})),
		dropFileText(downloadedAt, dropRows([]spamhaus.NetworkEntry{dropFillerV6})),
		dropFileText(downloadedAt, asnDropRows([]spamhaus.ASNEntry{dropFillerASN})))},
}

// unreadableIpapi supplies newer corrupt downloads with an address absent from built-ins.
var unreadableIpapi = []struct {
	name string
	snap abusive.Snapshot
}{
	{"under 90% of the stated count", abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: downloadedDay, Stated: 10, Entries: []abusive.NetworkEntry{abNet(1, "203.0.113.6", "203.0.113.6", "High", 70, "New Org", "isp")}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: downloadedDay, Stated: 1, Entries: []abusive.ASNEntry{abASN(2, 64999, "High", 70, "New AS", "isp")}}}},
	{"a control character", abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: downloadedDay, Stated: 1, Entries: []abusive.NetworkEntry{abNet(1, "203.0.113.6", "203.0.113.6", "High", 70, "New\x07 Org", "isp")}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: downloadedDay, Stated: 1, Entries: []abusive.ASNEntry{abASN(2, 64999, "High", 70, "New AS", "isp")}}}},
}

// fallbackWorld is a world whose built-in copies list 203.0.113.5 (DROP and ipapi.is), with
// hostnames for it and for 203.0.113.6.
func fallbackWorld(t *testing.T) *abWorld {
	t.Helper()
	x := newAbWorld(t)
	x.names("old.example.com", "new.example.com")
	x.host("old.example.com", "203.0.113.5")
	x.host("new.example.com", "203.0.113.6")
	x.owner("203.0.113.5", 64500, "ACME-NET")
	x.owner("203.0.113.6", 64500, "ACME-NET")
	x.h.abusive = abSnapshotOn(builtInDay, builtInDay, []abusive.NetworkEntry{abNet(1, "203.0.113.5", "203.0.113.5", "High", 70, "Old Org", "isp")}, nil)
	x.h.drop = dropListsAt(t, builtInAt, []spamhaus.NetworkEntry{dropNet("203.0.113.5/32", "SBL5005", "arin")}, nil)
	return x
}

// Fallback matches built-ins and warns once until an update installs a valid bundle.
func TestThreatRecon_AnUnreadableCopyFallsBackToTheBuiltInOne(t *testing.T) {
	t.Parallel()
	check := func(t *testing.T, x *abWorld, source, typ string, good func()) {
		t.Helper()
		x.mustPassive()
		if r := x.row("203.0.113.5"); r == nil || r["type"] != typ {
			t.Errorf("203.0.113.5 = %v, want the built-in copy's %s finding", r, typ)
		}
		if r := x.row("203.0.113.6"); r != nil && r["type"] == typ {
			t.Errorf("203.0.113.6 = %v: the unreadable copy was used", r)
		}
		warns := x.h.envelope().Meta.Warnings
		var hits []string
		for _, w := range warns {
			if strings.Contains(w, "unreadable") {
				hits = append(hits, w)
			}
		}
		if len(hits) != 1 || !isUnreadableWarning(hits[0], source, threatDir(x.h)) {
			t.Errorf("meta.warnings = %q, want one warning of the unreadable %s copy in %s", warns, source, threatDir(x.h))
		}
		if l := unreadableLines(x.h); len(l) != 0 {
			t.Errorf("under --json the warning is on stderr: %q", l)
		}
		// An update writes a good copy: the next run uses it and does not warn.
		good()
		x.mustPassive()
		for _, w := range x.h.envelope().Meta.Warnings {
			if strings.Contains(w, "unreadable") {
				t.Errorf("after a good copy, meta.warnings still has %q", w)
			}
		}
		if r := x.row("203.0.113.6"); r == nil || r["type"] != typ {
			t.Errorf("203.0.113.6 = %v after a good copy, want the downloaded copy's %s finding", r, typ)
		}
	}
	for _, c := range unreadableDrop {
		t.Run("spamhaus "+c.name, func(t *testing.T) {
			t.Parallel()
			x := fallbackWorld(t)
			writeThreatFile(t, x.h, "spamhaus.jsonl", c.body)
			check(t, x, "spamhaus", "drop-network", func() {
				writeDownloadedDrop(t, x.h, downloadedAt, []spamhaus.NetworkEntry{dropNet("203.0.113.6/32", "SBL6006", "arin")}, nil)
			})
		})
	}
	for _, c := range unreadableIpapi {
		t.Run("ipapi.is "+c.name, func(t *testing.T) {
			t.Parallel()
			x := fallbackWorld(t)
			x.h.drop = dropListsAt(t, builtInAt, nil, nil) // so that ipapi.is's match is the finding's type
			writeAbusiveSnapshot(t, x.h, c.snap)
			check(t, x, "ipapi.is", "network", func() {
				writeDownloadedAbusive(t, x.h, downloadedDay, downloadedDay,
					[]abusive.NetworkEntry{abNet(1, "203.0.113.6", "203.0.113.6", "High", 70, "New Org", "isp")},
					[]abusive.ASNEntry{abASN(2, 64999, "High", 70, "New AS", "isp")})
			})
		})
	}
}

// In the human layout, the warning is one line on stderr for each unreadable source, also under
// --quiet; recon export does not warn.
func TestThreatRecon_TheWarningIsPrintedOnceEvenUnderQuiet(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	writeThreatFile(t, h, "spamhaus.jsonl", "this is not a bundle\n")
	writeThreatFile(t, h, "ipapi.json", "{")
	for _, args := range [][]string{{"example.com"}, {"example.com", "--quiet"}} {
		if code := h.exec(args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, h.stderr.String())
		}
		lines := unreadableLines(h)
		if len(lines) != 2 {
			t.Errorf("%v: %d warning lines, want one for each source:\n%s", args, len(lines), h.stderr.String())
			continue
		}
		var spam, ipapi int
		for _, m := range h.logMsgs("WARN") {
			if isUnreadableWarning(m, "spamhaus", threatDir(h)) {
				spam++
			}
			if isUnreadableWarning(m, "ipapi.is", threatDir(h)) {
				ipapi++
			}
		}
		if spam != 1 || ipapi != 1 {
			t.Errorf("%v: %d Spamhaus and %d ipapi.is warnings, want one each:\n%s", args, spam, ipapi, h.stderr.String())
		}
	}
	h.execRoot("recon", "export", "-e", "example.com", "--output-dir", h.out)
	if l := unreadableLines(h); len(l) != 0 {
		t.Errorf("recon export warned: %q", l)
	}
}

// Missing base directories select embedded data silently, regardless of age.
func TestThreatRecon_NoDirectoryUsesTheBuiltInCopy(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.h.abusive = abSnapshotOn(staleIpapiNets, staleIpapiASNs, nil, nil)
	x.h.drop = staleDrop(t, []spamhaus.NetworkEntry{dropNet("203.0.113.7/32", "SBL7007", "arin")}, nil)
	writeThreatFile(t, x.h, "spamhaus.jsonl", "this is not a bundle\n") // where the directory was: never read
	x.h.setenv("XDG_CONFIG_HOME", "")
	x.h.setenv("HOME", "")
	x.mustPassive()
	if got, want := x.flagged(), []string{"203.0.113.7=high"}; !slices.Equal(got, want) {
		t.Errorf("flagged %v, want %v (the built-in copy)", got, want)
	}
	if w := x.h.envelope().Meta.Warnings; len(w) != 0 {
		t.Errorf("meta.warnings = %q, want none", w)
	}
	if s := x.h.stderr.String(); strings.Contains(s, "threat") || strings.Contains(s, "unreadable") {
		t.Errorf("stderr = %q", s)
	}
}
