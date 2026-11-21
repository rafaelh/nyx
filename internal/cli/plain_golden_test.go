package cli_test

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// Output that is not written to a terminal is what scripts and saved logs read, so its bytes are
// pinned here: each test below captures the output of a fixture-driven run on streams that are
// not terminals and compares it with a file under testdata/plain. Every capture is made twice,
// the second time with colour variables set, which must change nothing off a terminal.
//
// To rewrite the files after a deliberate change to that output:
//
//	go test ./internal/cli/ -run 'TestPlain_' -update-plain
var updatePlain = flag.Bool("update-plain", false, "rewrite the files under testdata/plain instead of comparing with them")

// outPlaceholder stands for the harness's temporary output directory in a golden file.
const outPlaceholder = "<OUTPUT-DIR>"

// colourVariants are the environments a capture is made in: the harness's own, and one that would
// turn on the richest colour on a terminal.
var colourVariants = []struct {
	name string
	env  map[string]string
}{
	{"the harness's environment", nil},
	{"COLORTERM=truecolor and TERM=xterm-256color", map[string]string{"COLORTERM": "truecolor", "TERM": "xterm-256color"}},
}

// goldenPlain runs capture once for each colour variant, requires the same bytes from both, and
// compares them with testdata/plain/<name>.txt (or rewrites the file under -update-plain).
// capture builds its own harness, calls tune on it before its first command, and returns what it
// read, with the harness for its output directory, which is written as <OUTPUT-DIR> in both the
// file and the comparison so that the file holds nothing that belongs to one machine.
func goldenPlain(t *testing.T, name string, capture func(tune func(*harness)) (*harness, string)) {
	t.Helper()
	var want string
	for i, v := range colourVariants {
		h, got := capture(func(h *harness) {
			for k, val := range v.env {
				h.setenv(k, val)
			}
		})
		if h.stdoutTTY || h.stderrTTY {
			t.Fatal("a plain capture must not be on a terminal")
		}
		got = strings.ReplaceAll(got, h.out, outPlaceholder)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Errorf("%s: output with %s differs from the harness's environment\n got: %q\nwant: %q", name, v.name, got, want)
		}
	}
	path := filepath.Join("testdata", "plain", name+".txt")
	if *updatePlain {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-plain to create it)", err)
	}
	if want != string(golden) {
		t.Errorf("%s differs from the recorded output\n got: %q\nwant: %q", path, want, golden)
	}
}

// noting is a stage that adds lines to the summary's notes.
type noting struct {
	*src
	notes []string
}

func (n noting) Notes(run.View) []string { return n.notes }

// longHost is a host name long enough to push a finding line past 100 columns.
const longHost = "customer-portal-staging-environment-eu-west.internal-services.division-alpha.example-holdings.a.com"

// summaryWorld is the stages of the runs whose summaries are captured, and what each says on the
// second run. The first run sees only the first key of crtsh and so has no changes to report.
type summaryWorld struct {
	h                          *harness
	crtsh, otx, wayback, spots *src
	shodan                     *src
}

func newSummaryWorld(t *testing.T, tune func(*harness)) *summaryWorld {
	t.Helper()
	w := &summaryWorld{
		crtsh:   newSrc("crtsh", finds("k1", list(host("www.a.com"), host("old.a.com"), certSvc("old.a.com", "2026-10-15")))),
		otx:     newSrc("otx", finds()),
		wayback: newSrc("wayback", finds()),
		spots:   newSrc("certspotter", finds()),
		shodan:  newSrc("shodan-host", finds()),
	}
	flaky := erring("flaky", 2, errors.New("source unavailable"))
	spread := budgeted(2, func(run.View) []run.Check { return costed(1, 1, 1, 1, 1) })
	notes := noting{src: newSrc("notes", finds()), notes: []string{
		"shodan: 3 hosts were not looked up (quota)", "permutations: the list was cut at 1000 names"}}
	w.h = newHarness(t, w.crtsh, w.otx, w.wayback, w.spots, w.shodan, flaky, spread, notes)
	tune(w.h)
	return w
}

// secondDay adds what the second run finds: new hosts, certificates, email posture and reported
// ports that make findings, and more high-confidence candidates than the summary lists.
func (w *summaryWorld) secondDay() {
	w.crtsh.finds = finds(
		"k1", list(host("www.a.com"), host("old.a.com"), certSvc("old.a.com", "2026-10-15")),
		"k2", list(host(longHost), certSvc(longHost, "2026-09-30"), host("shop.a.com"), webSvc("https://shop.a.com", "shop.a.com")),
		"mail", list(obs("email_posture", "a.com", "mx", "mail.a.com", "spf", "v=spf1 +all", "spf_all", "+all", "dmarc", "", "mta_sts", "present")),
		"cands", w.candidates(23, "crtsh"))
	w.otx.finds = finds("cands", w.candidates(23, "otx"))
	w.wayback.finds = finds("cands", w.candidates(23, "wayback"))
	w.spots.finds = finds("cands", w.candidates(23, "certspotter"))
	w.shodan.finds = finds("ports", list(
		obs("reported_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", "rdp"),
		obs("reported_port", "198.51.100.6:445", "ip", "198.51.100.6", "port", 445, "banner", "smb")))
	w.h.now = w.h.now.Add(24 * time.Hour)
}

// candidates are n roots and n/2 netblocks as one source sees them. Every source sees all of them
// except that certspotter sees only the first five roots, so most candidates have three sources
// and a few have four.
func (w *summaryWorld) candidates(n int, source string) []run.Observation {
	var out []run.Observation
	for i := range n {
		if source == "certspotter" && i >= 5 {
			break
		}
		out = append(out, root(fmt.Sprintf("holding-%02d.example.org", i)))
	}
	for i := range n / 2 {
		if source == "certspotter" {
			break
		}
		out = append(out, block(fmt.Sprintf("203.0.%d.0/24", i)))
	}
	return out
}

func (w *summaryWorld) run(t *testing.T, want int, args ...string) {
	t.Helper()
	args = append([]string{"a.com", "--cidr", "198.51.100.0/24", "--concurrency", "1"}, args...)
	if code := w.h.exec(args...); code != want {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, want, w.h.stdout.String(), w.h.stderr.String())
	}
}

// The summary of a first run has no changes block.
func TestPlain_SummaryFirstRun(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "summary-first-run", func(tune func(*harness)) (*harness, string) {
		w := newSummaryWorld(t, tune)
		w.run(t, 7)
		return w.h, w.h.stdout.String()
	})
}

// The summary of a second run has every block: counts, the unconfirmed risky ports line, notes,
// failed and deferred checks, findings of both severities (one with a long target), candidates
// with more than the summary lists, and the changes with their new findings.
func TestPlain_SummaryEveryBlock(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "summary-every-block", func(tune func(*harness)) (*harness, string) {
		w := newSummaryWorld(t, tune)
		w.run(t, 7)
		w.secondDay()
		w.run(t, 7)
		out := w.h.stdout.String()
		for _, block := range []string{"Summary", "risky ports reported by Shodan, unconfirmed", "permutations: the list was cut",
			"Failed checks", "Deferred to the next run", "Findings (high and medium)", "Candidates worth promoting",
			"and 14 more in candidates.csv", "Since last run", "New findings (high and medium)"} {
			if !strings.Contains(out, block) {
				t.Errorf("the summary lacks %q:\n%s", block, out)
			}
		}
		return w.h, out
	})
}

// A run the deadline ended says so in the summary, with the failed checks beside it.
func TestPlain_SummaryDeadline(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "summary-deadline", func(tune func(*harness)) (*harness, string) {
		h := newHarness(t, erring("flaky", 1, errors.New("boom")), blocking("permutations", 2, 3))
		tune(h)
		if code := h.exec("a.com", "--timeout", "400ms", "--concurrency", "5"); code != 7 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		out := h.stdout.String()
		if !strings.Contains(out, "Stopped by the deadline: 3 checks completed, 3 cancelled") {
			t.Errorf("the summary lacks the deadline line:\n%s", out)
		}
		return h, out
	})
}

// longWarning is a warning of 800 characters with a hostname and a URL in it.
var longWarning = func() string {
	w := "the source answered slowly for api.example.com and https://status.example.com/incidents/2026/11/01/degraded-performance-eu-west, so "
	for len(w) < 800 {
		w += "many of the lookups were retried after a long wait and a few were given up on; "
	}
	return w[:800]
}()

// newLogWorld is a run that writes every kind of log line: the run header, a stage in each state,
// found lines of each form, counts, warnings (one long and one of several lines) and, under
// --debug, the failures of checks.
func newLogWorld(t *testing.T, tune func(*harness)) *harness {
	t.Helper()
	crtsh := newSrc("crtsh", finds("k1", list(
		host("www.a.com"), host("old.a.com"), certSvc("old.a.com", "2026-10-15"), webSvc("https://www.a.com", "www.a.com"),
		obs("third_party", "a.com|mx|google.com", "root", "a.com", "mechanism", "mx", "domain", "google.com", "provider", "Google Workspace", "depth", 0),
		obs("open_port", "198.51.100.5:22", "ip", "198.51.100.5", "port", 22, "banner", "SSH-2.0-OpenSSH_9.6"),
		obs("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", ""),
		obs("email_posture", "a.com", "mx", "mail.a.com", "spf", "v=spf1 +all", "spf_all", "+all", "dmarc", "v=DMARC1; p=reject", "mta_sts", "present"))))
	warner := &testkit.Stage{StageName: "warner", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			v.Warn("quota is low")
			v.Warn("%s", longWarning)
			v.Warn("a warning with a line break\nand control characters\x07 that are sanitised away")
			return testkit.Keys("w", 1)
		}}
	keyless := &testkit.Stage{StageName: "shodan", Kind: run.ThirdParty,
		ConfiguredFn: func(run.Env) (bool, string) { return false, "no key" }}
	failing := erring("flaky", 2, errors.New("source unavailable: HTTP 503"))
	h := newHarness(t, crtsh, warner, failing, keyless)
	tune(h)
	return h
}

func (h *harness) logRun(t *testing.T, args ...string) {
	t.Helper()
	args = append([]string{"a.com", "--cidr", "198.51.100.0/24", "--concurrency", "1"}, args...)
	if code := h.exec(args...); code != 7 {
		t.Fatalf("exit %d\nstderr %s", code, h.stderr.String())
	}
}

// The log lines of a first run: the header, stages that are running, done, failed and not
// configured, found lines with and without a severity badge, counts, warnings, and the error
// that ends the run.
func TestPlain_LogFirstRun(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "log-first-run", func(tune func(*harness)) (*harness, string) {
		h := newLogWorld(t, tune)
		h.logRun(t)
		return h, h.stderr.String()
	})
}

// The log lines of a second run: stages whose checks were all completed before are done
// previously.
func TestPlain_LogSecondRun(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "log-second-run", func(tune func(*harness)) (*harness, string) {
		h := newLogWorld(t, tune)
		h.logRun(t)
		h.logRun(t)
		return h, h.stderr.String()
	})
}

// --debug adds a line for each failed check, ahead of the rest.
func TestPlain_LogDebug(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "log-debug", func(tune func(*harness)) (*harness, string) {
		h := newLogWorld(t, tune)
		h.logRun(t, "--debug")
		return h, h.stderr.String()
	})
}

// The palette sheet.
func TestPlain_PaletteSheet(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "palette-sheet", func(tune func(*harness)) (*harness, string) {
		h := newHarness(t)
		tune(h)
		if code := h.execRoot("recon", "--palette"); code != 0 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		if h.stderr.Len() != 0 {
			t.Errorf("stderr %q", h.stderr.String())
		}
		return h, h.stdout.String()
	})
}

// The error line, with its hint, for failures of both commands: nothing on stdout, and the error
// as the only thing on stderr.
func TestPlain_ErrorLines(t *testing.T) {
	t.Parallel()
	goldenPlain(t, "error-lines", func(tune func(*harness)) (*harness, string) {
		h := newHarness(t, noop())
		tune(h)
		var b strings.Builder
		for _, c := range []struct {
			want int
			args []string
		}{
			{2, []string{"recon", "--output-dir", h.out}},
			{2, []string{"recon", "--output-dir", h.out, "a.com", "--timeout", "abc", "--concurrency", "0"}},
			{2, []string{"cve", "--fields", "bogus", "CVE-2024-0001"}},
			{2, []string{"cve", "not-an-id"}},
		} {
			code := h.execRoot(c.args...)
			if code != c.want || h.stdout.Len() != 0 {
				t.Fatalf("%v: exit %d, stdout %q, stderr %q", c.args, code, h.stdout.String(), h.stderr.String())
			}
			fmt.Fprintf(&b, "$ nyx %s\n%s", strings.Join(c.args, " "), h.stderr.String())
		}
		return h, b.String()
	})
}

// longDescription is an NVD description of about 700 characters, with a URL in it.
const longDescription = "A flaw in the request parser of the Example Gateway allows a remote, unauthenticated attacker to " +
	"send a crafted sequence of chunked requests that desynchronise the front end and the back end, which can lead to " +
	"request smuggling, cache poisoning and the disclosure of other users' sessions. The flaw is present when the " +
	"optional streaming module is enabled, which it is by default on installations created before version 4.2. " +
	"Exploitation has been seen in the wild against the management interface; see https://advisories.example.com/2024/example-gateway-request-smuggling " +
	"for the vendor's analysis, indicators of compromise and the steps to take until a fixed release is installed. " +
	"Workarounds that disable the streaming module reduce but do not remove the exposure."

// richEntry is an NVD entry that fills every part of a record: a long description, a severity,
// weaknesses of different lengths, products with every kind of version bound, and references,
// some with tags and some with URLs longer than the width.
func richEntry() string {
	product := func(vendor, name, version, bounds string) string {
		return fmt.Sprintf(`{"vulnerable":true,"criteria":"cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*"%s}`, vendor, name, version, bounds)
	}
	products := strings.Join([]string{
		product("example", "gateway", "*", `,"versionStartIncluding":"4.0.0","versionEndExcluding":"4.2.7"`),
		product("example", "gateway", "*", `,"versionStartExcluding":"3.9.9","versionEndIncluding":"3.9.14"`),
		product("example", "gateway_streaming_module_for_enterprise_deployments", "2.0.1", ""),
		product("international_business_corporation_of_example_holdings", "management_console_and_reporting_suite_enterprise_edition", "*",
			`,"versionStartIncluding":"10.0.0.1000","versionEndExcluding":"10.4.2.2024110101"`),
		product("acme", "widget", "-", ""),
	}, ",")
	refs := []string{
		`{"url":"https://advisories.example.com/2024/example-gateway-request-smuggling","tags":["Vendor Advisory","Patch"]}`,
		`{"url":"https://github.com/example-org/example-gateway/commit/0123456789abcdef0123456789abcdef01234567#diff-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tags":["Patch","Third Party Advisory","Issue Tracking"]}`,
		`{"url":"https://example.com/writeup"}`,
		`{"url":"https://www.openwall.com/lists/oss-security/2024/11/02/1","tags":["Mailing List"]}`,
		`{"url":"https://nvd.example.net/redirect?target=https%3A%2F%2Fexample.org%2Fvery%2Flong%2Fpath%2Fthat%2Fkeeps%2Fgoing%2Fand%2Fgoing%2Fand%2Fgoing%2Fforever&token=abcdefghijklmnopqrstuvwxyz","tags":["Exploit","Technical Description"]}`,
	}
	return fmt.Sprintf(`{"id":"CVE-2024-10001","vulnStatus":"Analyzed","published":"2024-11-02T14:15:07.123","lastModified":"2025-02-20T19:20:44.907",`+
		`"descriptions":[{"lang":"en","value":%q}],`+
		`"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1",`+
		`"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0,"baseSeverity":"CRITICAL"}}]},`+
		`"weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[`+
		`{"lang":"en","value":"CWE-444"},{"lang":"en","value":"CWE-79: Improper Neutralisation of Input During Web Page Generation ('Cross-site Scripting') when the response is cached by an intermediary"},`+
		`{"lang":"en","value":"NVD-CWE-Other"}]}],`+
		`"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[%s]}]}],`+
		`"references":[%s]}`, longDescription, products, strings.Join(refs, ","))
}

// bareEntry is an NVD entry with nothing but an ID and a status: no description, no score, no
// weaknesses, products or references, so its severity is null.
const bareEntry = `{"id":"CVE-2024-10002","vulnStatus":"Awaiting Analysis","published":"2024-11-10T00:15:00.000","lastModified":"2024-11-10T00:15:00.000",` +
	`"descriptions":[],"references":[]}`

// cveShapes are the --fields values whose layouts are captured; "" is no flag.
var cveShapes = []string{"", "all", "id", "id,cvss_severity", "id,description", "id,cvss_score,cvss_vector", "cvss_score", "cvss_score,cvss_severity",
	"cvss_version,cvss_source", "weaknesses", "affected_products", "references", "references_count", "status,published,last_modified"}

// cveGolden captures nyx cve records for each --fields shape with COLUMNS set to columns ("" is
// unset): a record that fills every part, one with a null severity and nothing else, a rejected
// one and one that has only a version 2 score.
func cveGolden(t *testing.T, name, columns string) {
	t.Helper()
	goldenPlain(t, name, func(tune func(*harness)) (*harness, string) {
		h := newHarness(t)
		tune(h)
		h.setenv("COLUMNS", columns)
		h.stdoutWidth = 70 // a width the stream reports is not asked for off a terminal
		nvd := newNVD(t, h)
		nvd.mu.Lock()
		nvd.entries["CVE-2024-10001"], nvd.entries["CVE-2024-10002"] = richEntry(), bareEntry
		nvd.mu.Unlock()
		ids := []string{"CVE-2024-10001", "CVE-2024-10002", nvd.fixture("rejected.json"), nvd.fixture("only-v2.json")}
		var b strings.Builder
		for _, spec := range cveShapes {
			args := append([]string{"cve"}, ids...)
			if spec != "" {
				args = append(args, "--fields", spec)
			}
			if code := h.execRoot(args...); code != 0 || h.stderr.Len() != 0 {
				t.Fatalf("--fields %q: exit %d, stderr %q", spec, code, h.stderr.String())
			}
			fmt.Fprintf(&b, "$ nyx cve %s%s\n%s", strings.Join(ids, " "), map[bool]string{true: " --fields " + spec}[spec != ""], h.stdout.String())
		}
		return h, b.String()
	})
}

// A record's layout off a terminal wraps at 100 cells when COLUMNS is unset or not a number.
func TestPlain_CVERecordsDefaultWidth(t *testing.T) {
	t.Parallel()
	cveGolden(t, "cve-columns-unset", "")
}

// COLUMNS sets the width a record wraps at, off a terminal too.
func TestPlain_CVERecordsColumns80(t *testing.T) {
	t.Parallel()
	cveGolden(t, "cve-columns-80", "80")
}

// A COLUMNS under 60 wraps at 60.
func TestPlain_CVERecordsColumns40(t *testing.T) {
	t.Parallel()
	cveGolden(t, "cve-columns-40", "40")
}
