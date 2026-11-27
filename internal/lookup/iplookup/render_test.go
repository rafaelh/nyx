package iplookup

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// stream is a stream that reports width cells, with colour depth d.
func stream(terminal bool, d palette.Depth, width int) layout.Stream {
	return layout.Stream{Terminal: terminal, Depth: d, Width: func() int { return width }}
}

func renderTo(t *testing.T, recs []Record, spec string, active bool, s layout.Stream) string {
	t.Helper()
	f := mustSelect(t, spec, active)
	ps := make([]Projected, len(recs))
	for i, r := range recs {
		ps[i] = f.Project(r)
	}
	var b bytes.Buffer
	if err := Render(&b, ps, s); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// private is a non-public address's record: every selected key empty.
func private() Record {
	return Record{
		Address: "10.0.0.1", Hostnames: []string{}, Kind: "private",
		PTR: []string{}, InternetDBPorts: []int{}, InternetDBHostnames: []string{}, InternetDBTags: []string{},
		InternetDBCPEs: []string{}, InternetDBVulns: []string{}, ReverseIP: []string{},
		Ports: []Port{}, TLS: []TLSEntry{}, Web: []WebEntry{},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs\n got:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestRender_PlainGolden(t *testing.T) {
	t.Parallel()
	got := renderTo(t, []Record{full(), private()}, "all", true, stream(false, palette.None, 100))
	golden(t, "plain.txt", got)
}

func TestRender_TerminalGolden(t *testing.T) {
	t.Parallel()
	got := renderTo(t, []Record{full(), private()}, "all", true, stream(true, palette.None, 80))
	golden(t, "terminal.txt", got)
}

// A terminal wide enough for two columns lays the labelled sections out in them, the lists
// beneath at the full width.
func TestRender_TerminalWideGolden(t *testing.T) {
	t.Parallel()
	got := renderTo(t, []Record{full(), private()}, "all", true, stream(true, palette.None, 2*minColumn+gutter))
	golden(t, "terminal-wide.txt", got)
}

// Two columns need room for both: a narrower terminal, or a word too long to wrap that would push
// them past the width, gives one.
func TestRender_TwoColumnsOnlyWhenTheyFit(t *testing.T) {
	t.Parallel()
	wide := 2*minColumn + gutter
	twoColumns := regexp.MustCompile(`(?m)^Owner +Location$`)
	if got := renderTo(t, []Record{full()}, "all", true, stream(true, palette.None, wide)); !twoColumns.MatchString(got) {
		t.Errorf("%d cells: one column:\n%s", wide, got)
	}
	if got := renderTo(t, []Record{full()}, "all", true, stream(true, palette.None, wide-1)); !strings.Contains(got, "\nOwner\n") {
		t.Errorf("%d cells: not one column:\n%s", wide-1, got)
	}
	r := full()
	r.PTR = []string{"ec2-203-0-113-9.ap-southeast-2.compute.internal.a-very-long-label.example.com"}
	got := renderTo(t, []Record{r}, "all", true, stream(true, palette.None, wide))
	if !strings.Contains(got, "\nOwner\n") || !strings.Contains(got, "  PTR  "+r.PTR[0]+"\n") {
		t.Errorf("a long name: not one column:\n%s", got)
	}
	if got := renderTo(t, []Record{r}, "all", true, stream(true, palette.None, 140)); !twoColumns.MatchString(got) {
		t.Errorf("a long name with room for it: one column:\n%s", got)
	}
}

// The threat-data headings are in setup's red, and the others are not.
func TestRender_AlertHeadingsAreRed(t *testing.T) {
	t.Parallel()
	r := full()
	r.AbusiveNetworks = []abusive.NetworkMatch{{Network: "203.0.113.0/24", ScoreTag: "High", AbuseScore: 50, Org: "O", OrgType: "isp", Updated: "2026-11-21"}}
	r.AbusiveASN = []abusive.ASNMatch{{ASN: 64500, ScoreTag: "High", AbuseScore: 50, Org: "O", OrgType: "isp", Updated: "2026-11-21"}}
	r.DropASN = []spamhaus.ASNMatch{{ASN: 64500, Updated: dropASNDate}}
	for _, term := range []bool{false, true} {
		for _, width := range []int{80, 2*minColumn + gutter} {
			for _, d := range []palette.Depth{palette.Color16, palette.Color256, palette.TrueColor} {
				got := renderTo(t, []Record{r}, "all", true, stream(term, d, width))
				for _, h := range []string{"Abusive networks", "Abusive ASN", "Spamhaus DROP networks", "Spamhaus ASN-DROP"} {
					if !strings.Contains(got, d.BoldText(palette.Semantic, "alert", h)) {
						t.Errorf("terminal=%v width %d depth %d: %s is not red: %q", term, width, d, h, got)
					}
				}
				if strings.Contains(got, d.BoldText(palette.Semantic, "alert", "Owner")) || strings.Contains(got, d.BoldText(palette.Semantic, "alert", "Ports")) {
					t.Errorf("terminal=%v width %d depth %d: another heading is red: %q", term, width, d, got)
				}
			}
		}
	}
}

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func strip(s string) string { return sgr.ReplaceAllString(s, "") }

// With colour a terminal's layout is the uncoloured one with the palette's codes added.
func TestRender_ColourOnlyAddsTheStyle(t *testing.T) {
	t.Parallel()
	for _, terminal := range []bool{false, true} {
		for _, width := range []int{80, 2*minColumn + gutter} {
			plain := renderTo(t, []Record{full(), private()}, "all", true, stream(terminal, palette.None, width))
			for _, d := range []palette.Depth{palette.Color16, palette.Color256, palette.TrueColor} {
				got := renderTo(t, []Record{full(), private()}, "all", true, stream(terminal, d, width))
				if strip(got) != plain {
					t.Errorf("terminal=%v depth %d: without its codes the layout differs\n got:\n%s\nwant:\n%s", terminal, d, strip(got), plain)
				}
				if !strings.Contains(got, d.Bold("Owner")) && !strings.Contains(got, d.BoldText(palette.Semantic, "info", "Owner")) {
					t.Errorf("terminal=%v depth %d: the heading is not styled: %q", terminal, d, got)
				}
				if !strings.Contains(got, d.BoldText(palette.Semantic, "example", "203.0.113.9")) {
					t.Errorf("terminal=%v depth %d: the address is not bold amber: %q", terminal, d, got)
				}
			}
			if strings.Contains(plain, "\x1b") {
				t.Errorf("terminal=%v: an escape at depth None", terminal)
			}
		}
	}
}

func TestRender_NothingToWrite(t *testing.T) {
	t.Parallel()
	for _, term := range []bool{false, true} {
		if got := renderTo(t, nil, "all", false, stream(term, palette.None, 80)); got != "" {
			t.Errorf("terminal=%v: no records wrote %q", term, got)
		}
	}
}

func TestRender_OnlyTheSelectedSections(t *testing.T) {
	t.Parallel()
	r := full()
	r.Failures = nil
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{r}, "asn,geo_country", false, stream(term, palette.None, 100))
		if term {
			want := "203.0.113.9 (a.example.com, b.example.com) [documentation]\n\nOwner\n  ASN  AS64500\n\nLocation\n  Country  AU\n"
			if got != want {
				t.Errorf("terminal: got %q, want %q", got, want)
			}
			continue
		}
		want := "203.0.113.9 (a.example.com, b.example.com) [documentation]\n\nOwner\nASN: AS64500\n\nLocation\nCountry: AU\n"
		if got != want {
			t.Errorf("plain: got %q, want %q", got, want)
		}
	}
	// Nothing selected: the header and the failures, which are always there when there are any.
	got := renderTo(t, []Record{private()}, "", false, stream(false, palette.None, 100))
	if want := "10.0.0.1 [private]\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	r.AddFailure(Failure{Source: SourceRIPEstat, Code: clierr.Timeout, Message: "late", Transient: true})
	got = renderTo(t, []Record{r}, "", false, stream(false, palette.None, 100))
	if want := "203.0.113.9 (a.example.com, b.example.com) [documentation]\n\nFailures\n- ripestat: late (TIMEOUT, transient)\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Active sections never appear without --active.
	got = renderTo(t, []Record{full()}, "all", false, stream(false, palette.None, 100))
	for _, h := range []string{"Not contacted", "\nPorts\n", "\nTLS\n", "\nWeb\n"} {
		if strings.Contains(got, h) {
			t.Errorf("default mode shows %q:\n%s", h, got)
		}
	}
}

func TestRender_EmptyAndUnknownValues(t *testing.T) {
	t.Parallel()
	// A non-public address's keys are empty, so every value and section is left out.
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{private()}, "all", true, stream(term, palette.None, 2*minColumn+gutter))
		if want := "10.0.0.1 [private]\n"; got != want {
			t.Errorf("terminal=%v: got %q, want %q", term, got, want)
		}
	}
	// A value from a source that failed is unknown, and one from a source that did not is left out.
	r := Record{Address: "1.1.1.1", Hostnames: []string{}, Kind: "public", RDAPOrg: nil, PTR: []string{}}
	r.AddFailure(Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true})
	r.AddFailure(Failure{Source: SourceHackerTarget, Code: clierr.RateLimited, Message: "quota spent", Quota: true})
	got := renderTo(t, []Record{r}, "asn,provider,rdap_org,ptr,reverse_ip,reverse_ip_count", false, stream(false, palette.None, 100))
	want := `1.1.1.1 [public]

Owner
ASN: unknown

Provider
Provider: unknown

Reverse IP
Count: unknown
Names: unknown

Failures
- cymru: no answer before the deadline (TIMEOUT, transient)
- hackertarget: quota spent (RATE_LIMITED, quota)
`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	// When only the AS name failed, the AS number is known and the provider was decided from it:
	// only the name is unknown.
	r = Record{Address: "1.1.1.1", Hostnames: []string{}, Kind: "public", ASN: new(uint32(64500)), ReverseIP: []string{}, ReverseIPCount: new(0)}
	r.AddFailure(Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true})
	got = renderTo(t, []Record{r}, "asn,as_name,provider,reverse_ip_count", false, stream(false, palette.None, 100))
	for _, line := range []string{"ASN: AS64500", "Name: unknown", "Count: 0"} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("lacks %q:\n%s", line, got)
		}
	}
	if strings.Contains(got, "Provider") {
		t.Errorf("shows the empty provider:\n%s", got)
	}
}

func TestRender_RecordsAreSeparatedByABlankLine(t *testing.T) {
	t.Parallel()
	a, b := private(), private()
	b.Address = "10.0.0.2"
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{a, b}, "", false, stream(term, palette.None, 100))
		if got != "10.0.0.1 [private]\n\n10.0.0.2 [private]\n" {
			t.Errorf("terminal=%v: %q", term, got)
		}
	}
}

// hostile is text that would act on a terminal: escape sequences, a title change, a newline, a tab
// and a bidi override.
const hostile = "\x1b[31mred\x1b[0m\x1b]0;owned\x07 line\nbreak\there \u202eevil\r"

func TestRender_SanitisesEveryString(t *testing.T) {
	t.Parallel()
	r := full()
	r.Hostnames = []string{"a\x1b[2J.example.com"}
	r.ASName = new(hostile)
	r.RDAPOrg = new("Evil \x1b[31mOrg\x1b[0m\nSecond\tline")
	r.RDAPRegistry = new(hostile)
	r.PTR = []string{hostile}
	r.Provider = new(hostile)
	r.GeoCity = new(hostile)
	r.InternetDBTags = []string{hostile}
	r.InternetDBHostnames = []string{hostile}
	r.NotContacted = new(hostile)
	r.Ports = []Port{{Port: 22, State: PortOpen, Banner: new("SSH-2.0-\x1b[2Jx\x1b]8;;http://evil\x07link\nINJECTED\r\n")}}
	r.TLS = []TLSEntry{{Port: 443, ServerName: new(hostile), Outcome: OutcomeOK, Names: []string{hostile}, Issuer: new(hostile), Expiry: new(hostile)}}
	r.Web = []WebEntry{{Port: 80, Scheme: "http", Host: hostile, Outcome: OutcomeOK, Status: new(200), Server: new(hostile),
		Title: new("<title>\x1b[1;31mPWNED\x1b[0m\n\tnext"), Location: new(hostile)}}
	r.Failures = []Failure{{Source: SourceProbe, Code: clierr.NetworkError, Message: hostile}}
	for _, term := range []bool{false, true} {
		for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
			got := renderTo(t, []Record{r}, "all", true, stream(term, d, 80))
			plain := strip(got)
			for _, bad := range []string{"\x1b", "\x07", "\t", "\r", "\u202e", "owned", "\x00"} {
				if strings.Contains(plain, bad) {
					t.Errorf("terminal=%v depth %d: %q reached the output:\n%q", term, d, bad, plain)
				}
			}
			for _, want := range []string{"red line break here evil", "Evil Org Second line", "SSH-2.0-x", "link INJECTED", "<title>PWNED next", "a.example.com"} {
				if !strings.Contains(strings.Join(strings.Fields(plain), " "), want) {
					t.Errorf("terminal=%v depth %d: lacks %q:\n%s", term, d, want, plain)
				}
			}
			// The whole of a hostile value is on one line of a labelled row, never a line of its own.
			for line := range strings.SplitSeq(plain, "\n") {
				if strings.HasPrefix(line, "INJECTED") || strings.HasPrefix(line, "break") {
					t.Errorf("terminal=%v depth %d: a value's newline started a line: %q", term, d, line)
				}
			}
		}
	}
}

func longRecord() Record {
	r := private()
	r.Address = "203.0.113.9"
	r.Kind = "documentation"
	r.Hostnames = []string{"first-input.example.com", "second-input.example.com", "third-input.example.com", "fourth-input.example.com"}
	for i := range 40 {
		r.ReverseIP = append(r.ReverseIP, "host"+strings.Repeat("x", i%7)+".example.com")
	}
	n := len(r.ReverseIP)
	r.ReverseIPCount = &n
	r.Ports = []Port{{Port: 22, State: PortOpen, Banner: new(strings.Repeat("banner words ", 20))}}
	return r
}

func TestRender_WrapsToTheWidth(t *testing.T) {
	t.Parallel()
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{longRecord()}, "all", true, stream(term, palette.None, 60))
		for line := range strings.SplitSeq(got, "\n") {
			if w := layout.Measure(line); w > 60 {
				t.Errorf("terminal=%v: a line is %d cells wide: %q", term, w, line)
			}
		}
		if !strings.Contains(got, "host.example.com, hostx.example.com") {
			t.Errorf("terminal=%v: the list is not there:\n%s", term, got)
		}
		// A width under the least is the least.
		narrow := renderTo(t, []Record{longRecord()}, "all", true, stream(term, palette.None, 20))
		if narrow != got {
			t.Errorf("terminal=%v: a width of 20 laid out differently from 60", term)
		}
	}
}

func TestRender_NeverBreaksAWord(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 90) + ".example.com"
	r := private()
	r.RDAPOrg = &long
	got := renderTo(t, []Record{r}, "rdap_org", false, stream(false, palette.None, 60))
	if !strings.Contains(got, "Organisation: "+long+"\n") {
		t.Errorf("a long word was broken in the plain layout:\n%s", got)
	}
}

func TestRender_WebHostsThatAreIPv6AreBracketed(t *testing.T) {
	t.Parallel()
	r := private()
	r.Web = []WebEntry{{Port: 80, Scheme: "http", Host: "2001:db8::1", Outcome: OutcomeNoAnswer}}
	got := renderTo(t, []Record{r}, "web", true, stream(false, palette.None, 100))
	if !strings.Contains(got, "- 80 http://[2001:db8::1]/: no-answer\n") {
		t.Errorf("got\n%s", got)
	}
}

// Abuse sections distinguish matching entries, no matches and unknown origin AS.
func TestRender_AbusiveSections(t *testing.T) {
	t.Parallel()
	nets := []abusive.NetworkMatch{
		{Network: "34.68.34.64/27", Rank: 1, ScoreTag: "Very High", AbuseScore: 100, Org: "Mandiant, Inc.", OrgType: "business", Updated: "2026-11-21"},
		{Network: "34.68.0.0-34.68.40.9", Rank: 7, ScoreTag: "High", AbuseScore: 10.16, Org: "Outer", OrgType: "isp", Updated: "2026-11-21"},
	}
	asn := []abusive.ASNMatch{{ASN: 64050, Rank: 3, ScoreTag: "Very High", AbuseScore: 100, Org: "BGP Network Limited", OrgType: "Spamhaus ASN-DROP", Updated: "2026-11-20"}}
	pubRec := func(n []abusive.NetworkMatch, a []abusive.ASNMatch, fs ...Failure) Record {
		r := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public", AbusiveNetworks: n, AbusiveASN: a}
		for _, f := range fs {
			r.AddFailure(f)
		}
		return r
	}
	type tc struct {
		name string
		rec  Record
		want string
	}
	for _, c := range []tc{
		{"matches", pubRec(nets, asn), `34.68.34.70 [public]

Abusive networks
- 34.68.34.64/27: Very High, 100%, Mandiant, Inc. (business), updated 2026-11-21
- 34.68.0.0-34.68.40.9: High, 10.16%, Outer (isp), updated 2026-11-21

Abusive ASN
- AS64050: Very High, 100%, BGP Network Limited (Spamhaus ASN-DROP), updated 2026-11-20
`},
		{"nothing matches", pubRec([]abusive.NetworkMatch{}, []abusive.ASNMatch{}), `34.68.34.70 [public]
`},
		{"team cymru failed", pubRec(nets[:1], nil, Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true}), `34.68.34.70 [public]

Abusive networks
- 34.68.34.64/27: Very High, 100%, Mandiant, Inc. (business), updated 2026-11-21

Abusive ASN
unknown
`},
		{"a non-public address", func() Record { r := private(); r.AbusiveNetworks, r.AbusiveASN = nil, nil; return r }(), `10.0.0.1 [private]
`},
	} {
		for _, term := range []bool{false, true} {
			got := renderTo(t, []Record{c.rec}, "abusive_networks,abusive_asn", false, stream(term, palette.None, 100))
			if term {
				// The terminal layout has headings and indentation; the lines are the same.
				flat := strings.Join(strings.Fields(got), " ")
				for _, line := range strings.Split(c.want, "\n")[1:] {
					line = strings.TrimPrefix(strings.TrimSpace(line), "- ")
					if line == "" || line == "Abusive networks" || line == "Abusive ASN" {
						continue
					}
					if !strings.Contains(flat, strings.Join(strings.Fields(line), " ")) {
						t.Errorf("%s (terminal) lacks %q:\n%s", c.name, line, got)
					}
				}
				continue
			}
			if _, sections, _ := strings.Cut(c.want, "\n\n"); !strings.Contains(got, sections) || !strings.HasPrefix(got, strings.SplitN(c.want, "\n", 2)[0]) {
				t.Errorf("%s:\n got\n%s\nwant the sections\n%s", c.name, got, sections)
			}
		}
	}
}

// Clean snapshot text before terminal display, like other external data.
func TestRender_AbusiveTextIsSanitised(t *testing.T) {
	t.Parallel()
	r := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public",
		AbusiveNetworks: []abusive.NetworkMatch{{Network: "34.68.34.0/24\x1b[31m", ScoreTag: "Hi\x07gh", AbuseScore: 50, Org: "Evil\x1b]0;x\x07 Org", OrgType: "is\np", Updated: "2026-11-21"}},
		AbusiveASN:      []abusive.ASNMatch{{ASN: 1, ScoreTag: "x", Org: "A\x1b[2Jb", OrgType: "t", Updated: "2026-11-20"}}}
	got := renderTo(t, []Record{r}, "abusive_networks,abusive_asn", false, stream(false, palette.None, 100))
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("unsanitised output: %q", got)
	}
}

// lines are the rendered lines, each without its indentation and bullet.
func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(l), "- "))
	}
	return out
}

// countLines counts standalone final-word values in rendered lines.
func countLines(s, word string) int {
	n := 0
	for _, l := range lines(s) {
		if f := strings.Fields(l); len(f) > 0 && f[len(f)-1] == word {
			n++
		}
	}
	return n
}

// DROP sections label Spamhaus and include ordered source details/dates.
func TestRender_DropSections(t *testing.T) {
	t.Parallel()
	nets := []spamhaus.NetworkMatch{
		{CIDR: "34.68.34.64/27", SBLID: "SBL697779", RIR: "arin", Updated: dropV4Date},
		{CIDR: "34.68.0.0/16", SBLID: "SBL671779", RIR: "ripencc", Updated: dropV4Date},
	}
	asn := []spamhaus.ASNMatch{{ASN: 64050, ASName: "BAD-AS", Country: "RU", Domain: "bad.example", RIR: "lacnic", Updated: dropASNDate}}
	rec := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public", DropNetworks: nets, DropASN: asn}
	for _, term := range []bool{false, true} {
		s := stream(term, palette.None, 200)
		got := renderTo(t, []Record{rec}, "drop_networks,drop_asn", false, s)
		if !strings.Contains(got, "Spamhaus") {
			t.Errorf("terminal=%v: Spamhaus is not named:\n%s", term, got)
		}
		at := func(parts ...string) int {
			for i, l := range lines(got) {
				all := true
				for _, p := range parts {
					all = all && strings.Contains(l, p)
				}
				if all {
					return i
				}
			}
			return -1
		}
		inner := at("34.68.34.64/27", "SBL697779", "arin", dropV4Date)
		outer := at("34.68.0.0/16", "SBL671779", "ripencc", dropV4Date)
		as := at("AS64050", "BAD-AS", "RU", "bad.example", "lacnic", dropASNDate)
		if inner < 0 || outer < 0 || as < 0 || inner >= outer || outer >= as {
			t.Errorf("terminal=%v: the lines of the matches are at %d, %d and %d, want each on its own line in order:\n%s", term, inner, outer, as, got)
		}
	}
}

// An empty DROP key is left out with its heading, and drop_asn reads unknown when Team Cymru
// failed to give the AS.
func TestRender_DropEmptyAndUnknown(t *testing.T) {
	t.Parallel()
	one := []spamhaus.NetworkMatch{{CIDR: "34.68.34.64/27", SBLID: "SBL697779", RIR: "arin", Updated: dropV4Date}}
	pubRec := func(n []spamhaus.NetworkMatch, a []spamhaus.ASNMatch, fs ...Failure) Record {
		r := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public", DropNetworks: n, DropASN: a}
		for _, f := range fs {
			r.AddFailure(f)
		}
		return r
	}
	cymru := Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true}
	for _, c := range []struct {
		name     string
		rec      Record
		unknown  int // more than the record shows with neither key selected
		spamhaus bool
	}{
		{"nothing matches", pubRec([]spamhaus.NetworkMatch{}, []spamhaus.ASNMatch{}), 0, false},
		{"team cymru failed", pubRec(one, nil, cymru), 1, true},
		{"a non-public address", func() Record { r := private(); r.DropNetworks, r.DropASN = nil, nil; return r }(), 0, false},
	} {
		for _, term := range []bool{false, true} {
			s := stream(term, palette.None, 200)
			got := renderTo(t, []Record{c.rec}, "drop_networks,drop_asn", false, s)
			base := renderTo(t, []Record{c.rec}, "", false, s)
			if countLines(got, "none") != 0 {
				t.Errorf("terminal=%v, %s: a none line:\n%s", term, c.name, got)
			}
			if n := countLines(got, "unknown") - countLines(base, "unknown"); n != c.unknown {
				t.Errorf("terminal=%v, %s: %d more unknown lines, want %d:\n%s", term, c.name, n, c.unknown, got)
			}
			if strings.Contains(got, "Spamhaus") != c.spamhaus {
				t.Errorf("terminal=%v, %s: Spamhaus named %v, want %v:\n%s", term, c.name, !c.spamhaus, c.spamhaus, got)
			}
		}
	}
}

// Clean DROP metadata before display, like other source text.
func TestRender_DropTextIsSanitised(t *testing.T) {
	t.Parallel()
	r := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public",
		DropNetworks: []spamhaus.NetworkMatch{{CIDR: "34.68.34.0/24", SBLID: "SBL\x1b[31m5", RIR: "ar\u202ein", Updated: dropV4Date}},
		DropASN:      []spamhaus.ASNMatch{{ASN: 1, ASName: "A\x1b]0;owned\x07b", Country: "R\x07U", Domain: "x\n.example", RIR: "t", Updated: dropASNDate}}}
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{r}, "drop_networks,drop_asn", false, stream(term, palette.None, 200))
		if strings.ContainsAny(got, "\x1b\x07\u202e") || strings.Contains(got, "owned") {
			t.Errorf("terminal=%v: unsanitised output: %q", term, got)
		}
		if !strings.Contains(got, "SBL5") || !strings.Contains(got, "34.68.34.0/24") {
			t.Errorf("terminal=%v: the match is not shown: %q", term, got)
		}
	}
}

// A terminal makes a list's separating commas faint, and each hostname's dots pale and its TLD,
// the domain under it and the one under that coloured by level.
func TestRender_ListsAreColoured(t *testing.T) {
	t.Parallel()
	r := full()
	r.ReverseIP = []string{"000721.cn.trustexporter.com", "a.b.example.co.uk", "example.com.", "com"}
	d := palette.TrueColor
	role := func(name string) func(string) string {
		return func(s string) string { return d.Text(palette.Semantic, name, s) }
	}
	sep, dot, tld, dom, sub := role("separator")(", "), role("dot")("."), role("tld"), role("domain"), role("subdomain")
	got := renderTo(t, []Record{r}, "reverse_ip,internetdb_ports", false, stream(true, d, 200))
	for _, want := range []string{
		"000721" + dot + sub("cn") + dot + dom("trustexporter") + dot + tld("com") + sep +
			"a" + dot + "b" + dot + sub("example") + dot + dom("co") + dot + tld("uk") + sep +
			dom("example") + dot + tld("com") + dot + sep + tld("com") + "\n",
		"22" + sep + "443",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%q", want, got)
		}
	}
	// Plain output and a terminal without colour are unchanged.
	for _, term := range []bool{false, true} {
		if got := renderTo(t, []Record{r}, "reverse_ip", false, stream(term, palette.None, 200)); !strings.Contains(got, "000721.cn.trustexporter.com, a.b.example.co.uk, example.com., com\n") {
			t.Errorf("terminal=%v: %q", term, got)
		}
	}
}
