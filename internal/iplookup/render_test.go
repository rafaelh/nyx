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
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
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

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func strip(s string) string { return sgr.ReplaceAllString(s, "") }

// With colour a terminal's layout is the uncoloured one with the palette's codes added.
func TestRender_ColourOnlyAddsTheStyle(t *testing.T) {
	t.Parallel()
	for _, terminal := range []bool{false, true} {
		plain := renderTo(t, []Record{full(), private()}, "all", true, stream(terminal, palette.None, 80))
		for _, d := range []palette.Depth{palette.Color16, palette.Color256, palette.TrueColor} {
			got := renderTo(t, []Record{full(), private()}, "all", true, stream(terminal, d, 80))
			if strip(got) != plain {
				t.Errorf("terminal=%v depth %d: without its codes the layout differs\n got:\n%s\nwant:\n%s", terminal, d, strip(got), plain)
			}
			if !strings.Contains(got, d.Bold("Owner")) && !strings.Contains(got, d.BoldText(palette.Semantic, "info", "Owner")) {
				t.Errorf("terminal=%v depth %d: the heading is not styled: %q", terminal, d, got)
			}
			if !strings.Contains(got, d.Bold("203.0.113.9")) {
				t.Errorf("terminal=%v depth %d: the address is not bold: %q", terminal, d, got)
			}
		}
		if strings.Contains(plain, "\x1b") {
			t.Errorf("terminal=%v: an escape at depth None", terminal)
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
			want := "203.0.113.9 (a.example.com, b.example.com) [documentation]\n\nOwner\n  ASN  AS64500\n\nLocation\n  Country  AU\n\nFailures\n  none\n"
			if got != want {
				t.Errorf("terminal: got %q, want %q", got, want)
			}
			continue
		}
		want := "203.0.113.9 (a.example.com, b.example.com) [documentation]\n\nOwner\nASN: AS64500\n\nLocation\nCountry: AU\n\nFailures\nnone\n"
		if got != want {
			t.Errorf("plain: got %q, want %q", got, want)
		}
	}
	// Nothing selected: the header and the failures, which are always there.
	got := renderTo(t, []Record{private()}, "", false, stream(false, palette.None, 100))
	if want := "10.0.0.1 [private]\n\nFailures\nnone\n"; got != want {
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
	// A non-public address's keys are empty: none.
	got := renderTo(t, []Record{private()}, "all", true, stream(false, palette.None, 100))
	for _, want := range []string{"ASN: none", "PTR: none", "Ports: none", "Count: none", "Names: none", "\nNot contacted\nnone\n", "\nPorts\nnone\n", "\nTLS\nnone\n", "\nWeb\nnone\n", "\nFailures\nnone\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	// A value from a source that failed is unknown, and one from a source that did not is none.
	r := Record{Address: "1.1.1.1", Hostnames: []string{}, Kind: "public", RDAPOrg: nil, PTR: []string{}}
	r.AddFailure(Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true})
	r.AddFailure(Failure{Source: SourceHackerTarget, Code: clierr.RateLimited, Message: "quota spent", Quota: true})
	got = renderTo(t, []Record{r}, "asn,provider,rdap_org,ptr,reverse_ip,reverse_ip_count", false, stream(false, palette.None, 100))
	want := `1.1.1.1 [public]

Owner
ASN: unknown

Registration
Organisation: none

Names
PTR: none

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
	for _, line := range []string{"ASN: AS64500", "Name: unknown", "Provider: none", "Count: 0"} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("lacks %q:\n%s", line, got)
		}
	}
}

func TestRender_RecordsAreSeparatedByABlankLine(t *testing.T) {
	t.Parallel()
	a, b := private(), private()
	b.Address = "10.0.0.2"
	for _, term := range []bool{false, true} {
		got := renderTo(t, []Record{a, b}, "", false, stream(term, palette.None, 100))
		if !strings.Contains(got, "none\n\n10.0.0.2 [private]\n") {
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
				if !strings.Contains(squash(plain), want) {
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
