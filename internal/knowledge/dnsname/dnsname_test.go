package dnsname_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// Cover reversed DNS forms shared by PTR and Cymru.
func TestReverseNames(t *testing.T) {
	t.Parallel()
	cases := []struct{ addr, ptr, cymru string }{
		{"192.0.2.10", "10.2.0.192.in-addr.arpa", "10.2.0.192.origin.asn.cymru.com"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com"},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := dnsname.ReverseName(a); got != c.ptr {
			t.Errorf("ReverseName(%s) = %s, want %s", c.addr, got, c.ptr)
		}
		if got := dnsname.CymruOrigin(a); got != c.cymru {
			t.Errorf("CymruOrigin(%s) = %s, want %s", c.addr, got, c.cymru)
		}
	}
}

// Wildcard parent discovery proceeds nearest-first through the registrable domain.
func TestParents(t *testing.T) {
	t.Parallel()
	got := dnsname.Parents("a.b.example.com")
	if !slices.Equal(got, []string{"b.example.com", "example.com"}) {
		t.Errorf("Parents = %v", got)
	}
	if got := dnsname.Parents("example.com"); len(got) != 0 {
		t.Errorf("a registrable domain has no parents, got %v", got)
	}
	if got := dnsname.Parents("a.example.co.uk"); !slices.Equal(got, []string{"example.co.uk"}) {
		t.Errorf("public suffix handling: %v", got)
	}
}

// Normalise names to registrable roots.
func TestETLDPlusOne(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"www.example.com": "example.com", "a.b.example.co.uk": "example.co.uk"} {
		if got, ok := dnsname.ETLDPlusOne(in); !ok || got != want {
			t.Errorf("ETLDPlusOne(%s) = %q, %v", in, got, ok)
		}
	}
	if _, ok := dnsname.ETLDPlusOne("com"); ok {
		t.Error("a public suffix has no registrable domain")
	}
}

// Generation stays deterministic, unique, valid and capped, excluding the seed itself.
func TestPermute(t *testing.T) {
	t.Parallel()
	words := []string{"dev", "staging"}
	got := dnsname.Permute("api", words, 200)
	for _, want := range []string{"api-dev", "dev-api", "api.dev", "dev.api", "apidev", "devapi", "api1", "api2"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if slices.Contains(got, "api") {
		t.Error("the seed itself must not be generated")
	}
	if !slices.Equal(got, dnsname.Permute("api", words, 200)) {
		t.Error("not deterministic")
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Errorf("duplicate %q", g)
		}
		seen[g] = true
	}
	if capped := dnsname.Permute("api", words, 5); len(capped) != 5 || !slices.Equal(capped, got[:5]) {
		t.Errorf("cap: %v", capped)
	}
	if n := dnsname.Permute("web07", nil, 200); !slices.Contains(n, "web08") || !slices.Contains(n, "web06") {
		t.Errorf("digit increments keep padding: %v", n)
	}
	for _, g := range dnsname.Permute(strings.Repeat("a", 60), []string{"long-word"}, 200) {
		for part := range strings.SplitSeq(g, ".") {
			if !dnsname.ValidLabel(part) {
				t.Errorf("invalid label generated: %q", g)
			}
		}
	}
}

// A label's learnable forms are the label, then its hyphen-separated parts in order. A form that is
// empty, digits only, not a valid label or a repeat is left out, and a label beginning "xn--" is
// not split.
func TestLearnableForms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		label string
		want  []string
	}{
		{"api", []string{"api"}},
		{"api-dev2", []string{"api-dev2", "api", "dev2"}},
		{"2024", nil}, // digits only
		{"api-2024", []string{"api-2024", "api"}}, // a digits-only part
		{"2024-api", []string{"2024-api", "api"}},
		{"xn--bcher-kva", []string{"xn--bcher-kva"}}, // not split
		{"api-api", []string{"api-api", "api"}},      // a part repeats
		{"a--b", []string{"a--b", "a", "b"}},         // an empty part
		{"-a", []string{"a"}},                        // the label is invalid, its part is not
		{"web-01-02", []string{"web-01-02", "web"}},
	}
	for _, c := range cases {
		got := dnsname.LearnableForms(c.label)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("LearnableForms(%q) = %q, want %q", c.label, got, c.want)
		}
	}
}

// Hostnames in text are read as whole runs of name characters, in lower case, so a name is
// never cut out of a longer one: a run with an invalid label, or a single label, gives nothing.
// Order is not compared.
func TestHostnamesIn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		text string
		want []string
	}{
		{"API.Example.COM", []string{"api.example.com"}},
		{"example.com", []string{"example.com"}},
		{"www.example.com.evil.net", []string{"www.example.com.evil.net"}},
		{"_dmarc.example.com", nil},
		{"sel._domainkey.example.com", nil},
		{"v=spf1 include:_spf.example.com ~all", nil},
		{"a_b.example.com", nil},
		{"*.cdn.example.com", []string{"cdn.example.com"}},
		{"mailto:a@mail.example.com", []string{"mail.example.com"}},
		{"https://app.example.com/x", []string{"app.example.com"}},
		{"ns1.example.com:53", []string{"ns1.example.com"}},
		{"see www.example.com.", []string{"www.example.com"}},
		{"..example.com..", []string{"example.com"}},
		{"mail.example.com, smtp.Example.NET", []string{"mail.example.com", "smtp.example.net"}},
		{"-bad.example.com", []string{"bad.example.com"}}, // hyphens at the ends are trimmed, like dots
		{"bad-.example.com", nil},
		{"a..example.com", nil},
		{strings.Repeat("a", 64) + ".example.com", nil},
		{"localhost", nil},
		{"google-site-verification=abc123", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := slices.Sorted(slices.Values(hostnamesIn(t, c.text, false)))
		want := slices.Sorted(slices.Values(c.want))
		if !slices.Equal(got, want) {
			t.Errorf("HostnamesIn(%q) = %q, want %q", c.text, got, want)
		}
	}
}

// hostnameCase is a text and the names read from it, in the order they are written.
type hostnameCase struct {
	text string
	want []string
}

// hostnamesIn collects the names read from text, read once as a string and once as a byte
// slice, which must give the same names.
func hostnamesIn(t *testing.T, text string, cut bool) []string {
	t.Helper()
	got := slices.Collect(dnsname.HostnamesIn(text, cut))
	if fromBytes := slices.Collect(dnsname.HostnamesIn([]byte(text), cut)); !slices.Equal(fromBytes, got) {
		t.Errorf("HostnamesIn(%q, %v) gives %q from a string but %q from bytes", text, cut, got, fromBytes)
	}
	return got
}

func checkHostnames(t *testing.T, cases []hostnameCase) {
	t.Helper()
	for _, c := range cases {
		if got := hostnamesIn(t, c.text, false); !slices.Equal(got, c.want) {
			t.Errorf("HostnamesIn(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// Each way a link is commonly escaped gives the name after it, never one that begins with the
// remains of the escape, while a name that begins that way when written plainly keeps it.
func TestHostnamesIn_EscapedLinks(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	escaped := []string{
		`https%3A%2F%2Fapi.example.com`,
		`https:\/\/api.example.com`,
		`https:\u002F\u002Fapi.example.com`,
		`https:\x2F\x2Fapi.example.com`,
		`https:&#x2F;&#x2F;api.example.com`,
	}
	var cases []hostnameCase
	for _, text := range escaped {
		cases = append(cases, hostnameCase{text, api})
	}
	cases = append(cases,
		hostnameCase{`2fa.example.com`, []string{"2fa.example.com"}},
		hostnameCase{`https://2fa.example.com/login`, []string{"2fa.example.com"}},
		hostnameCase{`u002fapi.example.com x2fapi.example.com`, []string{"u002fapi.example.com", "x2fapi.example.com"}},
	)
	checkHostnames(t, cases)
}

// A name is read whole: further labels make it a longer name, and upper case is lowered.
func TestHostnamesIn_WholeNames(t *testing.T) {
	t.Parallel()
	checkHostnames(t, []hostnameCase{
		{`https://www.example.com.evil.net/`, []string{"www.example.com.evil.net"}},
		{`Visit API.Example.COM today`, []string{"api.example.com"}},
	})
}

// A wildcard entry, as a policy header writes it, and a cookie domain with its leading dot give
// the name below them.
func TestHostnamesIn_WildcardsAndCookieDomains(t *testing.T) {
	t.Parallel()
	checkHostnames(t, []hostnameCase{
		{`default-src 'self' *.cdn.example.com https://*.img.example.com`, []string{"cdn.example.com", "img.example.com"}},
		{`sid=1; Domain=.shop.example.com; Path=/; Secure`, []string{"shop.example.com"}},
	})
}

// Each escape is decoded in line to one character, which then joins, separates or rejects the
// run as that character would.
func TestHostnamesIn_Escapes(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	checkHostnames(t, []hostnameCase{
		// percent-encoding, either case of hex digit
		{`api%2Eexample%2ecom`, api},
		// JSON and script escapes: four hex digits, braces of one to six, and two hex digits
		{`api\u002Eexample\u002ecom`, api},
		{`https:\u{2F}\u{2F}api.example.com`, api},
		{`api\u{2e}example\u{00002E}com`, api},
		{`api\x2Eexample\x2ecom`, api},
		// a backslash and any other non-letter is that character
		{`api\.example\.com`, api},
		{`https:\/\/api\.example\.com\/x`, api},
		// a backslash and three decimal digits is that byte; over 255 separates
		{`api\046example\046com`, api},
		{`www\300api.example.com`, api},
		// a backslash and a digit not followed by two more separates
		{`x\0api.example.com`, api},
		// control escapes separate
		{`\napi.example.com`, api},
		{`\tapi.example.com`, api},
		{`\rapi.example.com`, api},
		{`\bapi.example.com`, api},
		{`\fapi.example.com`, api},
		{`\vapi.example.com`, api},
		{`api.example.com\nwww.example.com\tmail.example.com`, []string{"api.example.com", "www.example.com", "mail.example.com"}},
		// a backslash and any other letter rejects the run, as in a regular expression
		{`\w\.example\.com`, nil},
		{`^\sapi\.example\.com$`, nil},
		// HTML numeric references, decimal and hex, with or without the semicolon
		{`api&#46;example&#46;com`, api},
		{`api&#046;example&#46com`, api},
		{`api&#x2E;example&#x2e;com`, api},
		{`https:&#x2F&#x2Fwww.example.com`, []string{"www.example.com"}},
		// the digits are read greedily: U+2F00 and U+11F8 separate
		{`&#x2F00.example.com`, []string{"example.com"}},
		{`&#4600.example.com`, []string{"example.com"}},
		// seven digits are read, more separate
		{`api&#0000046;example.com`, api},
		{`api&#00000046;example.com`, []string{"example.com"}},
		// &amp; is decoded, no other named entity is
		{`api&period;example&period;com`, nil},
		{`&lt;api.example.com&gt;`, api},
		// a decoded escape character begins a new escape
		{`https:%252F%252Fapi.example.com`, api},
		{`api%252Eexample%252Ecom`, api},
		{`https:\\u002f\\u002fapi.example.com`, api},
		{`api\\u002eexample\\u002ecom`, api},
		{`line\\napi.example.com`, api},
		{`https:&amp;#x2F;&amp;#x2F;api.example.com`, api},
		{`api&amp;#46;example&amp;#46;com`, api},
		// an escape of a character outside Latin, Greek and Cyrillic separates
		{`\u4E2Dapi.example.com`, api},
	})
}

// A Latin, Greek or Cyrillic non-ASCII letter, written or escaped, and a byte that is not UTF-8
// reject the whole run; any other non-ASCII text separates names.
func TestHostnamesIn_NonASCII(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	checkHostnames(t, []hostnameCase{
		{"bücher.example.com", nil},
		{`b\195\188cher.example.com`, nil},
		{`b%C3%BCcher.example.com`, nil},
		{`b\xFCcher.example.com`, nil},
		{`b\u00FCcher.example.com`, nil},
		{`b&#252;cher.example.com`, nil},
		{"api.example.comü", nil},
		{"αapi.example.com", nil},
		{"api.exаmple.com", nil}, // a Cyrillic а
		{"api.example.comя", nil},
		{"b\xfccher.example.com", nil}, // a Latin-1 ü
		{"api.example.com\xfc", nil},   // a Latin-1 ü after the name
		{"\xfc api.example.com", api},  // a Latin-1 byte apart from the name
		{"请访问api.example.com获取更多信息", api},
		{"詳細はapi.example.comをご覧ください", api},
		{"api.example.com和www.example.com", []string{"api.example.com", "www.example.com"}},
		{"🚀api.example.com🎉www.example.com", []string{"api.example.com", "www.example.com"}},
		{"「api.example.com」", api},
		{"©api.example.com", api},
		{"api.example.com\u00a0www.example.com", []string{"api.example.com", "www.example.com"}},
	})
}

// A name of 253 bytes is read and one of 254 is not; a longer run is skipped whole, so its tail
// is not read as a name, and the names after it are still read.
func TestHostnamesIn_Length(t *testing.T) {
	t.Parallel()
	head := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "."
	n253, n254 := head+strings.Repeat("d", 61), head+strings.Repeat("d", 62)
	if len(n253) != 253 || len(n254) != 254 {
		t.Fatalf("test names are %d and %d bytes", len(n253), len(n254))
	}
	checkHostnames(t, []hostnameCase{
		{n253, []string{n253}},
		{"see " + strings.ToUpper(n253) + " now", []string{n253}},
		{n254, nil},
		{n254 + " api.example.com", []string{"api.example.com"}},
		{strings.Repeat("a.", 200) + "example.com www.example.com", []string{"www.example.com"}},
	})
}

// With cut, only the run that reaches the end of the text is dropped.
func TestHostnamesIn_Cut(t *testing.T) {
	t.Parallel()
	cases := []struct {
		text        string
		cut, notCut []string
	}{
		{"api.example.com www.exam", []string{"api.example.com"}, []string{"api.example.com", "www.exam"}},
		{"a.example.com b.example.com c.example.com", []string{"a.example.com", "b.example.com"},
			[]string{"a.example.com", "b.example.com", "c.example.com"}},
		{"api.example.com", nil, []string{"api.example.com"}},
		{"api.example.com.", nil, []string{"api.example.com"}},
		{"api.example.com ", []string{"api.example.com"}, []string{"api.example.com"}},
		{`<a href="https://api.example.com/">`, []string{"api.example.com"}, []string{"api.example.com"}},
	}
	for _, c := range cases {
		if got := hostnamesIn(t, c.text, true); !slices.Equal(got, c.cut) {
			t.Errorf("HostnamesIn(%q, true) = %q, want %q", c.text, got, c.cut)
		}
		if got := hostnamesIn(t, c.text, false); !slices.Equal(got, c.notCut) {
			t.Errorf("HostnamesIn(%q, false) = %q, want %q", c.text, got, c.notCut)
		}
	}
}

// Each occurrence is yielded, in the order written: the caller removes repeats.
func TestHostnamesIn_OncePerOccurrence(t *testing.T) {
	t.Parallel()
	checkHostnames(t, []hostnameCase{
		{"www.example.com api.example.com WWW.example.com www.example.com",
			[]string{"www.example.com", "api.example.com", "www.example.com", "www.example.com"}},
	})
}

// Any type whose underlying type is a string or a byte slice can be read.
func TestHostnamesIn_NamedTypes(t *testing.T) {
	t.Parallel()
	type page string
	type body []byte
	want := []string{"api.example.com"}
	if got := slices.Collect(dnsname.HostnamesIn(page("see api.example.com"), false)); !slices.Equal(got, want) {
		t.Errorf("from a named string: %q, want %q", got, want)
	}
	if got := slices.Collect(dnsname.HostnamesIn(body("see api.example.com"), false)); !slices.Equal(got, want) {
		t.Errorf("from a named byte slice: %q, want %q", got, want)
	}
}

// When the caller stops, nothing more is yielded and the rest of the text is not scanned: stopping
// after the first name takes a small part of the time a whole scan of the same text takes.
func TestHostnamesIn_StopsWhenTheCallerStops(t *testing.T) {
	t.Parallel()
	text := "first.example.com second.example.com " + strings.Repeat("a", 8<<20) + " last.example.com"
	var got []string
	dnsname.HostnamesIn(text, false)(func(h string) bool {
		got = append(got, h)
		return false
	})
	if want := []string{"first.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("stopping after the first name yielded %q, want %q", got, want)
	}
	start := time.Now()
	all := slices.Collect(dnsname.HostnamesIn(text, false))
	whole := time.Since(start)
	if want := []string{"first.example.com", "second.example.com", "last.example.com"}; !slices.Equal(all, want) {
		t.Fatalf("whole scan = %q, want %q", all, want)
	}
	early := whole
	for range 5 {
		start := time.Now()
		for range dnsname.HostnamesIn(text, false) {
			break
		}
		early = min(early, time.Since(start))
	}
	if early*10 > whole {
		t.Errorf("stopping after the first name took %v, a whole scan %v: the scan went on", early, whole)
	}
}

// The reading is linear and holds no more than a name: 4 MiB of short names, and 4 MiB of one
// run too long to be a name, are each read in well under a second.
func TestHostnamesIn_Linear(t *testing.T) {
	t.Parallel()
	short := strings.Repeat("a.b.c ", (4<<20)/6)
	n := 0
	within(t, time.Second, func() {
		for h := range dnsname.HostnamesIn(short, false) {
			if h == "a.b.c" {
				n++
			}
		}
	})
	if want := (4 << 20) / 6; n != want {
		t.Errorf("4 MiB of short names gave %d of them, want %d", n, want)
	}
	for _, long := range []string{strings.Repeat("a", 4<<20), strings.Repeat("a.", 2<<20)} {
		var got []string
		within(t, time.Second, func() {
			got = slices.Collect(dnsname.HostnamesIn([]byte(long+" api.example.com"), false))
		})
		if want := []string{"api.example.com"}; !slices.Equal(got, want) {
			t.Errorf("a 4 MiB run then a name gave %q, want %q", got, want)
		}
	}
}

// within fails the test when f has not returned by limit.
func within(t *testing.T, limit time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("not finished after %v", limit)
	}
}
