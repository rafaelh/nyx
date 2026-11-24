package candidates_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/kinds"
)

// families mirrors procedure-declared source families for ranking tests.
var families = candidates.NewFamilies(map[string]string{
	"crtsh": candidates.CertTransparency, "certspotter": candidates.CertTransparency, "wayback": candidates.WebArchive,
	"reverseip": candidates.ReverseIP, "rdap": candidates.Registrant, "whoisxml": candidates.Registrant, "org-asn": candidates.Registrant,
	"shared-ns": candidates.SharedInfra, "shared-mx": candidates.SharedInfra, "identifier-pivot": candidates.WebIdentifier,
})

// ev is the evidence of (source, item) pairs, each with its family.
func ev(pairs ...string) []candidates.Evidence {
	var out []candidates.Evidence
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, candidates.Evidence{Source: pairs[i], Item: pairs[i+1], Family: families.Of(pairs[i])})
	}
	return out
}

// The rules of confidence, one row per rule and one per edge of a rule.
func TestScore(t *testing.T) {
	t.Parallel()
	acme := []string{"Acme Pty Ltd"}
	cases := []struct {
		name  string
		ev    []candidates.Evidence
		orgs  []string
		want  candidates.Confidence
		count int
	}{
		{"registrant match joined by another family", ev("whoisxml", "Acme Pty Ltd", "certspotter", "k"), acme, candidates.High, 2},
		{"registrant match joined by reverse ip on one address", ev("org-asn", "Acme Pty Ltd", "reverseip", "198.51.100.1"), acme, candidates.High, 2},
		{"three families", ev("crtsh", "a", "wayback", "b", "otx", "c"), nil, candidates.High, 3},
		{"two families", ev("crtsh", "a", "wayback", "b"), nil, candidates.Medium, 2},
		{"registrant match alone", ev("whoisxml", "Acme Pty Ltd"), acme, candidates.Medium, 1},
		{"two registrant sources are one family", ev("whoisxml", "Acme Pty Ltd", "org-asn", "Acme Pty Ltd"), acme, candidates.Medium, 2},
		{"no --org: a registrant source alone is one signal", ev("whoisxml", "Acme Pty Ltd"), nil, candidates.Low, 1},
		{"no --org: registrant plus another family is two families", ev("whoisxml", "Acme Pty Ltd", "crtsh", "a"), nil, candidates.Medium, 2},
		{"registrant evidence about another organisation is not a match", ev("rdap", "Other Org", "crtsh", "a"), acme, candidates.Medium, 2},
		{"registrant evidence about another organisation alone", ev("rdap", "Other Org"), acme, candidates.Low, 1},
		{"reverse ip on two addresses", ev("reverseip", "198.51.100.1", "reverseip", "198.51.100.2"), nil, candidates.Medium, 2},
		{"reverse ip on one address", ev("reverseip", "198.51.100.1"), nil, candidates.Low, 1},
		{"shared name server", ev("shared-ns", "ns1.other.org"), nil, candidates.Medium, 1},
		{"shared mail host", ev("shared-mx", "mail.other.org"), nil, candidates.Medium, 1},
		{"a shared name server and mail host are one family", ev("shared-ns", "ns1.other.org", "shared-mx", "mail.other.org"), nil, candidates.Medium, 2},
		{"a shared name server and mail host joined by one family are two families", ev("shared-ns", "ns1.other.org", "shared-mx", "mail.other.org", "crtsh", "a"), nil, candidates.Medium, 3},
		{"a shared name server joined by two families", ev("shared-ns", "ns1.other.org", "crtsh", "a", "wayback", "b"), nil, candidates.High, 3},
		{"one source", ev("crtsh", "a"), nil, candidates.Low, 1},
		{"one source, several items, is one family", ev("crtsh", "a", "crtsh", "b"), nil, candidates.Low, 2},
		{"two sources of one family", ev("crtsh", "a", "certspotter", "a"), nil, candidates.Low, 2},
		{"the same pair twice counts once", ev("crtsh", "a", "crtsh", "a"), nil, candidates.Low, 1},
		{"sources outside the table are their own family", ev("httpprobe", "a.example.com:443", "rdns", "198.51.100.9"), nil, candidates.Medium, 2},
		{"three sources outside the table", ev("httpprobe", "a", "rdns", "b", "crawl", "c"), nil, candidates.High, 3},
		{"two identifiers are one family", ev("identifier-pivot:G-AAAAAA1", "G-AAAAAA1", "identifier-pivot:111111111", "111111111"), nil, candidates.Low, 2},
		{"two identifiers joined by one other family", ev("identifier-pivot:a", "a", "identifier-pivot:b", "b", "crtsh", "k"), nil, candidates.Medium, 3},
		{"two identifiers joined by two other families", ev("identifier-pivot:a", "a", "identifier-pivot:b", "b", "crtsh", "k", "wayback", "w"), nil, candidates.High, 4},
		{"no evidence", nil, acme, candidates.Low, 0},
	}
	for _, c := range cases {
		got := candidates.Score(c.ev, c.orgs)
		if got.Confidence != c.want || got.Count != c.count {
			t.Errorf("%s: got %s with %d evidence, want %s with %d", c.name, got.Confidence, got.Count, c.want, c.count)
		}
	}
}

func TestScoreSources(t *testing.T) {
	t.Parallel()
	got := candidates.Score(ev("wayback", "a", "crtsh", "b", "crtsh", "c", "wayback", "a"), nil)
	if want := []string{"crtsh", "wayback"}; !slices.Equal(got.Sources, want) {
		t.Errorf("sources = %v, want the distinct sources sorted: %v", got.Sources, want)
	}
	// Two identifiers are one family, but each value is its own source.
	got = candidates.Score(ev("identifier-pivot:G-AAAAAA1", "G-AAAAAA1", "identifier-pivot:111111111", "111111111"), nil)
	if want := []string{"identifier-pivot:111111111", "identifier-pivot:G-AAAAAA1"}; !slices.Equal(got.Sources, want) {
		t.Errorf("sources = %v, want each identifier: %v", got.Sources, want)
	}
}

// Family lookup handles source suffixes, retired sources and independent unknown sources.
func TestFamiliesOf(t *testing.T) {
	t.Parallel()
	for source, want := range map[string]string{
		"crtsh": "certificate transparency", "identifier-pivot": "web identifier",
		"identifier-pivot:G-AAAAAA1": "web identifier", "identifier-pivot:-1165240594": "web identifier",
		"crtsh:x": "certificate transparency", "something-new:x": "something-new:x", "something-new": "something-new",
		"otx": "passive dns", "anubis": "passive dns",
	} {
		if got := families.Of(source); got != want {
			t.Errorf("Of(%q) = %q, want %q", source, got, want)
		}
	}
}

// A family a procedure names takes the place of a retired source's.
func TestFamiliesNamedOverRetired(t *testing.T) {
	t.Parallel()
	f := candidates.NewFamilies(map[string]string{"otx": "otx"})
	if got := f.Of("otx"); got != "otx" {
		t.Errorf("Of(otx) = %q, want the family the procedure names", got)
	}
	if got := f.Of("anubis"); got != candidates.PassiveDNS {
		t.Errorf("Of(anubis) = %q, want passive dns", got)
	}
	if got := f.Sources(); !slices.Equal(got, []string{"anubis", "otx"}) {
		t.Errorf("Sources() = %v, want the named and the retired sources, sorted", got)
	}
}

// high first, then more evidence, then value; a row that is not current is
// last whatever it had, and keeps its own confidence.
func TestCompare(t *testing.T) {
	t.Parallel()
	rows := []candidates.Entry{
		{Value: "gone-high.org", Confidence: candidates.High, Count: 9, Current: false},
		{Value: "low-many.org", Confidence: candidates.Low, Count: 7, Current: true},
		{Value: "med-b.org", Confidence: candidates.Medium, Count: 2, Current: true},
		{Value: "high-few.org", Confidence: candidates.High, Count: 3, Current: true},
		{Value: "med-a.org", Confidence: candidates.Medium, Count: 2, Current: true},
		{Value: "high-many.org", Confidence: candidates.High, Count: 5, Current: true},
		{Value: "gone-low.org", Confidence: candidates.Low, Count: 1, Current: false},
	}
	slices.SortFunc(rows, candidates.Compare)
	var got []string
	for _, r := range rows {
		got = append(got, r.Value)
	}
	want := []string{"high-many.org", "high-few.org", "med-a.org", "med-b.org", "low-many.org", "gone-high.org", "gone-low.org"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %v\nwant    %v", got, want)
	}
}

func TestPromote(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ typ, value, want string }{
		{"root", "other.org", "other.org"},
		{"hostname", "www.other.org", "www.other.org"},
		{"netblock", "198.51.100.0/24", "--cidr 198.51.100.0/24"},
		{"asn", "AS64500", "--asn AS64500"},
		{"organisation", "Acme", "--org Acme"},
		{"organisation", "Acme Pty Ltd", "--org 'Acme Pty Ltd'"},
		{"organisation", "O'Neil & Sons", `--org 'O'\''Neil & Sons'`},
	} {
		if got := candidates.Promote(c.typ, c.value); got != c.want {
			t.Errorf("Promote(%q, %q) = %q, want %q", c.typ, c.value, got, c.want)
		}
	}
}

func rankOf(rs []candidates.Ranked, typ, value string) (candidates.Ranked, bool) {
	for _, r := range rs {
		if r.Type == typ && r.Value == value {
			return r, true
		}
	}
	return candidates.Ranked{}, false
}

// Current roots inherit current descendant-hostname evidence without changing hostname ranks.
func TestRankAllRollUp(t *testing.T) {
	t.Parallel()
	own := ev("crtsh", "a")
	cs := []candidates.Candidate{
		{Type: "root", Value: "other.org", Current: true, Evidence: own},
		{Type: "hostname", Value: "www.other.org", Current: true, Evidence: ev("wayback", "b")},
		{Type: "hostname", Value: "other.org", Current: true, Evidence: ev("rdns", "c")},
		{Type: "hostname", Value: "old.other.org", Current: false, Evidence: ev("httpprobe", "d")},
		{Type: "hostname", Value: "www.another.org", Current: true, Evidence: ev("httpprobe", "e")},
		{Type: "root", Value: "gone.org", Current: false, Evidence: ev("crtsh", "f")},
		{Type: "hostname", Value: "a.gone.org", Current: true, Evidence: ev("wayback", "g", "rdns", "h")},
	}
	got := candidates.RankAll(cs, map[candidates.Key]candidates.Rank{{Type: "root", Value: "gone.org"}: {Confidence: candidates.Low, Count: 1}}, nil)
	root, _ := rankOf(got, "root", "other.org")
	if want := []string{"crtsh", "rdns", "wayback"}; !slices.Equal(root.Sources, want) || root.Count != 3 || root.Confidence != candidates.High {
		t.Errorf("root = %+v, want the sources %v, 3 evidence and high", root, want)
	}
	if www, _ := rankOf(got, "hostname", "www.other.org"); www.Count != 1 || www.Confidence != candidates.Low {
		t.Errorf("hostname = %+v, want its own evidence only", www)
	}
	if gone, _ := rankOf(got, "root", "gone.org"); gone.Current || gone.Count != 1 {
		t.Errorf("a root that is not current = %+v, want its last rank and no roll-up", gone)
	}
	if len(own) != 1 || cap(own) != 1 {
		t.Errorf("the roll-up wrote to the caller's evidence: %v", own)
	}
}

// Unsupported or non-current candidates retain their previous rank where available.
func TestRankAllKeepsLastRank(t *testing.T) {
	t.Parallel()
	last := candidates.Rank{Sources: []string{"crtsh", "wayback"}, Count: 2, Confidence: candidates.Medium}
	lastOf := map[candidates.Key]candidates.Rank{
		{Type: "root", Value: "gone.org"}: last, {Type: "root", Value: "forgotten.org"}: last, {Type: "root", Value: "rerun.org"}: last,
	}
	cs := []candidates.Candidate{
		{Type: "root", Value: "gone.org", Current: false, Evidence: ev("crtsh", "a")},
		{Type: "root", Value: "forgotten.org", Current: true},
		{Type: "root", Value: "rerun.org", Current: true, Evidence: ev("crtsh", "a")},
		{Type: "root", Value: "never.org", Current: false, Evidence: ev("crtsh", "a")},
		{Type: "root", Value: "new.org", Current: true},
		{Type: "hostname", Value: "www.forgotten.org", Current: true, Evidence: ev("httpprobe", "b", "rdns", "c", "crawl", "d")},
	}
	got := candidates.RankAll(cs, lastOf, nil)
	if r, _ := rankOf(got, "root", "gone.org"); r.Current || r.Confidence != candidates.Medium || r.Count != 2 {
		t.Errorf("not current = %+v, want the last rank, not current", r)
	}
	if r, _ := rankOf(got, "root", "forgotten.org"); !r.Current || r.Confidence != candidates.Medium || r.Count != 2 {
		t.Errorf("no evidence of its own = %+v, want the last rank, current, whatever rolls up", r)
	}
	if r, _ := rankOf(got, "root", "rerun.org"); r.Confidence != candidates.Low || r.Count != 1 {
		t.Errorf("evidence of its own = %+v, want it ranked afresh", r)
	}
	if r, ok := rankOf(got, "root", "never.org"); ok {
		t.Errorf("never ranked and not current = %+v, want it left out", r)
	}
	if r, ok := rankOf(got, "root", "new.org"); !ok || !r.Current || r.Confidence != candidates.Low || r.Count != 0 {
		t.Errorf("never ranked, current, no evidence = %+v, %v, want a low rank", r, ok)
	}
}

// The summary lists the current candidates of high confidence, best first, by
// type when they tie.
func TestListed(t *testing.T) {
	t.Parallel()
	high := func(typ, value string, n int, current bool) candidates.Ranked {
		return candidates.Ranked{Type: typ, Value: value, Current: current, Count: n, Confidence: candidates.High}
	}
	got := candidates.Listed([]candidates.Ranked{
		high("root", "few.org", 3, true),
		high("root", "gone.org", 9, false),
		{Type: "root", Value: "medium.org", Current: true, Count: 9, Confidence: candidates.Medium},
		high("root", "tie.org", 5, true),
		high("hostname", "tie.org", 5, true),
		high("root", "many.org", 7, true),
	})
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Type+" "+r.Value)
	}
	if want := []string{"root many.org", "hostname tie.org", "root tie.org", "root few.org"}; !slices.Equal(keys, want) {
		t.Errorf("listed = %v\nwant     %v", keys, want)
	}
}

// The types the roll-up and Promote tell apart are the names of the kinds the
// candidates are.
func TestTypesAreKindNames(t *testing.T) {
	t.Parallel()
	var names []string
	for _, k := range kinds.CandidateKinds {
		names = append(names, k.Name())
	}
	if want := []string{"root", "hostname", "netblock", "asn", "organisation"}; !slices.Equal(names, want) {
		t.Errorf("candidate kinds = %v, want %v", names, want)
	}
}
