package cve

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/sanitize"
)

var allNames = []string{"id", "status", "published", "last_modified", "description", "cvss_version", "cvss_score",
	"cvss_severity", "cvss_vector", "cvss_source", "weaknesses", "affected_products_count", "affected_products", "references_count", "references"}

// defaultNames are the fields a lookup returns when --fields is not given: everything but the two lists.
var defaultNames = slices.DeleteFunc(slices.Clone(allNames), func(n string) bool { return n == "affected_products" || n == "references" })

func TestFields_NamesAreTheRecordsKeysInOrder(t *testing.T) {
	t.Parallel()
	if got := FieldNames(); !slices.Equal(got, allNames) {
		t.Errorf("FieldNames() = %v", got)
	}
	if got, want := ValidFields(), "valid fields: "+strings.Join(allNames, ", ")+", or all"; got != want {
		t.Errorf("ValidFields() = %q, want %q", got, want)
	}
}

// The selection keeps the table's order whatever order it was given in, always
// has id, ignores empty names and accepts all.
func TestFields_Select(t *testing.T) {
	t.Parallel()
	score, sev := 9.8, "CRITICAL"
	rec := Record{ID: "CVE-2024-0001", CVSSScore: &score, CVSSSeverity: &sev, Weaknesses: []string{}, AffectedProducts: []AffectedProduct{}, References: []Reference{}}
	all := strings.NewReplacer(`"affected_products":`, `"affected_products_count":{"total":0},"affected_products":`,
		`"references":`, `"references_count":{"total":0},"references":`).Replace(encode(t, rec))
	for _, c := range []struct{ spec, want string }{
		{"cvss_score", `{"id":"CVE-2024-0001","cvss_score":9.8}`},
		{"id,cvss_score", `{"id":"CVE-2024-0001","cvss_score":9.8}`},
		{" cvss_severity , cvss_score,,id ", `{"id":"CVE-2024-0001","cvss_score":9.8,"cvss_severity":"CRITICAL"}`},
		{"description,references", `{"id":"CVE-2024-0001","description":null,"references_count":{"total":0},"references":[]}`},
		{"", `{"id":"CVE-2024-0001"}`},
		{"all", all},
		{"cvss_score,all", all},
	} {
		f, unknown := Select(c.spec)
		if unknown != nil {
			t.Errorf("Select(%q): unknown %q", c.spec, unknown)
			continue
		}
		if got := encode(t, View{Fields: f}.Project(rec)); got != c.want {
			t.Errorf("Select(%q) projects to %s, want %s", c.spec, got, c.want)
		}
		if !f.Has("id") {
			t.Errorf("Select(%q) does not have id", c.spec)
		}
	}
}

func TestFields_UnknownNames(t *testing.T) {
	t.Parallel()
	if _, unknown := Select("cvss_score,bogus, severity ,all"); !slices.Equal(unknown, []string{"bogus", "severity"}) {
		t.Fatalf("Select's unknown names = %q, want bogus and severity", unknown)
	}
}

func TestFields_Has(t *testing.T) {
	t.Parallel()
	f, unknown := Select("cvss_score")
	if unknown != nil {
		t.Fatal(unknown)
	}
	for name, want := range map[string]bool{"id": true, "cvss_score": true, "cvss_severity": false, "bogus": false} {
		if f.Has(name) != want {
			t.Errorf("Has(%q) = %v", name, !want)
		}
	}
}

// A count can be named like any field, and a list brings its count with it.
func TestFields_CountsAndLists(t *testing.T) {
	t.Parallel()
	rec := Record{ID: "CVE-2024-0001", AffectedProducts: []AffectedProduct{{CPE: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}}, References: []Reference{{URL: "https://example.com/"}, {URL: "https://example.org/"}}}
	for _, c := range []struct{ spec, want string }{
		{"affected_products_count", `{"id":"CVE-2024-0001","affected_products_count":{"total":1}}`},
		{"references_count", `{"id":"CVE-2024-0001","references_count":{"total":2}}`},
		{"references_count,affected_products_count", `{"id":"CVE-2024-0001","affected_products_count":{"total":1},"references_count":{"total":2}}`},
		{"references", `{"id":"CVE-2024-0001","references_count":{"total":2},"references":[{"url":"https://example.com/","tags":null},{"url":"https://example.org/","tags":null}]}`},
		{"affected_products", `{"id":"CVE-2024-0001","affected_products_count":{"total":1},"affected_products":[{"cpe":"cpe:2.3:a:x:y:*:*:*:*:*:*:*:*","vendor":null,"product":null,"version":null,` +
			`"version_start_including":null,"version_start_excluding":null,"version_end_including":null,"version_end_excluding":null}]}`},
		{"", `{"id":"CVE-2024-0001"}`},
	} {
		if got := encode(t, View{Fields: selectFields(t, c.spec)}.Project(rec)); got != c.want {
			t.Errorf("Select(%q) projects to\n%s\nwant\n%s", c.spec, got, c.want)
		}
	}
	all := selectFields(t, "all")
	for _, name := range allNames {
		if !all.Has(name) {
			t.Errorf("all lacks %s", name)
		}
	}
}

// With no --fields the lists are left out and their counts are in.
func TestFields_Default(t *testing.T) {
	t.Parallel()
	rec := FromNVD(loadEntry(t, "long-lists.json"))
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encode(t, View{Fields: DefaultFields()}.Project(rec))), &got); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(got))
	if want := slices.Sorted(slices.Values(defaultNames)); !slices.Equal(keys, want) {
		t.Errorf("default keys %v, want %v", keys, want)
	}
	if string(got["affected_products_count"]) != `{"total":6}` || string(got["references_count"]) != `{"total":5}` {
		t.Errorf("counts %s, %s", got["affected_products_count"], got["references_count"])
	}
	for _, name := range allNames {
		if want := slices.Contains(defaultNames, name); DefaultFields().Has(name) != want {
			t.Errorf("DefaultFields().Has(%q) = %v", name, !want)
		}
	}
}

// A count's keys depend on the flags and never on the data: matched only under
// --match, and omitted only under --limit and only for a list that is shown.
func TestView_CountKeysFollowTheFlags(t *testing.T) {
	t.Parallel()
	rec := FromNVD(loadEntry(t, "long-lists.json"))
	for _, c := range []struct {
		name, spec, match string
		limit             int
		products, refs    string
	}{
		{"neither", "all", "", 0, `{"total":6}`, `{"total":5}`},
		{"match", "all", "log4j", 0, `{"total":6,"matched":3}`, `{"total":5,"matched":2}`},
		{"match with nothing matching", "all", "zzz", 0, `{"total":6,"matched":0}`, `{"total":5,"matched":0}`},
		{"limit", "all", "", 2, `{"total":6,"omitted":4}`, `{"total":5,"omitted":3}`},
		{"a limit longer than the list", "all", "", 100, `{"total":6,"omitted":0}`, `{"total":5,"omitted":0}`},
		{"both", "all", "log4j", 1, `{"total":6,"matched":3,"omitted":2}`, `{"total":5,"matched":2,"omitted":1}`},
		{"limit with only one list shown", "references,affected_products_count", "", 2, `{"total":6}`, `{"total":5,"omitted":3}`},
		{"match with the counts alone", "affected_products_count,references_count", "log4j", 0, `{"total":6,"matched":3}`, `{"total":5,"matched":2}`},
	} {
		var got struct {
			Products json.RawMessage `json:"affected_products_count"`
			Refs     json.RawMessage `json:"references_count"`
		}
		if err := json.Unmarshal([]byte(encode(t, View{Fields: selectFields(t, c.spec), Match: c.match, Limit: c.limit}.Project(rec))), &got); err != nil {
			t.Fatal(err)
		}
		if string(got.Products) != c.products || string(got.Refs) != c.refs {
			t.Errorf("%s: counts %s and %s, want %s and %s", c.name, got.Products, got.Refs, c.products, c.refs)
		}
	}
}

// cutJSON is the long-lists fixture's record cut by the fields, the match and the limit, as JSON.
func cutJSON(t *testing.T, spec, match string, limit int) (products, refs []json.RawMessage) {
	t.Helper()
	var got struct {
		Products []json.RawMessage `json:"affected_products"`
		Refs     []json.RawMessage `json:"references"`
	}
	rec := FromNVD(loadEntry(t, "long-lists.json"))
	if err := json.Unmarshal([]byte(encode(t, View{Fields: selectFields(t, spec), Match: match, Limit: limit}.Project(rec))), &got); err != nil {
		t.Fatal(err)
	}
	return got.Products, got.Refs
}

func versions(t *testing.T, products []json.RawMessage) []string {
	t.Helper()
	var out []string
	for _, p := range products {
		var ap AffectedProduct
		if err := json.Unmarshal(p, &ap); err != nil {
			t.Fatal(err)
		}
		out = append(out, shortForm(ap))
	}
	return out
}

// An affected product matches on the line human mode shows, ignoring case, and
// not on the fixed prefix of its CPE.
func TestView_MatchAffectedProducts(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		match string
		want  int
	}{
		{"log4j", 3}, {"LOG4J", 3}, {" log4j ", 3}, {"Log4J", 3},
		{"apache log4j", 3}, {"apache", 4}, {"2.3.1", 1}, {">= 2.0.1", 1}, {"< 2.12.2", 1}, {"(>= 2.0.1, < 2.3.1)", 1},
		{"vcenter", 1}, {"2.17.0", 1}, {"nginx", 0},
		// The CPE-only entry matches on the rest of its CPE and not on its prefix.
		{"node.js", 1}, {"*:*:*", 1}, {"cpe:2.3:a", 0}, {"2.3:a:", 0}, {"cpe", 0},
	} {
		products, _ := cutJSON(t, "affected_products", c.match, 0)
		if len(products) != c.want {
			t.Errorf("--match %q kept %d affected products %v, want %d", c.match, len(products), versions(t, products), c.want)
		}
	}
}

// The text matched is the NVD's, as --json writes it: a CPE escape is matched unescaped.
func TestView_MatchIsOnTheUnescapedText(t *testing.T) {
	t.Parallel()
	rec := FromNVD(loadEntry(t, "cpe-escapes.json"))
	for match, want := range map[string]int{"acme:labs": 1, "widget_pro!": 1, "1.0.2": 1, `acme\:labs`: 0, `widget\_pro`: 0} {
		got := View{Fields: selectFields(t, "affected_products"), Match: match}.Project(rec)
		if n := len(got.rec.AffectedProducts); n != want {
			t.Errorf("--match %q kept %d, want %d", match, n, want)
		}
	}
}

// A reference matches on its URL or any one of its tags.
func TestView_MatchReferences(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		match string
		want  int
	}{
		{"log4j", 2}, {"EXAMPLE.COM", 1}, {"vendor advisory", 2}, {"Patch", 2}, {"third party", 1}, {"mailing list", 1},
		{"https://example.com/advisory", 1}, {"nothing like this", 0},
	} {
		_, refs := cutJSON(t, "references", c.match, 0)
		if len(refs) != c.want {
			t.Errorf("--match %q kept %d references, want %d", c.match, len(refs), c.want)
		}
	}
}

// --limit keeps the first entries in the NVD's order, and --match comes first.
func TestView_LimitAfterMatch(t *testing.T) {
	t.Parallel()
	products, refs := cutJSON(t, "affected_products,references", "", 2)
	if got := versions(t, products); !slices.Equal(got, []string{"apache log4j (>= 2.0.1, < 2.3.1)", "apache log4j (>= 2.4.0, < 2.12.2)"}) {
		t.Errorf("--limit 2 products %v", got)
	}
	if len(refs) != 2 || !strings.Contains(string(refs[0]), "logging.apache.org") || !strings.Contains(string(refs[1]), "github.com") {
		t.Errorf("--limit 2 references %s", refs)
	}
	products, _ = cutJSON(t, "affected_products", "apache", 3)
	if got := versions(t, products); !slices.Equal(got, []string{"apache log4j (>= 2.0.1, < 2.3.1)", "apache log4j (>= 2.4.0, < 2.12.2)", "apache log4j 2.17.0"}) {
		t.Errorf("--match apache --limit 3 products %v", got)
	}
	// The match first: the first matching entry is the third of the list.
	products, _ = cutJSON(t, "affected_products", "tomcat", 1)
	if got := versions(t, products); !slices.Equal(got, []string{"apache tomcat 9.0.1"}) {
		t.Errorf("--match tomcat --limit 1 products %v", got)
	}
	// Nothing matching is an empty list, not null.
	if products, refs = cutJSON(t, "affected_products,references", "zzz", 0); products == nil || refs == nil || len(products)+len(refs) != 0 {
		t.Errorf("nothing matching: %v and %v, want empty lists", products, refs)
	}
}

// The cut leaves the record it was given alone, and the limit and match of a list
// that is not shown still count it.
func TestView_ProjectDoesNotChangeTheRecord(t *testing.T) {
	t.Parallel()
	rec := FromNVD(loadEntry(t, "long-lists.json"))
	before := encode(t, rec)
	_ = View{Fields: selectFields(t, "all"), Match: "log4j", Limit: 1}.Project(rec)
	if after := encode(t, rec); after != before {
		t.Errorf("the record changed:\n%s\n%s", before, after)
	}
}

func TestListHint(t *testing.T) {
	t.Parallel()
	long := FromNVD(loadEntry(t, "long-lists.json"))
	productsOnly := Record{ID: "CVE-2024-0001", AffectedProducts: []AffectedProduct{{CPE: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}}}
	none := Record{ID: "CVE-2024-0002", AffectedProducts: []AffectedProduct{}, References: []Reference{}}
	const both = "use --fields affected_products,references (or --fields all) to list them"
	const refs = "use --fields references (or --fields all) to list them"
	for _, c := range []struct {
		name string
		view View
		recs []Record
		want string
	}{
		{"the default names both", View{Fields: DefaultFields()}, []Record{long}, both},
		{"only the id names both", View{Fields: selectFields(t, "id")}, []Record{long}, both},
		{"a list empty in every record is not named", View{Fields: DefaultFields()}, []Record{productsOnly, none}, "use --fields affected_products (or --fields all) to list them"},
		{"one list shown leaves one", View{Fields: selectFields(t, "affected_products")}, []Record{long}, refs},
		{"every list shown says nothing", View{Fields: selectFields(t, "all")}, []Record{long}, ""},
		{"both lists shown says nothing", View{Fields: selectFields(t, "affected_products,references")}, []Record{long}, ""},
		{"every list left out is empty", View{Fields: DefaultFields()}, []Record{none, none}, ""},
		{"no record", View{Fields: DefaultFields()}, nil, ""},
		{"a match counts only matching entries", View{Fields: DefaultFields(), Match: "tomcat"}, []Record{long}, "use --fields affected_products (or --fields all) to list them"},
		{"a match with nothing matching says nothing", View{Fields: DefaultFields(), Match: "zzz"}, []Record{long}, ""},
		{"a match matching only references", View{Fields: DefaultFields(), Match: "vmware"}, []Record{long}, both},
		{"a match matching only references, products shown", View{Fields: selectFields(t, "affected_products"), Match: "psirt"}, []Record{long}, refs},
	} {
		if got := ListHint(projectAll(c.view, c.recs)); got != c.want {
			t.Errorf("%s: ListHint = %q, want %q", c.name, got, c.want)
		}
	}
}

// productLine with the display's cleaning is the line human mode shows.
func TestProductLine(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		ap   AffectedProduct
		want string
	}{
		{AffectedProduct{Vendor: new("apache"), Product: new("log4j"), VersionStartIncluding: new("2.0.1"), VersionEndExcluding: new("2.3.1")}, "apache log4j (>= 2.0.1, < 2.3.1)"},
		{AffectedProduct{Vendor: new("apache"), Product: new("tomcat"), Version: new("9.0.1")}, "apache tomcat 9.0.1"},
		{AffectedProduct{CPE: "cpe:2.3:a:*:*:*:*:*:*:*:node.js:*:*"}, "cpe:2.3:a:*:*:*:*:*:*:*:node.js:*:*"},
		{AffectedProduct{Vendor: new("a\nb"), Product: new("c\td"), VersionStartExcluding: new("1\x1b[2J"), VersionEndIncluding: new("2")}, "a b c d (> 1, <= 2)"},
	} {
		if got, short := productLine(c.ap, sanitize.Line, sanitize.Line), shortForm(c.ap); got != c.want || short != c.want {
			t.Errorf("productLine = %q, shortForm = %q, want %q", got, short, c.want)
		}
	}
	// With no cleaning the NVD's text is as given.
	raw := AffectedProduct{Vendor: new("a\nb"), Product: new("c")}
	if got := productLine(raw, func(s string) string { return s }, func(s string) string { return s }); got != "a\nb c" {
		t.Errorf("productLine without cleaning = %q", got)
	}
}
