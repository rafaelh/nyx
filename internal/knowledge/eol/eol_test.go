package eol

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// cyclesOf reads a list of cycles as endoflife.date publishes them.
func cyclesOf(t *testing.T, doc string) []cycleRecord {
	t.Helper()
	var c []cycleRecord
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Cycle lookup tries the product's preferred dotted version length, then shorter supported
// forms.
func TestFind_CycleShapes(t *testing.T) {
	t.Parallel()
	mixed := cyclesOf(t, `[{"cycle":"12.1","eol":"2030-01-01"},{"cycle":"11","eol":"2025-01-01"},{"cycle":"9.4","eol":"2020-02-02"}]`)
	for _, tc := range []struct {
		name    string
		parts   int
		cycles  []cycleRecord
		version string
		cycle   string
		end     string
		ok      bool
	}{
		{"major", 1, cyclesOf(t, `[{"cycle":"8","eol":"2023-01-24"}]`), "8.83.1", "8", "2023-01-24", true},
		{"minor", 2, cyclesOf(t, `[{"cycle":"5.6","eol":"2018-12-31"}]`), "5.6.40", "5.6", "2018-12-31", true},
		{"patch with letters after the number", 3, cyclesOf(t, `[{"cycle":"1.3.5","eol":"2020-07-20"}]`), "1.3.5e", "1.3.5", "2020-07-20", true},
		{"a leading v", 2, cyclesOf(t, `[{"cycle":"3.1","eol":"2024-01-01"}]`), "v3.1.4", "3.1", "2024-01-01", true},
		{"a version of only the major part", 2, cyclesOf(t, `[{"cycle":"3","eol":"2024-01-01"}]`), "3", "3", "2024-01-01", true},
		{"falls back from minor to major", 2, mixed, "11.0.20", "11", "2025-01-01", true},
		{"prefers the longer cycle", 2, mixed, "12.1.5", "12.1", "2030-01-01", true},
		{"a minor cycle for a major-only version", 2, mixed, "9", "", "", false},
		{"no cycle of that version", 2, mixed, "13.0.1", "", "", false},
		{"a cycle with no end announced", 2, cyclesOf(t, `[{"cycle":"2.4","eol":false}]`), "2.4.58", "", "", false},
		{"a cycle that ended on no known date", 1, cyclesOf(t, `[{"cycle":"1","eol":true}]`), "1.12.4", "1", "", true},
		{"a cycle name is not a prefix of a longer number", 2, cyclesOf(t, `[{"cycle":"1.1","eol":"2020-01-01"}]`), "1.10.2", "", "", false},
		{"a version with no number", 2, mixed, "latest", "", "", false},
		{"an empty version", 2, mixed, "", "", "", false},
	} {
		cycle, end, ok := find(tc.parts, tc.cycles, tc.version)
		if cycle != tc.cycle || end != tc.end || ok != tc.ok {
			t.Errorf("%s: find(%q) = %q %q %v, want %q %q %v", tc.name, tc.version, cycle, end, ok, tc.cycle, tc.end, tc.ok)
		}
	}
}

// Embedded lookup is case-insensitive and returns nothing for unsupported products or versions.
func TestLookup_EmbeddedData(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version, cycle, end string
		ok                        bool
	}{
		{"Nginx", "1.18.0", "1.18", "2021-04-20", true},
		{"nginx", "1.18.0", "1.18", "2021-04-20", true},
		{"PHP", "5.6.40", "5.6", "2018-12-31", true},
		{"Apache HTTP Server", "2.2.34", "2.2", "2017-07-11", true},
		{"Laravel", "8.1.0", "8", "2023-01-24", true},
		{"Laravel", "5.8.38", "5.8", "2020-02-26", true}, // cycles 13 to 6, then 5.8 and 5.5
		{"Ruby", "1.9.3", "1.9.3", "2015-02-23", true},   // cycles 4.0 to 2.1, then 2.0.0 and 1.9.3
		{"Ruby", "2.7.8", "2.7", "2023-03-31", true},
		{"ProFTPD", "1.3.5e", "1.3.5", "2020-07-20", true},
		{"Exim", "4.94.2", "4.94", "2021-09-28", true},
		{"Postfix", "3.4.13", "3.4", "2023-04-17", true},
		{"jQuery", "1.12.4", "1", "", true},
		{"Jenkins", "2.492.3", "2.492", "2025-04-30", true},
		{"Varnish", "6.0", "6.0", "2027-04-15", true},
		{"Concrete CMS", "8.5.4", "8", "2025-08-05", true}, // cycles 9, 8, 5.7: fewer parts
		{"Jenkins", "2.600", "", "", false},                // a weekly release: the 2 line has no end
		{"Apache HTTP Server", "2.4.58", "", "", false},    // 2.4 has no end announced
		{"Nginx", "0.1.0", "", "", false},                  // older than the table
		{"Nginx", "", "", "", false},
		{"Unknown Server", "1.0", "", "", false},
		{"", "1.0", "", "", false},
	} {
		cycle, end, ok := Lookup(tc.name, tc.version)
		if cycle != tc.cycle || end != tc.end || ok != tc.ok {
			t.Errorf("Lookup(%q, %q) = %q %q %v, want %q %q %v", tc.name, tc.version, cycle, end, ok, tc.cycle, tc.end, tc.ok)
		}
	}
}

// Validate product mappings, cycle lengths and one-to-one embedded file coverage.
func TestProducts_EveryEntryHasData(t *testing.T) {
	t.Parallel()
	var entries []entry
	if err := yaml.Unmarshal(productsYAML, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("products.yaml lists no product")
	}
	listed, names := map[string]bool{}, map[string]string{}
	for _, e := range entries {
		listed[e.Product+".json"] = true
		b, err := fs.ReadFile(dataFS, "data/"+e.Product+".json")
		if err != nil {
			t.Errorf("%s: no data file: %v", e.Product, err)
			continue
		}
		cycles := cyclesOf(t, string(b))
		if len(cycles) == 0 {
			t.Errorf("%s: data file has no cycles", e.Product)
		}
		parts, ok := cycleParts[e.Cycle]
		if !ok {
			t.Errorf("%s: cycle %q is not major, minor or patch", e.Product, e.Cycle)
		}
		// A cycle named by more parts than the entry says could never be matched.
		for _, c := range cycles {
			if n := len(strings.Split(c.Cycle, ".")); ok && n > parts {
				t.Errorf("%s: cycle %q has %d parts, more than %q (%d)", e.Product, c.Cycle, n, e.Cycle, parts)
			}
		}
		if len(e.Names) == 0 {
			t.Errorf("%s: no names", e.Product)
		}
		for _, n := range e.Names {
			if prev := names[strings.ToLower(n)]; prev != "" {
				t.Errorf("name %q is both %s and %s", n, prev, e.Product)
			}
			names[strings.ToLower(n)] = e.Product
		}
	}
	files, _ := fs.ReadDir(dataFS, "data")
	for _, f := range files {
		if !listed[f.Name()] {
			t.Errorf("data/%s belongs to no entry of products.yaml", f.Name())
		}
	}
}

// DataDate is the day the data was taken, a date; the Makefile target rewrites it.
func TestDataDate_IsADate(t *testing.T) {
	t.Parallel()
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(DataDate()) {
		t.Errorf("DataDate = %q", DataDate())
	}
}

// The Makefile downloads exactly the products products.yaml lists, with curl and no Go code.
func TestMakefile_DownloadsTheListedProducts(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"eol-data:", "curl", "internal/knowledge/eol/products.yaml", "internal/knowledge/eol/DATE"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Makefile does not contain %q", want)
		}
	}
}
