// Package eol matches detected product versions to embedded endoflife.date security-support
// cycles without I/O. products.yaml maps detection names and version patterns to product data;
// DATE records the snapshot date. make eol-data refreshes product JSON and DATE.
package eol

import (
	"embed"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed data/*.json
var dataFS embed.FS

//go:embed products.yaml
var productsYAML []byte

//go:embed DATE
var dateFile string

// cycleParts is how many dotted parts of a version a product's cycles are named by.
var cycleParts = map[string]int{"major": 1, "minor": 2, "patch": 3}

// cycleRecord follows endoflife.date: EOL is a security-support date, false for no announced
// end, or true for ended support without a known date.
type cycleRecord struct {
	Cycle string `json:"cycle"`
	EOL   any    `json:"eol"`
}

// product associates support cycles with their version-prefix length.
type product struct {
	parts  int
	cycles []cycleRecord
}

// products maps a lower-cased name to its product, and names lists the names as written.
type products struct {
	byName map[string]*product
	names  []string
}

// entry is one entry of products.yaml.
type entry struct {
	Product string   `yaml:"product"`
	Cycle   string   `yaml:"cycle"`
	Names   []string `yaml:"names"`
}

// load reads embedded product mappings and cycles. Invalid product files are skipped; tests
// validate embedded data.
var load = sync.OnceValue(func() products {
	var entries []entry
	out := products{byName: map[string]*product{}}
	if yaml.Unmarshal(productsYAML, &entries) != nil {
		return out
	}
	for _, e := range entries {
		b, err := dataFS.ReadFile("data/" + e.Product + ".json")
		if err != nil {
			continue
		}
		p := &product{parts: cycleParts[e.Cycle]}
		if json.Unmarshal(b, &p.cycles) != nil || p.parts == 0 {
			continue
		}
		for _, n := range e.Names {
			out.byName[strings.ToLower(n)] = p
			out.names = append(out.names, n)
		}
	}
	slices.Sort(out.names)
	return out
})

// leadingNumber is the dotted number a version starts with, ignoring a leading v: "1.3.5e" and
// "7.4.3-4ubuntu2" give 1.3.5 and 7.4.3.
var leadingNumber = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// find matches a version's dotted prefix to a cycle, trying shorter prefixes if needed. Cycles
// with no announced end are ignored; ended cycles without a date return an empty end.
func find(parts int, cycles []cycleRecord, version string) (cycle, end string, ok bool) {
	m := leadingNumber.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return "", "", false
	}
	nums := strings.Split(m[1], ".")
	for n := min(parts, len(nums)); n >= 1; n-- {
		name := strings.Join(nums[:n], ".")
		for _, c := range cycles {
			if c.Cycle != name {
				continue
			}
			switch v := c.EOL.(type) {
			case string:
				return c.Cycle, v, true
			case bool:
				if v {
					return c.Cycle, "", true
				}
			}
			return "", "", false
		}
	}
	return "", "", false
}

// Lookup accepts a case-insensitive detected product name and version. It returns the matched
// cycle and support-end date, empty for ended cycles without a date. Unknown products/versions
// and unannounced ends return ok=false.
func Lookup(name, version string) (cycle, end string, ok bool) {
	p := load().byName[strings.ToLower(strings.TrimSpace(name))]
	if p == nil {
		return "", "", false
	}
	return find(p.parts, p.cycles, version)
}

// Names lists every name the table can look up, sorted.
func Names() []string { return slices.Clone(load().names) }

// DataDate is the day (YYYY-MM-DD) the embedded data was taken.
func DataDate() string { return strings.TrimSpace(dateFile) }
