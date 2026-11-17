// Package eol holds the end of security support of the release cycles of the products nyx can
// version, as endoflife.date records them. The data is embedded: one JSON file per product, as
// endoflife.date publishes it, under data/; products.yaml, which says which detected names
// (a Wappalyzer technology or a banner product) belong to which product and how a version names
// its release cycle; and DATE, the day the data was taken. `make eol-data` refreshes all three.
// The package does no I/O.
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

// cycleRecord is one release cycle as endoflife.date publishes it. EOL is the date security
// support ends, or a boolean: false when no end is announced, true when the cycle has ended
// on no known date.
type cycleRecord struct {
	Cycle string `json:"cycle"`
	EOL   any    `json:"eol"`
}

// product is a product with its cycles and how many parts of a version name one.
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

// load reads products.yaml and each product's data file. The embedded files are checked by
// a test, so one that does not parse leaves its product out.
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

// find returns the cycle of version among cycles: the one named by its first parts dotted
// numbers, or by fewer when there is none of that length. A cycle with no end announced
// matches nothing, and one that ended on no known date has an empty end.
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

// Lookup returns the cycle a version of the named product belongs to and the date its security
// support ends (YYYY-MM-DD; empty when the cycle ended on no known date). The name is a
// Wappalyzer technology or a banner product, in any case. ok is false for a name or version
// the table cannot match, and for a cycle with no end announced.
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
