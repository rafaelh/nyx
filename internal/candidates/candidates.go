// Package candidates ranks discoveries outside scope by the independent evidence supporting
// them. Evidence pairs a source with the item linking a candidate to the engagement. Procedures
// group sources into families; confidence depends on which families agree. This package
// performs no I/O and does not read scope or the store.
package candidates

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/shellquote"
)

// Confidence indicates how strongly the evidence supports adding a candidate to scope.
type Confidence string

const (
	Low    Confidence = "low"
	Medium Confidence = "medium"
	High   Confidence = "high"
)

func (c Confidence) rank() int {
	switch c {
	case High:
		return 0
	case Medium:
		return 1
	default:
		return 2
	}
}

// Evidence links a candidate to a source and supporting item. An empty Family gives the source
// its own independent family.
type Evidence struct{ Source, Item, Family string }

type Rank struct {
	Sources    []string // the distinct sources, sorted
	Count      int      // the distinct (source, item) pairs
	Confidence Confidence
}

// Procedures group related sources into these families. Undeclared sources each form their own
// family.
const (
	CertTransparency = "certificate transparency"
	WebArchive       = "web archive"
	PassiveDNS       = "passive dns"
	ReverseIP        = "reverse ip"
	Registrant       = "registrant"
	SharedInfra      = "shared infrastructure"
	WebIdentifier    = "web identifier"
)

// retired preserves the passive-DNS classification of OTX and Anubis evidence saved by older
// versions.
var retired = map[string]string{"otx": PassiveDNS, "anubis": PassiveDNS}

// Families groups evidence sources by discovery mechanism.
type Families struct{ m map[string]string }

// NewFamilies combines procedure-declared source families with mappings for retired sources.
func NewFamilies(named map[string]string) Families {
	m := maps.Clone(retired)
	maps.Copy(m, named)
	return Families{m}
}

// Of returns a source's family. A suffix after a colon, such as "identifier-pivot:G-ABC123",
// identifies a result rather than a new source family.
func (f Families) Of(source string) string {
	if fam, ok := f.m[source]; ok {
		return fam
	}
	if name, _, ok := strings.Cut(source, ":"); ok {
		if fam, ok := f.m[name]; ok {
			return fam
		}
	}
	return source
}

// Sources returns sorted source names for display. Sources with result-specific suffixes are
// listed under the name before the colon.
func (f Families) Sources() []string {
	return slices.Sorted(maps.Keys(f.m))
}

// Score calculates confidence from independent evidence families. Confidence is high with three
// families, or a registrant match plus another family. It is medium with two families,
// self-hosted name-server/mail evidence, reverse-IP evidence on multiple addresses, or a
// registrant match alone. Otherwise it is low.
//
// A registrant match requires evidence from a registrant-family source queried for an --org
// input. Registry lookups apply orgname's word matching where possible; organisation search
// services perform their own matching.
func Score(ev []Evidence, orgs []string) Rank {
	pairs := map[Evidence]bool{}
	sources := map[string]bool{}
	fams := map[string]bool{}
	reverseItems := map[string]bool{}
	match := false
	for _, e := range ev {
		if pairs[e] {
			continue
		}
		pairs[e] = true
		sources[e.Source] = true
		f := cmp.Or(e.Family, e.Source)
		fams[f] = true
		switch f {
		case ReverseIP:
			reverseItems[e.Item] = true
		case Registrant:
			match = match || slices.Contains(orgs, e.Item)
		}
	}
	r := Rank{Sources: slices.Sorted(maps.Keys(sources)), Count: len(pairs), Confidence: Low}
	switch {
	case match && len(fams) > 1, len(fams) >= 3:
		r.Confidence = High
	case len(fams) == 2, fams[SharedInfra], len(reverseItems) >= 2, match:
		r.Confidence = Medium
	}
	return r
}

// Candidate types correspond to the record kinds used by ranking and scope promotion.
const (
	typeRoot         = "root"
	typeHostname     = "hostname"
	typeNetblock     = "netblock"
	typeASN          = "asn"
	typeOrganisation = "organisation"
)

// Candidate pairs a discovered entity with the evidence from its completed jobs. Type is its
// record kind: root, hostname, netblock, asn or organisation.
type Candidate struct {
	Type, Value string
	Current     bool
	Evidence    []Evidence
}

type Key struct{ Type, Value string }

type Ranked struct {
	Type, Value string
	Current     bool
	Rank
}

// RankAll preserves input order and calculates ranks from current evidence. Candidate roots
// also inherit evidence from current candidate hostnames beneath them, allowing root and
// hostname discoveries to corroborate each other. Hostnames retain their own ranks.
//
// Non-current candidates keep their last rank. Current candidates without direct evidence also
// keep their rank while redo jobs are pending; inherited hostname evidence alone cannot make
// a root current. Candidates without a rank to preserve are omitted.
func RankAll(cs []Candidate, last map[Key]Rank, orgs []string) []Ranked {
	support := make([][]Evidence, len(cs))
	roots := map[string]int{} // the current candidate roots, by value
	for i, c := range cs {
		support[i] = slices.Clip(c.Evidence) // clone before appending rolled-up evidence to avoid changing the caller's slice
		if c.Current && c.Type == typeRoot {
			roots[c.Value] = i
		}
	}
	for _, h := range cs {
		if !h.Current || h.Type != typeHostname {
			continue
		}
		for name := h.Value; ; {
			if i, ok := roots[name]; ok {
				support[i] = append(support[i], h.Evidence...)
			}
			_, rest, found := strings.Cut(name, ".")
			if !found {
				break
			}
			name = rest
		}
	}
	var out []Ranked
	for i, c := range cs {
		rank, ok := last[Key{c.Type, c.Value}]
		if c.Current && (len(c.Evidence) > 0 || !ok) {
			rank = Score(support[i], orgs)
		} else if !ok {
			continue
		}
		out = append(out, Ranked{Type: c.Type, Value: c.Value, Current: c.Current, Rank: rank})
	}
	return out
}

// Listed returns current high-confidence candidates, best first, for the summary. Other
// candidates remain in candidates.csv.
func Listed(rs []Ranked) []Ranked {
	var out []Ranked
	for _, r := range rs {
		if r.Current && r.Confidence == High {
			out = append(out, r)
		}
	}
	entry := func(r Ranked) Entry {
		return Entry{Value: r.Value, Current: true, Confidence: High, Count: r.Count}
	}
	slices.SortFunc(out, func(a, b Ranked) int {
		return cmp.Or(Compare(entry(a), entry(b)), strings.Compare(a.Type, b.Type))
	})
	return out
}

// Entry supplies the fields used to sort candidates.
type Entry struct {
	Value      string
	Current    bool
	Confidence Confidence
	Count      int
}

// Compare orders candidates.csv by current status, confidence, evidence count and value.
// Non-current rows retain their previous confidence but sort after current rows.
func Compare(a, b Entry) int {
	if a.Current != b.Current {
		if a.Current {
			return -1
		}
		return 1
	}
	return cmp.Or(
		cmp.Compare(a.Confidence.rank(), b.Confidence.rank()),
		cmp.Compare(b.Count, a.Count),
		strings.Compare(a.Value, b.Value),
	)
}

// Promote returns the CLI input that adds a candidate to scope: a positional domain, --cidr,
// --asn or --org value.
func Promote(typ, value string) string {
	switch typ {
	case typeNetblock:
		return "--cidr " + shellquote.Quote(value)
	case typeASN:
		return "--asn " + shellquote.Quote(value)
	case typeOrganisation:
		return "--org " + shellquote.Quote(value)
	}
	return value
}
