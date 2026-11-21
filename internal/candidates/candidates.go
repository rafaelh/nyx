// Package candidates ranks the candidates (roots, hostnames, netblocks,
// autonomous systems and organisations found but not in scope) by how many
// independent signals support them, and orders and lists them. It is pure: it
// reads no store, scope or file.
//
// A candidate's evidence is a list of (source, item) pairs: the source is the
// stage or mechanism that observed it, the item is what linked it (an
// organisation, an address, a netblock, a root, a service). Sources are grouped
// into families, and the confidence is decided by how many families agree and
// by which. See Score for the rules.
package candidates

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/shellquote"
)

// Confidence is how far a candidate's evidence supports promoting it to scope.
type Confidence string

// The confidence levels.
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

// Evidence is one source and the item that linked the candidate.
type Evidence struct{ Source, Item string }

// Rank is the ranking of one candidate.
type Rank struct {
	Sources    []string // the distinct sources, sorted
	Count      int      // the distinct (source, item) pairs
	Confidence Confidence
}

// The families. A source outside the table is a family of its own, named after it.
const (
	certTransparency = "certificate transparency"
	webArchive       = "web archive"
	passiveDNS       = "passive dns"
	reverseIP        = "reverse ip"
	registrant       = "registrant"
	sharedInfra      = "shared infrastructure"
	webIdentifier    = "web identifier"
)

// families maps a source (a stage name, or the mechanism a stage reports) to
// its family. A source that is its own family is listed with its own name, so
// that Sources lists every value the sources column can hold. org-asn is a
// registrant source on the assumption that RIPEstat's organisation search
// matches registry organisation names; ct-org searches certificates by their
// organisation, so it is a certificate transparency source.
var families = map[string]string{
	"crtsh": certTransparency, "certspotter": certTransparency, "censys": certTransparency, "ct-org": certTransparency,
	"wayback": webArchive, "commoncrawl": webArchive,
	// otx and anubis are no longer run; they stay so that what an engagement
	// stored from them still counts as passive DNS, not as a family of its own.
	"otx": passiveDNS, "virustotal": passiveDNS, "securitytrails": passiveDNS, "shodan": passiveDNS,
	"shodan-dns": passiveDNS, "shodan-host": passiveDNS, "chaos": passiveDNS, "urlscan": passiveDNS, "anubis": passiveDNS, "hackertarget": passiveDNS,
	"reverseip":        reverseIP,
	"rdap":             registrant,
	"whoisxml":         registrant,
	"org-asn":          registrant,
	"shared-ns":        sharedInfra,
	"shared-mx":        sharedInfra,
	"identifier-pivot": webIdentifier,
	// Their own families.
	"httpprobe": "httpprobe", "rdns": "rdns", "crawl": "crawl",
}

// Family is the family a source belongs to. A source may carry what it found
// after a colon ("identifier-pivot:G-ABC123"): it belongs to the family of the
// part before the colon, so that each such value is not a family of its own.
func Family(source string) string {
	if f, ok := families[source]; ok {
		return f
	}
	if name, _, ok := strings.Cut(source, ":"); ok {
		if f, ok := families[name]; ok {
			return f
		}
	}
	return source
}

// Sources lists every source the family table names, sorted: the values the
// sources column can hold for a stage this package knows, apart from a source
// that carries what it found after a colon (see Family), which is listed by the
// name before the colon.
func Sources() []string {
	return slices.Sorted(maps.Keys(families))
}

// Score ranks a candidate's evidence. orgs are the --org inputs.
//
// The confidence is high when a registrant-family match of an input
// organisation is joined by any other family, or three or more families agree;
// medium with two families, or a shared name server or mail host, or reverse IP
// on two or more addresses, or a registrant match alone; low otherwise. A
// registrant match is evidence from a registrant-family source whose item is an
// input organisation, that is, a source that was asked about that organisation
// (a registry lookup applies the word rule of package orgname to the names it
// gets back where it can; a search by organisation name leaves it to the
// service), so without an --org input the rule never applies. A shared
// name server or mail host is shared-infrastructure evidence: its stage reports
// only self-hosted ones.
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
		f := Family(e.Source)
		fams[f] = true
		switch f {
		case reverseIP:
			reverseItems[e.Item] = true
		case registrant:
			match = match || slices.Contains(orgs, e.Item)
		}
	}
	r := Rank{Sources: slices.Sorted(maps.Keys(sources)), Count: len(pairs), Confidence: Low}
	switch {
	case match && len(fams) > 1, len(fams) >= 3:
		r.Confidence = High
	case len(fams) == 2, fams[sharedInfra], len(reverseItems) >= 2, match:
		r.Confidence = Medium
	}
	return r
}

// The types of candidate the roll-up and Promote tell apart: the names of the
// record kinds the candidates are.
const (
	typeRoot         = "root"
	typeHostname     = "hostname"
	typeNetblock     = "netblock"
	typeASN          = "asn"
	typeOrganisation = "organisation"
)

// Candidate is one candidate and the evidence of the completed checks that
// observe it. Type is the kind of record it is ("root", "hostname",
// "netblock", "asn" or "organisation").
type Candidate struct {
	Type, Value string
	Current     bool
	Evidence    []Evidence
}

// Key names a candidate.
type Key struct{ Type, Value string }

// Ranked is a candidate and its rank.
type Ranked struct {
	Type, Value string
	Current     bool
	Rank
}

// RankAll ranks the candidates, in the order given. last is the rank each
// candidate last had while it was current.
//
// A current candidate root also counts the evidence of every current candidate
// hostname under it (or equal to it), so that stages that report roots and
// stages that report hostnames can corroborate each other; the hostnames keep
// their own rank. A candidate that is no longer current keeps its last rank. So
// does a current candidate with no evidence of its own: it is observed only by
// checks a redo has forgotten and that have not run again (evidence rolled up
// from hostnames does not make a root current), and it keeps its last rank
// until they do, so that a candidate they no longer find shows the rank it had
// while supported. A candidate with no rank to keep is left out.
func RankAll(cs []Candidate, last map[Key]Rank, orgs []string) []Ranked {
	support := make([][]Evidence, len(cs))
	roots := map[string]int{} // the current candidate roots, by value
	for i, c := range cs {
		support[i] = slices.Clip(c.Evidence) // so that the roll-up does not write to the caller's array
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

// Listed are the candidates the summary lists, best first: the current ones
// of high confidence. The rest are in candidates.csv only.
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

// Entry is what the sort order looks at.
type Entry struct {
	Value      string
	Current    bool
	Confidence Confidence
	Count      int
}

// Compare is the sort order of candidates.csv: rows that are current first,
// then high before medium before low, then more evidence, then by value. A row
// that is not current keeps the confidence it last had, and sorts last.
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

// Promote is the input that brings a candidate of the type into scope, as the
// user would type it: a root or hostname as a positional domain, a netblock as
// --cidr, an autonomous system as --asn and an organisation as --org.
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
