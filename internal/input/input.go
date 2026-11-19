// Package input parses and validates the inputs given on the command line:
// domains, organisations, ASNs, CIDRs and exclusions.
package input

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/dnsname"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Raw is the unvalidated input as given on the command line.
type Raw struct {
	Domains     []string
	DomainsFile string
	Orgs        []string
	ASNs        []string
	CIDRs       []string
	Exclude     []string
	ExcludeFile string
}

// Parsed holds canonical, de-duplicated inputs (sorted, except First).
type Parsed struct {
	Roots      []string
	Orgs       []string
	ASNs       []string // "AS123"
	CIDRs      []string // masked
	Exclusions []string // canonical entries
	First      string   // first input, used to name the engagement
}

// Empty reports whether no scope inputs were given.
func (p Parsed) Empty() bool {
	return len(p.Roots)+len(p.Orgs)+len(p.ASNs)+len(p.CIDRs) == 0
}

// NormaliseHost trims, lowercases and drops the trailing dot of a hostname.
func NormaliseHost(h string) string { return dnsname.Normalise(h) }

// IPLiteral parses host as an IP address, unmapped. A zoned address is not a
// literal egress will dial, and a bracketed form is a URL authority, not a host.
func IPLiteral(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ParseDomain lowercases, converts to punycode and validates a root domain.
// Public suffixes and IP literals are rejected.
func ParseDomain(s string) (string, error) {
	d := NormaliseHost(s)
	if d == "" {
		return "", fmt.Errorf("invalid domain %q: empty", s)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("invalid domain %q: IP addresses are not domains", s)
	}
	if strings.ContainsAny(d, "/:@ _*") {
		return "", fmt.Errorf("invalid domain %q: contains characters not allowed in a hostname", s)
	}
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %v", s, err)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain %q: too long", s)
	}
	for _, label := range strings.Split(ascii, ".") {
		if !dnsname.ValidLabel(label) {
			return "", fmt.Errorf("invalid domain %q: bad label %q", s, label)
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", fmt.Errorf("invalid domain %q: it is a public suffix, not a registrable domain", s)
	}
	return ascii, nil
}

// ParseOrg trims an organisation name and requires it to be non-empty.
func ParseOrg(s string) (string, error) {
	o := strings.TrimSpace(s)
	if o == "" {
		return "", fmt.Errorf("invalid organisation %q: empty", s)
	}
	return o, nil
}

// ParseASN accepts "AS123" or "123" (1..4294967295) and returns "AS123".
func ParseASN(s string) (string, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "AS"), "as")
	n, err := strconv.ParseUint(t, 10, 32)
	if err != nil || n < 1 || strings.HasPrefix(t, "+") {
		return "", fmt.Errorf("invalid ASN %q: want AS<number> in 1..4294967295", s)
	}
	return "AS" + strconv.FormatUint(n, 10), nil
}

// RangeCIDRs splits the inclusive range of addresses into the fewest CIDR
// prefixes that cover it exactly, in address order. It returns nil if the
// ends are not both valid, of one family, and in order.
func RangeCIDRs(start, end netip.Addr) []netip.Prefix {
	start, end = start.Unmap(), end.Unmap()
	if !start.IsValid() || !end.IsValid() || start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return nil
	}
	var out []netip.Prefix
	for {
		// The largest block that starts at start, is aligned and ends by end.
		bits := start.BitLen()
		for bits > 0 {
			p := netip.PrefixFrom(start, bits-1)
			if p.Masked().Addr() != start || last(p).Compare(end) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(start, bits)
		out = append(out, p)
		l := last(p)
		if l == end || !l.Next().IsValid() {
			return out
		}
		start = l.Next()
	}
}

// last is the highest address of the prefix.
func last(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// ParseCIDR parses a prefix and masks host bits.
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %v", s, err)
	}
	return p.Masked(), nil
}

// Exclusion is a hostname, wildcard or CIDR exclusion entry. Entry is the
// canonical entry; prefix is set for a CIDR only.
type Exclusion struct {
	Entry  string
	prefix netip.Prefix
}

// ParseExclusion parses "host.example.com", "*.dev.example.com", a CIDR or a bare IP.
func ParseExclusion(s string) (Exclusion, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return Exclusion{}, fmt.Errorf("invalid exclusion %q: empty", s)
	}
	if a, err := netip.ParseAddr(t); err == nil {
		p := netip.PrefixFrom(a, a.BitLen())
		return Exclusion{Entry: p.String(), prefix: p}, nil
	}
	if strings.Contains(t, "/") {
		p, err := netip.ParsePrefix(t)
		if err != nil {
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: %v", s, err)
		}
		p = p.Masked()
		return Exclusion{Entry: p.String(), prefix: p}, nil
	}
	name := strings.TrimSuffix(t, ".")
	wild := false
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name, wild = rest, true
	}
	if name == "" || strings.Contains(name, "*") {
		return Exclusion{}, fmt.Errorf("invalid exclusion %q: wildcards are only allowed as a leading \"*.\"", s)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || label == "" || strings.ContainsAny(label, " /:@") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: bad hostname", s)
		}
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		// Underscores are legal in real DNS names even though IDNA rejects them.
		ascii = name
	}
	if wild {
		return Exclusion{Entry: "*." + ascii}, nil
	}
	return Exclusion{Entry: ascii}, nil
}

// ParseExclusions parses each entry with ParseExclusion, stopping at the first
// that does not parse.
func ParseExclusions(entries []string) ([]Exclusion, error) {
	var out []Exclusion
	for _, e := range entries {
		x, err := ParseExclusion(e)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

// MatchesHost reports whether the hostname is excluded by name. CIDR entries never match a name.
func (e Exclusion) MatchesHost(h string) bool {
	if e.prefix.IsValid() {
		return false
	}
	h = NormaliseHost(h)
	if base, ok := strings.CutPrefix(e.Entry, "*."); ok {
		return strings.HasSuffix(h, "."+base)
	}
	return h == e.Entry
}

// Prefix returns the CIDR of a CIDR exclusion.
func (e Exclusion) Prefix() (netip.Prefix, bool) { return e.prefix, e.prefix.IsValid() }

// ReadList reads a file of one entry per line; blank lines and # comments
// (whole-line or trailing) are ignored.
func ReadList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, errors.Unwrap(err))
	}
	defer f.Close()
	return ParseList(f)
}

// ParseList is ReadList for an open reader.
func ParseList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// Parse validates every input. All problems are reported together, as
// clierr.Problems, each under the name of the argument it came from (domain,
// domains-file, org, asn, cidr, exclude or exclude-file) with the value as
// given.
func Parse(raw Raw) (Parsed, error) {
	var probs clierr.Problems
	var p Parsed
	first := ""
	setFirst := func(s string) {
		if first == "" {
			first = strings.TrimSpace(s)
		}
	}

	// item is one value and the argument it came from.
	type item struct{ name, value string }
	named := func(name string, vals []string) []item {
		out := make([]item, len(vals))
		for i, v := range vals {
			out[i] = item{name, v}
		}
		return out
	}
	domains := named("domain", raw.Domains)
	if len(raw.Domains) > 0 {
		setFirst(raw.Domains[0])
	}
	readFile := func(name, path string) []item {
		lines, err := ReadList(path)
		if err != nil {
			probs.Add(name, path, err.Error(), "")
			return nil
		}
		return named(name, lines)
	}
	if raw.DomainsFile != "" {
		lines := readFile("domains-file", raw.DomainsFile)
		domains = append(domains, lines...)
		if len(lines) > 0 {
			setFirst(lines[0].value)
		}
	}
	for _, o := range raw.Orgs {
		setFirst(o)
	}
	for _, a := range raw.ASNs {
		if canon, err := ParseASN(a); err == nil {
			setFirst(canon) // "123" and "as123" both name the engagement "as123"
		} else {
			setFirst(a)
		}
	}
	for _, c := range raw.CIDRs {
		setFirst(c)
	}

	set := func(items []item, parse func(string) (string, error)) []string {
		var out []string
		for _, it := range items {
			c, err := parse(it.value)
			if err != nil {
				probs.Add(it.name, it.value, err.Error(), "")
				continue
			}
			out = append(out, c)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	p.Roots = set(domains, ParseDomain)
	p.Orgs = set(named("org", raw.Orgs), ParseOrg)
	p.ASNs = set(named("asn", raw.ASNs), ParseASN)
	p.CIDRs = set(named("cidr", raw.CIDRs), func(s string) (string, error) {
		pr, err := ParseCIDR(s)
		return pr.String(), err
	})
	excl := named("exclude", raw.Exclude)
	if raw.ExcludeFile != "" {
		excl = append(excl, readFile("exclude-file", raw.ExcludeFile)...)
	}
	p.Exclusions = set(excl, func(s string) (string, error) {
		e, err := ParseExclusion(s)
		return e.Entry, err
	})
	p.First = first
	if err := probs.Err(); err != nil {
		return Parsed{}, err
	}
	return p, nil
}

var nameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// EngagementName makes a safe directory name from a name given with -e, or
// from the first input: lowercased, every character outside [a-z0-9._-]
// replaced, and no path separators or leading dots left.
func EngagementName(s string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r == '/':
			b.WriteByte('_')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := b.String()
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-._")
	if !nameOK.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("cannot make an engagement name from %q", s)
	}
	return name, nil
}
