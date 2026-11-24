// Package input validates and normalises command-line domains, organisations, ASNs, CIDRs and
// exclusions.
package input

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
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

// Parsed holds normalised, deduplicated and sorted inputs. First preserves the original first
// input for naming.
type Parsed struct {
	Roots      []string
	Orgs       []string
	ASNs       []string // "AS123"
	CIDRs      []string // masked
	Exclusions []string // canonical entries
	First      string   // first input, used to name the engagement
}

func (p Parsed) Empty() bool {
	return len(p.Roots)+len(p.Orgs)+len(p.ASNs)+len(p.CIDRs) == 0
}

// IPLiteral parses and unmaps a host address. It rejects zone identifiers and URL-style
// brackets, which egress does not accept as dialable hosts.
func IPLiteral(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// CleanName normalises a source-reported hostname to lowercase punycode, removing a trailing
// dot and leading "*.". Invalid hostnames, addresses, URLs and public suffixes return "".
func CleanName(n string) string {
	n = strings.TrimPrefix(strings.TrimSpace(n), "*.")
	d, _ := ParseDomain(n)
	return d
}

// ParseDomain normalises a domain to lowercase punycode and validates it, rejecting public
// suffixes and IP literals.
func ParseDomain(s string) (string, error) {
	return parseName(s, nameOptions{noun: "domain", rejectSuffix: true})
}

// ParseHostname normalises a DNS name. Public suffixes such as "co.uk" are allowed;
// single-label names require singleLabel. IP literals and names containing only digits and dots
// are rejected.
func ParseHostname(s string, singleLabel bool) (string, error) {
	return parseName(s, nameOptions{noun: "hostname", needTwoLabels: !singleLabel, rejectDigits: true})
}

// nameOptions controls the validation differences between domains and lookup hostnames.
type nameOptions struct {
	noun          string // what the name is called in an error
	rejectSuffix  bool   // a public suffix is not a name
	needTwoLabels bool   // a single label is not a name
	rejectDigits  bool   // a name of only digits and dots is not a name
}

// parseName shares normalisation and validation between domain and hostname parsing.
func parseName(s string, o nameOptions) (string, error) {
	d := dnsname.Normalise(s)
	if d == "" {
		return "", fmt.Errorf("invalid %s %q: empty", o.noun, s)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("invalid %s %q: IP addresses are not %ss", o.noun, s, o.noun)
	}
	if strings.ContainsAny(d, "/:@ _*") {
		return "", fmt.Errorf("invalid %s %q: contains characters not allowed in a hostname", o.noun, s)
	}
	if o.rejectDigits && strings.Trim(d, "0123456789.") == "" {
		return "", fmt.Errorf("invalid %s %q: a name of only digits and dots is not a hostname", o.noun, s)
	}
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", o.noun, s, err)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("invalid %s %q: too long", o.noun, s)
	}
	for label := range strings.SplitSeq(ascii, ".") {
		if !dnsname.ValidLabel(label) {
			return "", fmt.Errorf("invalid %s %q: bad label %q", o.noun, s, label)
		}
	}
	if o.needTwoLabels && !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("invalid %s %q: a hostname needs two or more labels", o.noun, s)
	}
	if o.rejectSuffix {
		if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
			return "", fmt.Errorf("invalid %s %q: it is a public suffix, not a registrable domain", o.noun, s)
		}
	}
	return ascii, nil
}

// BareHost extracts a lowercase, unbracketed host from a URL or host:port value, optionally
// with a path. Bare names and addresses return ok=false.
func BareHost(s string) (host string, ok bool) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, " \t\r\n") {
		return "", false
	}
	if scheme, rest, found := strings.Cut(s, "://"); found {
		if !validScheme(scheme) {
			return "", false
		}
		u, err := url.Parse(scheme + "://" + rest)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		return strings.ToLower(u.Hostname()), true
	}
	// Accept host:port values with an optional path as well as full URLs.
	authority, _, _ := strings.Cut(s, "/")
	if rest, found := strings.CutPrefix(authority, "["); found {
		h, port, found := strings.Cut(rest, "]")
		if !found || h == "" || !strings.HasPrefix(port, ":") || !validPort(port[1:]) {
			return "", false
		}
		if a, err := netip.ParseAddr(h); err != nil || !a.Is6() {
			return "", false
		}
		return strings.ToLower(h), true
	}
	if strings.Count(authority, ":") != 1 {
		return "", false // a bare name or IPv6 address has no port to strip
	}
	h, port, _ := strings.Cut(authority, ":")
	if h == "" || !validPort(port) {
		return "", false
	}
	return strings.ToLower(h), true
}

// validScheme reports whether s is a URL scheme: a letter, then letters, digits, "+", "-" or ".".
func validScheme(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return s != ""
}

// validPort reports whether s is a port number, 1 to 65535.
func validPort(s string) bool {
	n, err := strconv.ParseUint(s, 10, 16)
	return err == nil && n >= 1 && !strings.HasPrefix(s, "+")
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

// RangeCIDRs covers an inclusive address range with the fewest prefixes, in address order.
// Invalid, mixed-family or reversed endpoints return nil.
func RangeCIDRs(start, end netip.Addr) []netip.Prefix {
	start, end = start.Unmap(), end.Unmap()
	if !start.IsValid() || !end.IsValid() || start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return nil
	}
	var out []netip.Prefix
	for {
		// Choose the largest aligned block starting here that fits within the range.
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
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	return p.Masked(), nil
}

// Exclusion represents an excluded hostname, wildcard or network. Entry is normalised; prefix
// is set only for network exclusions.
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
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: %w", s, err)
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
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 || label == "" || strings.ContainsAny(label, " /:@") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: bad hostname", s)
		}
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		// Accept underscores used in DNS names even though IDNA rejects them.
		ascii = name
	}
	if wild {
		return Exclusion{Entry: "*." + ascii}, nil
	}
	return Exclusion{Entry: ascii}, nil
}

// ParseExclusions validates entries in order and stops at the first error.
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

// MatchesHost checks name exclusions only; network exclusions need an address.
func (e Exclusion) MatchesHost(h string) bool {
	if e.prefix.IsValid() {
		return false
	}
	h = dnsname.Normalise(h)
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
		return nil, fmt.Errorf("cannot read %s: %w", path, errors.Unwrap(err))
	}
	defer f.Close()
	return ParseList(f)
}

// ParseList reads the same format as ReadList from an existing reader.
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

// Parse validates all inputs and returns their problems together as clierr.Problems. Each
// problem includes the original argument name and value.
func Parse(raw Raw) (Parsed, error) {
	var probs clierr.Problems
	var p Parsed
	first := ""
	setFirst := func(s string) {
		if first == "" {
			first = strings.TrimSpace(s)
		}
	}

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
			setFirst(canon) // Use the same engagement name for equivalent ASN inputs such as "123" and "as123".
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

// EngagementName derives a safe directory name from -e or the first input. It lowercases,
// replaces characters outside [a-z0-9._-], and removes path separators and leading dots.
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

// RangeText formats an inclusive range as one CIDR when possible, otherwise "start-end".
// Invalid, mixed-family or reversed endpoints return "".
func RangeText(start, end netip.Addr) string {
	start, end = start.Unmap(), end.Unmap()
	cidrs := RangeCIDRs(start, end)
	switch len(cidrs) {
	case 0:
		return ""
	case 1:
		return cidrs[0].String()
	}
	return start.String() + "-" + end.String()
}
