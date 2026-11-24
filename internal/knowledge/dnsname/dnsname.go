// Package dnsname supplies pure helpers for reverse names, zones, registrable roots, SRV
// records and name generation.
package dnsname

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ReverseName builds IPv4/IPv6 PTR owner names.
func ReverseName(a netip.Addr) string { return reverse(a) + suffix(a, "in-addr.arpa", "ip6.arpa") }

// CymruOrigin builds an address's origin-AS TXT query name.
func CymruOrigin(a netip.Addr) string {
	return reverse(a) + suffix(a, "origin.asn.cymru.com", "origin6.asn.cymru.com")
}

func suffix(a netip.Addr, v4, v6 string) string {
	if a.Unmap().Is4() {
		return "." + v4
	}
	return "." + v6
}

func reverse(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var parts []string
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(parts, ".")
}

// Normalise trims whitespace, lowercases and removes the final DNS dot.
func Normalise(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// SRV parses "priority weight port target" and rejects malformed records or the null target
// ".", which means no service.
func SRV(value string) (port uint16, target string, ok bool) {
	f := strings.Fields(value)
	if len(f) != 4 || f[3] == "." {
		return 0, "", false
	}
	p, err := strconv.ParseUint(f[2], 10, 16)
	if err != nil {
		return 0, "", false
	}
	return uint16(p), f[3], true
}

// Under compares normalised names on label boundaries, including equality.
func Under(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

// ETLDPlusOne is the registrable domain of name.
func ETLDPlusOne(name string) (string, bool) {
	d, err := publicsuffix.EffectiveTLDPlusOne(Normalise(name))
	return d, err == nil
}

// Registrable falls back to the normalised name for public suffixes and single labels.
func Registrable(name string) string {
	if d, ok := ETLDPlusOne(name); ok {
		return d
	}
	return Normalise(name)
}

// Parents returns ancestors nearest first through the registrable domain. Registrable domains
// and public suffixes have no returned parents.
func Parents(name string) []string {
	name = Normalise(name)
	reg, ok := ETLDPlusOne(name)
	if !ok {
		return nil
	}
	var out []string
	for name != reg {
		_, rest, found := strings.Cut(name, ".")
		if !found {
			break
		}
		name = rest
		out = append(out, name)
	}
	return out
}

// ValidLabel validates one hostname component.
func ValidLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Permute deterministically generates unique label variants up to max, trying digit changes
// before word joins. Dotted joins form two separately validated labels. The original label is
// excluded.
func Permute(label string, words []string, max int) []string {
	var out []string
	seen := map[string]bool{label: true}
	add := func(s string) bool {
		if seen[s] {
			return true
		}
		for part := range strings.SplitSeq(s, ".") {
			if !ValidLabel(part) {
				return true
			}
		}
		seen[s] = true
		out = append(out, s)
		return len(out) < max
	}
	if max <= 0 {
		return nil
	}
	for _, d := range digitVariants(label) {
		if !add(d) {
			return out
		}
	}
	for _, w := range words {
		for _, v := range []string{label + "-" + w, w + "-" + label, label + "." + w, w + "." + label, label + w, w + label} {
			if !add(v) {
				return out
			}
		}
	}
	return out
}

func digitVariants(label string) []string {
	i := len(label)
	for i > 0 && label[i-1] >= '0' && label[i-1] <= '9' {
		i--
	}
	base, digits := label[:i], label[i:]
	if digits == "" {
		return []string{label + "1", label + "2"}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return nil
	}
	pad := func(v int) string { return fmt.Sprintf("%s%0*d", base, len(digits), v) }
	out := []string{pad(n + 1), pad(n + 2)}
	if n > 0 {
		out = append(out, pad(n-1))
	}
	return out
}
