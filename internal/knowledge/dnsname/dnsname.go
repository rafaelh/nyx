// Package dnsname supplies pure helpers for reverse names, zones, registrable roots, SRV
// records and name generation.
package dnsname

import (
	"bytes"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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

// LearnableForms returns the forms of a label that name guessing learns: the label itself and,
// unless it begins "xn--", its hyphen-separated parts, leaving out empty, digits-only and
// invalid forms and repeats.
func LearnableForms(label string) []string {
	forms := []string{label}
	if !strings.HasPrefix(label, "xn--") {
		forms = append(forms, strings.Split(label, "-")...)
	}
	var out []string
	for _, f := range forms {
		if ValidLabel(f) && strings.Trim(f, "0123456789") != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
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

// HostnamesIn yields the hostnames written in text, once per occurrence and in the order they
// appear, so a caller removes repeats. It makes one pass over the bytes with a buffer of one
// name, copies nothing of the text and stops as soon as the caller does.
//
// Every character, once escapes are decoded, is a name character (A-Z, a-z, 0-9, dot and
// hyphen), a rejecting character or a separator. A maximal run of name and rejecting characters is
// lower-cased, has the dots and hyphens at its ends trimmed (so a name pressed against an HTML
// comment's dashes is read), and is yielded when it holds no
// rejecting character, is at most 253 bytes, has at least two labels and only valid labels. A
// longer run is skipped to its end without being buffered. A run is read whole, so a name
// followed by more labels (www.example.com.evil.net) is that longer name, and a name with an
// underscore label (_dmarc.example.com) gives nothing rather than the part after it. The
// rejecting characters are an underscore, a letter or mark of the Latin, Greek or Cyrillic script,
// a byte of 0x80 or more that is not valid UTF-8, an escape that gives one such byte, and a
// combining mark such as a diacritic right after a name character (the decomposed form of
// bücher.example.com gives nothing); every other character separates, so a name inside Chinese,
// Japanese or emoji text is read.
//
// Escapes are decoded in line, each to one character that is then classed as above: %XX; \uXXXX,
// \u{X...} (one to six hex digits) and \xXX; \ and three decimal digits, the byte of that value
// (the DNS presentation form; a value over 255 separates, and a backslash and fewer than three
// digits separates, taking the digits); \n, \r, \t, \b, \f and \v, which separate; \ and any
// other ASCII letter, which rejects, as does a \u or \x that lacks its digits (a regular expression
// such as \w\.example\.com must not give w.example.com); \ and any other character, which is that
// character (\/ is a slash, \. a dot); and &#DDD; and &#xHH;, whose semicolon is optional and
// whose digits are read greedily (more than seven separate). &amp; is an ampersand, and no other
// named entity is decoded. A decoded %, \ or & begins a new escape with the input that follows
// it, so %252F, \\u002f and &amp;#x2F; are read through. Each step consumes input, so the pass
// stays linear. An escape that would run on past the end of the text counts as reaching it.
//
// With cut, a run that reaches the end of the text is not yielded, as the text was cut there and
// the name may have been longer.
func HostnamesIn[T ~string | ~[]byte](text T, cut bool) iter.Seq[string] {
	return func(yield func(string) bool) {
		var r nameReader
		r.yield = yield
		for i := 0; i < len(text); {
			b := text[i]
			e := escape{class: byteClass[b], ch: b, next: i + 1}
			switch e.class {
			case clHigh:
				ru, size := runeAt(text, i)
				e = escape{class: highClass(ru, ru == utf8.RuneError && size == 1), next: i + size}
			case clPercent, clBackslash, clAmp:
				e = decodeEscape(text, i+1, b)
			}
			i = e.next
			switch e.class {
			case clName:
				r.name(e.ch | 0x20) // the bit lowers a letter and leaves a digit or hyphen
			case clDot:
				r.dot()
			case clReject:
				r.reject()
			case clMark: // a diacritic is part of the character before it
				if r.touching() {
					r.reject()
				} else if !r.flush(cut && e.truncated) {
					return
				}
			default:
				if !r.flush(cut && e.truncated) {
					return
				}
			}
		}
		r.flush(cut)
	}
}

// MaxNameLen is the longest DNS name in its text form, without the final dot.
const MaxNameLen = 253

// The classes of a character once decoded. The introducers are the three characters that begin
// an escape; clHigh is a byte of 0x80 or more, which begins a UTF-8 sequence.
const (
	clSep byte = iota
	clName
	clDot
	clReject
	clHigh
	clPercent
	clBackslash
	clAmp
	clMark // a combining mark of no script of its own, such as a diacritic
)

// byteClass is the class of each byte read as itself.
var byteClass = func() (t [256]byte) {
	for b := range 256 {
		switch {
		case b >= 0x80:
			t[b] = clHigh
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-':
			t[b] = clName
		}
	}
	t['.'], t['_'] = clDot, clReject
	t['%'], t['\\'], t['&'] = clPercent, clBackslash, clAmp
	return t
}()

// nameReader is the run being read: its name so far and whether it can still be a name. Dots and
// hyphens after the last letter or digit wait in a tail and are written only when another letter
// or digit follows, so those at either end of a run are trimmed.
type nameReader struct {
	yield func(string) bool
	buf   [MaxNameLen]byte
	n     int  // bytes in buf, which ends in a letter or digit
	dots  int  // dots in the tail
	hyph  int  // hyphens in the tail
	mixed bool // the tail has a dot and a hyphen, which no name has side by side
	label int  // length of the current label
	dead  bool // the run can no longer be a name
}

// name adds a lower-case letter, digit or hyphen.
func (r *nameReader) name(c byte) {
	if r.dead || r.n == 0 && c == '-' { // a leading hyphen is dropped
		return
	}
	if c == '-' {
		r.mixed = r.mixed || r.dots > 0
		r.hyph++
		return
	}
	if r.n > 0 && !r.writeTail() {
		r.dead = true
		return
	}
	if r.n >= MaxNameLen || r.label >= 63 {
		r.dead = true
		return
	}
	r.buf[r.n] = c
	r.n++
	r.label++
}

// writeTail writes the tail before a letter or digit, reporting whether the name can go on: one
// dot ends a label, and hyphens stay inside it.
func (r *nameReader) writeTail() bool {
	dots, hyph := r.dots, r.hyph
	r.dots, r.hyph = 0, 0
	switch {
	case r.mixed || dots > 1: // a label that ends or begins with a hyphen, or an empty one
		return false
	case dots == 1:
		if r.n >= MaxNameLen {
			return false
		}
		r.buf[r.n] = '.'
		r.n++
		r.label = 0
	case hyph > 0:
		if r.n+hyph > MaxNameLen || r.label+hyph > 63 {
			return false
		}
		for range hyph {
			r.buf[r.n] = '-'
			r.n++
		}
		r.label += hyph
	}
	return true
}

// dot adds a dot, which closes the label before it. A leading dot is dropped.
func (r *nameReader) dot() {
	if r.dead || r.n == 0 {
		return
	}
	r.mixed = r.mixed || r.hyph > 0
	r.dots++
}

// reject adds a character that makes the run give nothing.
func (r *nameReader) reject() { r.dead = true }

// touching reports whether the character just read belongs to the run: a name character, or
// anything once the run is dead. A dot or hyphen in the tail does not count, as the run may end
// there.
func (r *nameReader) touching() bool { return r.dead || r.n > 0 && r.dots == 0 && r.hyph == 0 }

// flush ends the run, yielding its name when it is one and drop is false, and reports whether
// the caller wants more. The tail is trimmed; a name has two labels, so a dot in buf.
func (r *nameReader) flush(drop bool) bool {
	ok := !r.dead && !drop && r.n > 0 && bytes.IndexByte(r.buf[:r.n], '.') >= 0
	var name string
	if ok {
		name = string(r.buf[:r.n])
	}
	r.n, r.dots, r.hyph, r.mixed, r.label, r.dead = 0, 0, 0, false, 0, false
	return !ok || r.yield(name)
}

// highClass is the class of a non-ASCII character: a byte that is not valid UTF-8 (invalid), or a
// letter or mark of the Latin, Greek or Cyrillic script, rejects the run. A combining mark that
// takes the script of the letter before it (U+0308 in the decomposed form of ü) is clMark, which
// rejects a run it touches; any other character separates.
func highClass(r rune, invalid bool) byte {
	switch {
	case invalid || (unicode.IsLetter(r) || unicode.IsMark(r)) && unicode.In(r, unicode.Latin, unicode.Greek, unicode.Cyrillic):
		return clReject
	case unicode.IsMark(r) && unicode.Is(unicode.Inherited, r):
		return clMark
	}
	return clSep
}

// runeAt decodes the character at text[i], which is a byte of 0x80 or more.
func runeAt[T ~string | ~[]byte](text T, i int) (rune, int) {
	var b [utf8.UTFMax]byte
	k := 0
	for ; k < len(b) && i+k < len(text); k++ {
		b[k] = text[i+k]
	}
	return utf8.DecodeRune(b[:k])
}

// escape is the result of decoding one escape.
type escape struct {
	class     byte // clSep, clName, clDot or clReject
	ch        byte // the character, when class is clName
	next      int  // where the input goes on
	truncated bool // the escape would have gone on past the end of the text
}

// hexAt returns the value of the hex digit at text[i], -1 when it is not one and -2 when the
// text has ended.
func hexAt[T ~string | ~[]byte](text T, i int) int {
	if i >= len(text) {
		return -2
	}
	switch c := text[i]; {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// decoded is one step of decoding an escape: a character, or the end of the escape. A character
// is c when it is ASCII or a byte of 0x80 or more, and r when it is a character of 0x80 or more.
type decoded struct {
	c         byte
	r         rune
	next      int
	truncated bool
	done      bool   // the escape is over, and result is it
	result    escape // when done
}

// finish ends the escape with a result.
func finish(class byte, next int, truncated bool) decoded {
	return decoded{done: true, result: escape{class: class, next: next, truncated: truncated}}
}

// decodeEscape decodes the escape whose introducer is intro and whose body begins at text[i].
// A character that decodes to another introducer begins a new escape at the input that follows.
// When the body is not an escape the introducer is a separator and the input goes on at i.
func decodeEscape[T ~string | ~[]byte](text T, i int, intro byte) escape {
	for {
		var d decoded
		switch intro {
		case '%':
			d = decodePercent(text, i)
		case '\\':
			d = decodeBackslash(text, i)
		default: // '&'
			d = decodeAmpersand(text, i)
		}
		if d.done {
			return d.result
		}
		i = d.next
		if d.r != 0 {
			class := highClass(d.r, false)
			return escape{class: class, next: i, truncated: class != clReject && d.truncated}
		}
		if d.c >= utf8.RuneSelf {
			return escape{class: clReject, next: i}
		}
		switch class := byteClass[d.c]; class {
		case clPercent, clBackslash, clAmp:
			intro = d.c
		default:
			return escape{class: class, ch: d.c, next: i, truncated: d.truncated}
		}
	}
}

// decodePercent decodes the two hex digits after a percent sign at text[i-1].
func decodePercent[T ~string | ~[]byte](text T, i int) decoded {
	hi, lo := hexAt(text, i), hexAt(text, i+1)
	switch {
	case hi == -2 || hi >= 0 && lo == -2:
		return finish(clSep, len(text), true)
	case hi < 0 || lo < 0:
		return finish(clSep, i, false)
	}
	return decoded{c: byte(hi<<4 | lo), next: i + 2}
}

// decodeBackslash decodes what follows a backslash at text[i-1].
func decodeBackslash[T ~string | ~[]byte](text T, i int) decoded {
	n := len(text)
	if i >= n {
		return finish(clSep, n, true)
	}
	switch b := text[i]; {
	case b == 'u' || b == 'x':
		v, next, state := hexEscape(text, i, b == 'u')
		switch state {
		case -2:
			return finish(clSep, n, true)
		case -1:
			return finish(clReject, next, false)
		}
		if b == 'x' || v < utf8.RuneSelf {
			return decoded{c: byte(v), next: next}
		}
		return decoded{r: rune(v), next: next}
	case b >= '0' && b <= '9':
		v, k := 0, 0
		for ; k < 3 && i+k < n && text[i+k] >= '0' && text[i+k] <= '9'; k++ {
			v = v*10 + int(text[i+k]-'0')
		}
		i += k
		if k == 3 && v <= 255 {
			return decoded{c: byte(v), next: i}
		}
		if k < 3 { // fewer than three digits: they go with the backslash
			for i < n && text[i] >= '0' && text[i] <= '9' {
				i++
			}
			return finish(clSep, i, i >= n)
		}
		return finish(clSep, i, false)
	case b == 'n' || b == 'r' || b == 't' || b == 'b' || b == 'f' || b == 'v':
		return finish(clSep, i+1, false)
	case b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z':
		return finish(clReject, i+1, false)
	case b >= utf8.RuneSelf:
		ru, size := runeAt(text, i)
		return finish(highClass(ru, ru == utf8.RuneError && size == 1), i+size, false)
	}
	return decoded{c: text[i], next: i + 1}
}

// decodeAmpersand decodes what follows an ampersand at text[i-1]: &amp; or a numeric reference.
func decodeAmpersand[T ~string | ~[]byte](text T, i int) decoded {
	n := len(text)
	if i >= n {
		return finish(clSep, n, true)
	}
	switch text[i] {
	case '#':
		v, next, res, truncated := numericReference(text, i+1)
		switch res {
		case refNone:
			if truncated {
				return finish(clSep, n, true)
			}
			return finish(clSep, i, false)
		case refSkip:
			return finish(clSep, next, truncated)
		}
		if v < utf8.RuneSelf {
			return decoded{c: byte(v), next: next, truncated: truncated}
		}
		return decoded{r: rune(v), next: next, truncated: truncated}
	case 'a':
		for k, want := range []byte("amp;") {
			if i+k >= n {
				return finish(clSep, n, true)
			}
			if text[i+k] != want {
				return finish(clSep, i, false)
			}
		}
		return decoded{c: '&', next: i + 4}
	}
	return finish(clSep, i, false)
}

// hexEscape reads the digits of a \u or \x escape whose letter is at text[i]. It gives the value,
// where the input goes on, and 0 when the escape is whole, -1 when it is not an escape and -2
// when the text ends inside it.
func hexEscape[T ~string | ~[]byte](text T, i int, long bool) (v, next, state int) {
	i++
	digits, braced := 2, false
	if long {
		digits = 4
		if i < len(text) && text[i] == '{' {
			braced = true
			i++
		}
	}
	k := 0
	for ; braced || k < digits; k++ {
		d := hexAt(text, i)
		if d == -2 {
			return 0, len(text), -2
		}
		if d < 0 {
			break
		}
		if braced && k == 6 {
			return 0, i, -1
		}
		v = min(v<<4|d, 1<<24)
		i++
	}
	if braced {
		if i >= len(text) {
			return 0, len(text), -2
		}
		if k == 0 || text[i] != '}' {
			return 0, i, -1
		}
		i++
	} else if k < digits {
		return 0, i, -1
	}
	return v, i, 0
}

// The results of numericReference.
const (
	refOK   = iota // a character reference
	refNone        // not a character reference
	refSkip        // a reference to nothing a name holds: too many digits, or out of range
)

// numericReference reads the digits of a &#DDD; or &#xHH; reference from text[i], after the
// "&#". It gives the value, where the input goes on, how it went, and whether the digits ran to the
// end of the text, so more might have followed.
func numericReference[T ~string | ~[]byte](text T, i int) (v, next, res int, truncated bool) {
	start, n, base := i, len(text), 10
	if i < n && (text[i] == 'x' || text[i] == 'X') {
		base = 16
		i++
	}
	digits := 0
	for ; i < n; i++ {
		d := hexAt(text, i)
		if d < 0 || base == 10 && d > 9 {
			break
		}
		digits++
		v = min(v*base+d, 1<<24)
	}
	switch {
	case digits == 0:
		return 0, start, refNone, i >= n
	case i < n && text[i] == ';':
		i++
	case i >= n:
		truncated = true
	}
	if digits > 7 || v == 0 || v > unicode.MaxRune {
		return 0, i, refSkip, truncated
	}
	return v, i, refOK, truncated
}
