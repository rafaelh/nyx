package layout

import "strings"

// Mode is how a block of text may be broken into lines.
type Mode int

// The modes. The zero value never breaks a line except at a newline.
const (
	// None breaks only at "\n". It is the mode of a table column that never wraps.
	None Mode = iota
	// Spaces breaks only at spaces: not after hyphens, slashes or other punctuation.
	Spaces
	// Commas breaks only after ", ". A segment too long for a line falls back to
	// Spaces within it.
	Commas
)

// Span is a piece of text and how to style it.
type Span struct {
	// Text is plain: already sanitised and redacted, with no escape sequence.
	Text string
	// Style is a palette function, applied to each line's part of the text after
	// the lines are broken. Nil means no style.
	Style func(string) string
	// Keep makes the span one unbreakable token, styled whole. Badges and padded
	// names are Keep spans. A word that holds a Keep span is never broken.
	Keep bool
}

// Plain is a single unstyled span.
func Plain(text string) []Span { return []Span{{Text: text}} }

// Wrap lays spans out as lines at most width cells wide, for text that follows a
// prefix first cells wide on its first line. The caller writes that prefix: the
// first line returned does not include it. Each later line starts with rest
// spaces, which Wrap writes. There is always at least one line.
//
// Spaces are kept: a leading run, a run inside a line and a run at the end. Only
// the single space at which a line is broken is consumed. "\n" is a hard break,
// and the line after it starts at rest like any other continuation.
//
// A word longer than the space left moves to the next line when a word is
// already on this one. When it is the first word of its line, or still too long
// on the next line:
//   - a protected word (Protected) or one holding a Keep span is left whole, and
//     the line runs past width;
//   - any other word is broken at width, counting cells.
//
// Lines are broken first and styled afterwards, run by run, so no escape sequence
// crosses a break: a styled run that goes on to the next line is closed at the end
// of one and opened again on the next.
func Wrap(spans []Span, width, first, rest int, mode Mode) []string {
	if mode == None {
		width = 1 << 30
	}
	e := &engine{width: width, rest: rest, curW: first}
	e.feed(tokenise(spans), mode)
	return e.render(spans)
}

// Hang lays spans out after prefix, which it writes at the start of the first line. Each later line
// starts with as many spaces as prefix is wide (its escape sequences count zero), so the text hangs
// under its first line. Otherwise it is Wrap.
func Hang(prefix string, spans []Span, width int, mode Mode) []string {
	w := Measure(prefix)
	lines := Wrap(spans, width, w, w, mode)
	lines[0] = prefix + lines[0]
	return lines
}

// frag is a piece of a line: text in the style of one span.
type frag struct {
	text string
	si   int // index into the spans, or -1 for no style
	w    int // width in cells
	keep bool
}

type word struct {
	frags []frag
	w     int
	whole bool // protected, or holds a Keep span: never broken
}

type tokKind int

const (
	tWord tokKind = iota
	tSpace
	tNL
)

type tok struct {
	kind tokKind
	word word
	sp   frag
}

// plain is the text of the word with no styling.
func (w word) plain() string {
	if len(w.frags) == 1 {
		return w.frags[0].text
	}
	var b strings.Builder
	for _, f := range w.frags {
		b.WriteString(f.text)
	}
	return b.String()
}

func tokenise(spans []Span) []tok {
	var out []tok
	var cur word
	flush := func() {
		if len(cur.frags) == 0 {
			return
		}
		for _, f := range cur.frags {
			cur.w += f.w
			cur.whole = cur.whole || f.keep
		}
		cur.whole = cur.whole || Protected(cur.plain())
		out = append(out, tok{kind: tWord, word: cur})
		cur = word{}
	}
	for i, sp := range spans {
		si := i
		if sp.Style == nil {
			si = -1
		}
		if sp.Keep {
			if sp.Text == "" {
				continue
			}
			text := sp.Text
			if sp.Style != nil {
				text = sp.Style(text)
			}
			cur.frags = append(cur.frags, frag{text: sp.Text, si: si, w: Measure(text), keep: true})
			continue
		}
		start := 0
		emit := func(end int) {
			if end > start {
				t := sp.Text[start:end]
				cur.frags = append(cur.frags, frag{text: t, si: si, w: Measure(t)})
			}
		}
		for j := range len(sp.Text) {
			c := sp.Text[j]
			if c != ' ' && c != '\n' {
				continue
			}
			emit(j)
			flush()
			if c == ' ' {
				out = append(out, tok{kind: tSpace, sp: frag{text: " ", si: si, w: 1}})
			} else {
				out = append(out, tok{kind: tNL})
			}
			start = j + 1
		}
		emit(len(sp.Text))
	}
	flush()
	return out
}

// unit is what can sit on a line or move to the next as a whole: a word, or in
// Commas mode a run of words ending after a comma.
type unit struct {
	toks []tok
	w    int
}

type engine struct {
	width, rest int
	lines       [][]frag
	cur         []frag
	curW        int
	content     bool // a word is already on the current line
	pending     []frag
}

// feed lays out tokens: spaces are held back until the next word shows where they go.
func (e *engine) feed(toks []tok, mode Mode) {
	var u unit
	closeUnit := func() {
		if len(u.toks) > 0 {
			e.place(u)
			u = unit{}
		}
	}
	for i, t := range toks {
		switch t.kind {
		case tNL:
			closeUnit()
			e.flushTrailing()
			e.newLine()
		case tSpace:
			if mode == Commas && len(u.toks) > 0 && !endsWithComma(u) && nextIsWord(toks, i) {
				u.toks = append(u.toks, t)
				u.w++
				continue
			}
			closeUnit()
			e.pending = append(e.pending, t.sp)
		case tWord:
			if mode != Commas {
				e.place(unit{toks: []tok{t}, w: t.word.w})
				continue
			}
			u.toks = append(u.toks, t)
			u.w += t.word.w
		}
	}
	closeUnit()
	e.flushTrailing()
}

func endsWithComma(u unit) bool {
	last := u.toks[len(u.toks)-1]
	return last.kind == tWord && strings.HasSuffix(last.word.plain(), ",")
}

// nextIsWord reports whether the run of spaces at toks[i] is followed by a word.
func nextIsWord(toks []tok, i int) bool {
	for ; i < len(toks); i++ {
		if toks[i].kind != tSpace {
			return toks[i].kind == tWord
		}
	}
	return false
}

func (e *engine) newLine() {
	e.lines = append(e.lines, e.cur)
	e.cur = nil
	if e.rest > 0 {
		e.cur = []frag{{text: strings.Repeat(" ", e.rest), si: -1, w: e.rest}}
	}
	e.curW = e.rest
	e.content = false
}

// flushPending writes the held spaces to the line.
func (e *engine) flushPending() {
	for _, f := range e.pending {
		e.cur = append(e.cur, f)
		e.curW += f.w
	}
	e.pending = nil
}

// flushTrailing writes the held spaces at the end of a line, as many as fit.
func (e *engine) flushTrailing() {
	room := max(0, e.width-e.curW)
	if len(e.pending) > room {
		e.pending = e.pending[:room]
	}
	e.flushPending()
}

func (e *engine) place(u unit) {
	for {
		if e.curW+len(e.pending)+u.w <= e.width {
			e.flushPending()
			e.add(u)
			return
		}
		if !e.content {
			break
		}
		// Break at the space before the unit; only one space is consumed.
		if len(e.pending) > 0 {
			e.pending = e.pending[1:]
		}
		e.newLine()
	}
	if len(u.toks) == 1 {
		w := u.toks[0].word
		e.flushPending()
		if w.whole {
			e.add(u)
			return
		}
		e.hardBreak(w)
		return
	}
	// A segment too long for a line: lay its words out at spaces.
	for _, t := range u.toks {
		if t.kind == tSpace {
			e.pending = append(e.pending, t.sp)
			continue
		}
		e.place(unit{toks: []tok{t}, w: t.word.w})
	}
}

func (e *engine) add(u unit) {
	for _, t := range u.toks {
		if t.kind == tSpace {
			e.cur = append(e.cur, t.sp)
			continue
		}
		e.cur = append(e.cur, t.word.frags...)
	}
	e.curW += u.w
	e.content = true
}

type cell struct {
	r  rune
	si int
	w  int
}

// hardBreak breaks a word that cannot be kept whole at the width, cell by cell.
// A zero-width rune stays with the rune before it, and each line takes at least
// one rune so the loop always ends.
func (e *engine) hardBreak(w word) {
	var rs []cell
	for _, f := range w.frags {
		for _, r := range f.text {
			rs = append(rs, cell{r, f.si, runeWidth(r)})
		}
	}
	for {
		total := 0
		for _, c := range rs {
			total += c.w
		}
		avail := e.width - e.curW
		if total <= avail {
			e.addCells(rs)
			e.content = true
			return
		}
		n, used := 0, 0
		for n < len(rs) && (used+rs[n].w <= avail || n == 0) {
			used += rs[n].w
			n++
		}
		for n < len(rs) && rs[n].w == 0 {
			n++
		}
		e.addCells(rs[:n])
		rs = rs[n:]
		if len(rs) == 0 {
			e.content = true
			return
		}
		e.newLine()
	}
}

func (e *engine) addCells(rs []cell) {
	for i := 0; i < len(rs); {
		j := i
		var b strings.Builder
		w := 0
		for j < len(rs) && rs[j].si == rs[i].si {
			b.WriteRune(rs[j].r)
			w += rs[j].w
			j++
		}
		e.cur = append(e.cur, frag{text: b.String(), si: rs[i].si, w: w})
		e.curW += w
		i = j
	}
}

// render styles each line, a run of same-span fragments at a time.
func (e *engine) render(spans []Span) []string {
	e.lines = append(e.lines, e.cur)
	out := make([]string, len(e.lines))
	var run strings.Builder
	for i, l := range e.lines {
		var b strings.Builder
		for j := 0; j < len(l); {
			k := j + 1
			if !l[j].keep {
				for k < len(l) && l[k].si == l[j].si && !l[k].keep {
					k++
				}
			}
			si := l[j].si
			if si < 0 {
				for _, f := range l[j:k] {
					b.WriteString(f.text)
				}
				j = k
				continue
			}
			run.Reset()
			for _, f := range l[j:k] {
				run.WriteString(f.text)
			}
			if run.Len() > 0 {
				b.WriteString(spans[si].Style(run.String()))
			}
			j = k
		}
		out[i] = b.String()
	}
	return out
}

// measureSpans is, from one pass over the spans, natural: the width of the widest
// line when nothing wraps (every space kept, as Wrap keeps them); and unbreakable:
// the width of the widest word that Wrap never breaks, a protected word or one
// holding a Keep span.
func measureSpans(spans []Span) (natural, unbreakable int) {
	line := 0
	for _, t := range tokenise(spans) {
		switch t.kind {
		case tNL:
			line = 0
		case tSpace:
			line += t.sp.w
		case tWord:
			line += t.word.w
			if t.word.whole {
				unbreakable = max(unbreakable, t.word.w)
			}
		}
		natural = max(natural, line)
	}
	return natural, unbreakable
}
