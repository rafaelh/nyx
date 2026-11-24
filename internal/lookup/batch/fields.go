package batch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Keys are the field names of a lookup record in record order: the order of its JSON keys and
// the names --fields accepts.
type Keys struct {
	names []string
	pos   map[string]int
}

// NewKeys indexes names, which are in record order.
func NewKeys(names []string) Keys {
	pos := make(map[string]int, len(names))
	for i, n := range names {
		pos[n] = i
	}
	return Keys{names: names, pos: pos}
}

// Index is the position of the name in the record, or -1.
func (k Keys) Index(name string) int {
	if i, ok := k.pos[name]; ok {
		return i
	}
	return -1
}

// Selection marks the selected fields of a record, by their position in its Keys.
type Selection []bool

// Has reports whether the field at position i is selected. It is false for -1.
func (s Selection) Has(i int) bool { return i >= 0 && i < len(s) && s[i] }

// Select reads a --fields value: comma-separated names, trimmed, with blanks ignored. It calls
// all for "all" and pick with the position of each known name, in the order given, and returns
// the unknown names, unchanged and in order, or nil.
func (k Keys) Select(spec string, all func(), pick func(i int)) []string {
	var unknown []string
	for name := range strings.SplitSeq(spec, ",") {
		name = strings.TrimSpace(name)
		i := k.Index(name)
		switch {
		case name == "":
		case name == "all":
			all()
		case i < 0:
			unknown = append(unknown, name)
		default:
			pick(i)
		}
	}
	return unknown
}

// Marshal encodes the selected fields as one JSON object, its keys in record order, each value
// as encoding/json encodes it with HTML left unescaped.
func (k Keys) Marshal(s Selection, value func(i int) any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, name := range k.names {
		if !s.Has(i) {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:", name)
		if err := enc.Encode(value(i)); err != nil {
			return nil, fmt.Errorf("encoding %s: %w", name, err)
		}
		b.Truncate(b.Len() - 1) // Encode's newline
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
