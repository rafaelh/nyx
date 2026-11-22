// Package configedit edits one nyx config file the way a person would: it changes only the values
// it is told to, and keeps every other setting, comment and their order. It reads the file as a
// YAML document of nodes, so a setting is found by its dotted key whatever case the file spells it
// in, and it writes the document back with Save, which replaces the file atomically.
//
// Store is the setup command's Backend over that document.
package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Doc is a config file as a YAML document. Settings are named by dotted key ("keys.shodan",
// "rate.per_host"), and each name is matched case-insensitively at every level, as the loader does.
// A Doc is not safe for concurrent use.
type Doc struct {
	doc  *yaml.Node // the document node
	root *yaml.Node // its mapping
}

// Entry is what Lookup found for a key.
type Entry struct {
	// Node is the value of the first entry in file order, or nil when the file has none.
	Node *yaml.Node
	// Variants, when the file spells the key (or a block above it) more than once with different
	// case, holds those spellings as dotted paths in file order ("keys.Shodan", "keys.shodan" or,
	// for blocks, "Keys" and "keys"). The loader keeps only one of them, so the setting is
	// ambiguous. It is nil otherwise.
	Variants []string
}

// Parse reads a config file's bytes. Empty data is an empty document; a file that holds only
// comments keeps them. It is an error when the data is not one YAML document whose top level is a
// mapping.
func Parse(data []byte) (*Doc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var n yaml.Node
	switch err := dec.Decode(&n); {
	case errors.Is(err, io.EOF):
		n = yaml.Node{}
	case err != nil:
		return nil, err
	}
	if n.Kind != 0 {
		var extra yaml.Node
		switch err := dec.Decode(&extra); {
		case err == nil:
			return nil, errors.New("the file holds more than one YAML document")
		case !errors.Is(err, io.EOF):
			return nil, err
		}
	}
	d := &Doc{doc: &n}
	if n.Kind == 0 {
		d.doc = &yaml.Node{Kind: yaml.DocumentNode, HeadComment: commentsOnly(data)}
	}
	if len(d.doc.Content) == 0 {
		d.doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	d.root = d.doc.Content[0]
	if d.root.Kind == yaml.ScalarNode && d.root.Tag == "!!null" {
		// A file of only "null", "~" or "---".
		*d.root = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: d.root.HeadComment}
	}
	if d.root.Kind != yaml.MappingNode {
		return nil, errors.New("the top level of the file is not a mapping")
	}
	return d, nil
}

// commentsOnly is the comment lines of a file that holds no YAML node, as one head comment.
func commentsOnly(data []byte) string {
	var lines []string
	for l := range strings.SplitSeq(string(data), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// keyName is the lower-case name of a mapping key, as the loader reads it.
func keyName(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	return strings.ToLower(n.Value), true
}

// find is the indexes of the keys of mapping m that name want (lower case), in file order.
func find(m *yaml.Node, want string) []int {
	var out []int
	for i := 0; i+1 < len(m.Content); i += 2 {
		if name, ok := keyName(m.Content[i]); ok && name == want {
			out = append(out, i)
		}
	}
	return out
}

// Lookup finds key. It looks in every block that spells the key's parents, so a setting under a
// second spelling of its block is found too.
func (d *Doc) Lookup(key string) Entry {
	parts := strings.Split(strings.ToLower(key), ".")
	type level struct {
		m      *yaml.Node
		prefix string
	}
	cur := []level{{d.root, ""}}
	var e Entry
	for l, name := range parts {
		var next []level
		var spelled []string
		for _, lv := range cur {
			for _, i := range find(lv.m, name) {
				path := lv.m.Content[i].Value
				if lv.prefix != "" {
					path = lv.prefix + "." + path
				}
				if !slices.Contains(spelled, path) {
					spelled = append(spelled, path)
				}
				v := lv.m.Content[i+1]
				switch {
				case l == len(parts)-1:
					if e.Node == nil {
						e.Node = v
					}
				case v.Kind == yaml.MappingNode:
					next = append(next, level{v, path})
				}
			}
		}
		if len(spelled) > 1 && e.Variants == nil {
			e.Variants = spelled
		}
		cur = next
	}
	return e
}

// span is a mapping's key and where it sits in its parent, from the root down to a setting's block.
type span struct {
	parent *yaml.Node
	idx    int
}

// block finds the mapping that holds the last part of key and returns it with the path of keys
// that lead there. Blocks spelled in more than one case are merged into the first, so the setting
// is left with one home. A block that is only a key with no value becomes a mapping. With create
// false a missing block is not an error: block returns nil.
func (d *Doc) block(parts []string, create bool) (*yaml.Node, []span, error) {
	cur := d.root
	var path []span
	for _, name := range parts[:len(parts)-1] {
		idxs := find(cur, name)
		if len(idxs) == 0 {
			if !create {
				return nil, nil, nil
			}
			cur.Content = append(cur.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
				&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
			idxs = []int{len(cur.Content) - 2}
		}
		first := idxs[0]
		blk := cur.Content[first+1]
		if err := openBlock(blk, name); err != nil {
			return nil, nil, err
		}
		for _, j := range slices.Backward(idxs[1:]) {
			other := cur.Content[j+1]
			if err := openBlock(other, name); err != nil {
				return nil, nil, err
			}
			blk.Content = append(blk.Content, other.Content...)
			cur.Content = slices.Delete(cur.Content, j, j+2)
		}
		path = append(path, span{cur, first})
		cur = blk
	}
	return cur, path, nil
}

// openBlock makes a valueless block a mapping, and refuses one that holds something else.
func openBlock(n *yaml.Node, name string) error {
	switch {
	case n.Kind == yaml.MappingNode:
		if len(n.Content) == 0 {
			n.Style = 0
		}
	case n.Kind == yaml.ScalarNode && n.Tag == "!!null":
		line := n.LineComment
		*n = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", LineComment: line}
	default:
		return fmt.Errorf("%s is not a block of settings", name)
	}
	return nil
}

// SetString sets key to value, which is always written as a string, so it reads back exactly as
// given (a "0123", "yes" or "0x10" is quoted). The entry is replaced in place and keeps its
// comments and spelling; case variants of it collapse to the first one. It is an error for the
// value not to be valid UTF-8, which cannot be stored.
func (d *Doc) SetString(key, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s: the value is not valid UTF-8", key)
	}
	return d.set(key, func(old *yaml.Node) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	})
}

// SetList sets key to a block sequence of strings. An item that an existing sequence already holds
// (compared trimmed and lower-cased) keeps its node and so its comments. An empty list clears the
// key.
func (d *Doc) SetList(key string, items []string) error {
	for _, it := range items {
		if !utf8.ValidString(it) {
			return fmt.Errorf("%s: an item is not valid UTF-8", key)
		}
	}
	if len(items) == 0 {
		d.Clear(key)
		return nil
	}
	return d.set(key, func(old *yaml.Node) *yaml.Node {
		var spare []*yaml.Node
		if old != nil && old.Kind == yaml.SequenceNode {
			spare = slices.Clone(old.Content)
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, it := range items {
			n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: it}
			if i := slices.IndexFunc(spare, func(s *yaml.Node) bool { return s.Kind == yaml.ScalarNode && normalise(s.Value) == it }); i >= 0 {
				n = spare[i]
				spare = slices.Delete(spare, i, i+1)
			}
			seq.Content = append(seq.Content, n)
		}
		return seq
	})
}

func normalise(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// set puts the node build returns (given the value it replaces, or nil) at key.
func (d *Doc) set(key string, build func(old *yaml.Node) *yaml.Node) error {
	parts := strings.Split(strings.ToLower(key), ".")
	cur, _, err := d.block(parts, true)
	if err != nil {
		return err
	}
	idxs := find(cur, parts[len(parts)-1])
	if len(idxs) == 0 {
		cur.Content = append(cur.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: parts[len(parts)-1]}, build(nil))
		return nil
	}
	first := idxs[0]
	old := cur.Content[first+1]
	n := build(old)
	n.HeadComment, n.LineComment, n.FootComment = old.HeadComment, old.LineComment, old.FootComment
	if n.Kind == yaml.SequenceNode && n.LineComment != "" {
		// Beside "skip:", where it was, not after the first item.
		cur.Content[first].LineComment, n.LineComment = n.LineComment, ""
	}
	cur.Content[first+1] = n
	for _, j := range slices.Backward(idxs[1:]) {
		cur.Content = slices.Delete(cur.Content, j, j+2)
	}
	return nil
}

// Clear removes key with its own comments, every case variant of it, and any block it leaves
// empty. The head comment of the document's first entry, which is usually the file's header, moves
// to the document. A key the file does not hold is left alone.
func (d *Doc) Clear(key string) {
	parts := strings.Split(strings.ToLower(key), ".")
	cur, path, err := d.block(parts, false)
	if err != nil || cur == nil {
		return
	}
	for _, j := range slices.Backward(find(cur, parts[len(parts)-1])) {
		d.removePair(cur, j)
	}
	for _, sp := range slices.Backward(path) {
		blk := sp.parent.Content[sp.idx+1]
		if len(blk.Content) > 0 {
			break
		}
		d.removePair(sp.parent, sp.idx)
	}
}

// removePair removes the key at index i of mapping m, and its value.
func (d *Doc) removePair(m *yaml.Node, i int) {
	if m == d.root && i == 0 {
		if hc := m.Content[0].HeadComment; hc != "" {
			if d.doc.HeadComment != "" {
				hc = d.doc.HeadComment + "\n\n" + hc
			}
			d.doc.HeadComment = hc
		}
	}
	m.Content = slices.Delete(m.Content, i, i+2)
}

// Bytes is the document as YAML, indented by two spaces. Comments and order are kept; blank lines
// between entries are not.
func (d *Doc) Bytes() ([]byte, error) {
	if len(d.root.Content) == 0 {
		// An empty mapping would be written as "{}": write the comments alone, or nothing.
		var parts []string
		for _, c := range []string{d.doc.HeadComment, d.doc.FootComment} {
			if c != "" {
				parts = append(parts, c)
			}
		}
		if len(parts) == 0 {
			return nil, nil
		}
		return []byte(strings.Join(parts, "\n\n") + "\n"), nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d.doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodedText is a scalar as the loader reads it as text: "16" for 0x10, "8" for 010, "5" for 5.0,
// "1" for true, "" for null. It is false for a node that is not a scalar or has no text form.
func DecodedText(n *yaml.Node) (string, bool) {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return "", false
	}
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		if x {
			return "1", true
		}
		return "0", true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}
