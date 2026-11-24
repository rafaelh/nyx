// Package configedit changes selected YAML settings while preserving other values, comments and
// order. Dotted keys are matched case-insensitively through document nodes. Save replaces files
// atomically; Store adapts the document to setup.Backend.
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

// Doc holds a YAML config document with case-insensitive dotted keys such as "keys.shodan". It
// is not safe for concurrent use.
type Doc struct {
	doc  *yaml.Node // the document node
	root *yaml.Node // its mapping
}

// Entry describes a setting found by Lookup.
type Entry struct {
	// Node selects the first file-order value, or nil when absent.
	Node *yaml.Node
	// Variants lists case-conflicting key paths in file order, including conflicting parent
	// blocks. Since the loader keeps only one spelling, these settings are ambiguous. Nil
	// means no conflict.
	Variants []string
}

// Parse accepts one YAML mapping document, including empty or comment-only files. It preserves
// comments for editing.
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

// commentsOnly preserves a node-free file as one YAML head comment.
func commentsOnly(data []byte) string {
	var lines []string
	for l := range strings.SplitSeq(string(data), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// keyName matches loader key normalisation.
func keyName(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	return strings.ToLower(n.Value), true
}

// find returns matching normalised mapping-key indexes in file order.
func find(m *yaml.Node, want string) []int {
	var out []int
	for i := 0; i+1 < len(m.Content); i += 2 {
		if name, ok := keyName(m.Content[i]); ok && name == want {
			out = append(out, i)
		}
	}
	return out
}

// Lookup searches all case variants of parent blocks, including settings hidden beneath a
// duplicate spelling.
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

// span traces a setting's parent mappings for replacement and cleanup.
type span struct {
	parent *yaml.Node
	idx    int
}

// block finds a setting's parent mapping and the path to it. Case-variant blocks merge into the
// first spelling; valueless keys become mappings. With create=false, missing blocks return nil
// without error.
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

// openBlock promotes empty values to mappings and rejects incompatible nodes.
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

// SetString replaces a setting in place, preserving comments and spelling while collapsing case
// variants. It quotes values such as "0123" or "yes" to preserve their text. Invalid UTF-8 is
// rejected.
func (d *Doc) SetString(key, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s: the value is not valid UTF-8", key)
	}
	return d.set(key, func(old *yaml.Node) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	})
}

// SetList writes a block sequence of strings. Existing items matched after trimming and
// lowercasing retain their nodes and comments. An empty list removes the key.
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

// set builds a replacement from the previous value and installs it at key.
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
		// Keep the comment beside the sequence key rather than its first item.
		cur.Content[first].LineComment, n.LineComment = n.LineComment, ""
	}
	cur.Content[first+1] = n
	for _, j := range slices.Backward(idxs[1:]) {
		cur.Content = slices.Delete(cur.Content, j, j+2)
	}
	return nil
}

// Clear removes a key, its case variants and comments, and newly empty parent blocks. It
// preserves a first-entry header comment on the document. Missing keys are unchanged.
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

// Bytes emits two-space YAML while preserving comments/order, but not inter-entry blank lines.
func (d *Doc) Bytes() ([]byte, error) {
	if len(d.root.Content) == 0 {
		// Preserve comment-only output without emitting an empty-mapping literal.
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

// DecodedText reproduces the loader's scalar conversion, including numeric bases, booleans and
// null. It returns false for non-scalars or unsupported text forms.
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
