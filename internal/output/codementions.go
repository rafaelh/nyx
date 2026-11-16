package output

import "github.com/rafaelh/nyx/internal/kinds"

var codeMentionColumns = []string{"repository", "path", "url", "hostnames", "root"}

// codeMentionRows lists the code mentions of the in-scope roots. A mention that
// is no longer current has no attributes, so it has no root to ask the showing
// rule about: it is listed with only its URL, the key.
func codeMentionRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.CodeMention) {
		if r.Current && !vis.Shown(kinds.CodeMention, r) {
			continue
		}
		a := kinds.CodeMention.Attrs(r)
		rows = append(rows, recordRow(r, a.Repository, a.Path, r.Key, a.Hostnames, a.Root))
	}
	return rows
}
