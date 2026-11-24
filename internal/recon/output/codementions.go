package output

import "github.com/rafaelh/nyx/internal/recon/kinds"

var codeMentionColumns = []string{"repository", "path", "url", "hostnames", "root"}

// codeMentionRows lists mentions for in-scope roots. Non-current records have lost root
// attributes, so only their URL key is listed.
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
