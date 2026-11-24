package output

import (
	"strconv"

	"github.com/rafaelh/nyx/internal/recon/kinds"
)

var thirdPartyColumns = []string{"root", "mechanism", "domain", "provider", "depth"}

// thirdPartyRows lists visible external dependencies across all mechanisms.
func thirdPartyRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.ThirdParty) {
		a := kinds.ThirdParty.Attrs(r)
		// Recover root/domain from the key even for non-current records so dependencies
		// brought into scope are hidden consistently.
		asked := r
		if len(r.Attrs) == 0 {
			asked.Attrs = map[string]any{"root": a.Root, "domain": a.Domain}
		}
		if !vis.Shown(kinds.ThirdParty, asked) {
			continue
		}
		rows = append(rows, recordRow(r, a.Root, a.Mechanism, a.Domain, a.Provider, strconv.Itoa(a.Depth)))
	}
	return rows
}
