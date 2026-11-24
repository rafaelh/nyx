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
		// Shown recovers a non-current record's root and domain from its key, so a dependency
		// brought into scope is hidden whether or not it is current.
		if !vis.Shown(kinds.ThirdParty, r) {
			continue
		}
		a := kinds.ThirdParty.Attrs(r)
		rows = append(rows, recordRow(r, a.Root, a.Mechanism, a.Domain, a.Provider, strconv.Itoa(a.Depth)))
	}
	return rows
}
