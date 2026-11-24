package findings

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/origin"
)

// originArrow joins the hostname and the address of an origin exposure's target.
const originArrow = " -> "

// originTarget identifies a hostname/address pair. The same key preserves one finding row as
// the origin moves between possible and confirmed.
func originTarget(host, addr string) string { return host + originArrow + addr }

// splitOriginTarget reverses originTarget.
func splitOriginTarget(target string) (host, addr string) {
	host, addr, _ = strings.Cut(target, originArrow)
	return host, addr
}

// originExposure compares candidate origins with the hostname's probed service. Matching
// confirmation rules yield medium severity; other candidates remain possible at low severity,
// including uncontactable ones. Pairs that stop qualifying are no longer derived.
func (d *deriver) originExposure() []Finding {
	pairs := origin.Pairs(d.in.Scope, d.in.Inv, d.vis, d.in.Records, d.in.Settings.OriginCheck.MaxCandidates)
	if len(pairs) == 0 {
		return nil
	}
	answers := origin.Answers(d.in.Records)
	out := make([]Finding, 0, len(pairs))
	for _, p := range pairs {
		addr := p.Addr.String()
		by, confirmed := "", false
		if a, ok := answers[p.Key()]; ok {
			by, confirmed = origin.Confirmed(p.Probe, a)
		}
		found := strings.Join(p.Found, ";")
		typ, confirmedCol := "possible", "no"
		var detail string
		switch {
		case confirmed:
			typ, confirmedCol = "confirmed", "yes"
			detail = fmt.Sprintf("%s is behind %s, and %s answers for it (confirmed by %s; found by %s)", p.Host, p.Provider, addr, by, found)
		case !p.Contactable:
			detail = fmt.Sprintf("%s is behind %s; %s may be its origin (found by %s) but is not contacted", p.Host, p.Provider, addr, found)
		default:
			detail = fmt.Sprintf("%s is behind %s; %s may be its origin (found by %s), not confirmed", p.Host, p.Provider, addr, found)
		}
		out = append(out, newFinding(OriginExposure, typ, Severity(OriginExposure, typ), originTarget(p.Host, addr), detail,
			map[string]any{"hostname": p.Host, "provider": p.Provider, "address": addr, "found_by": found,
				"confirmed_by": by, "confirmed": confirmedCol}))
	}
	return out
}
