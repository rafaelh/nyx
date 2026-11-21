package findings

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/origin"
)

// originArrow joins the hostname and the address of an origin exposure's target.
const originArrow = " -> "

// originTarget is the target of an origin exposure: the hostname and the address it may be exposed
// at. The record key holds the same two parts, so a pair keeps one row whether it is a possible
// origin or a confirmed one.
func originTarget(host, addr string) string { return host + originArrow + addr }

// splitOriginTarget reverses originTarget.
func splitOriginTarget(target string) (host, addr string) {
	host, addr, _ = strings.Cut(target, originArrow)
	return host, addr
}

// originExposure derives one finding for each candidate origin of a hostname behind a CDN or WAF
// (see package origin). It is confirmed (medium) when the origincheck answer for the pair meets the
// confirmation rules against what the probe saw of the hostname; otherwise it is possible (low),
// which includes a candidate that may not be contacted and one whose answer does not confirm. A
// pair that no longer qualifies is not derived, so its finding stops being current.
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
