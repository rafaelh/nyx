package origin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// Records adapts procedure and findings readers to current-kind access.
type Records func(kinds.Named) []store.Record

// Pair includes a candidate and the fronted host's HTTPS probe data needed for jobs and
// findings.
type Pair struct {
	Candidate
	Probe       Probe
	CertSubject string // the subject of the certificate the probe saw
}

// Probed requires a 2xx HTTPS baseline before checking candidate origins.
func (p Pair) Probed() bool { return p.Probe.Status >= 200 && p.Probe.Status < 300 }

// Key is the key of the pair's origin_check record.
func (p Pair) Key() string {
	return kinds.OriginCheck.Key(kinds.OriginCheckAttrs{Host: p.Host, Addr: p.Addr.String()})
}

// JobKey includes the pair and a hash of the probed title/certificate subject so changes
// trigger another origin check.
func (p Pair) JobKey() string {
	sum := sha256.Sum256([]byte(p.Probe.Title + "\x00" + p.CertSubject))
	return p.Key() + "|" + hex.EncodeToString(sum[:4])
}

// FrontedHosts returns sorted in-scope probe names on a CDN/WAF with provider labels, using one
// representative per wildcard zone.
func FrontedHosts(sc *scope.Scope, inv *inventory.Inventory) []Front {
	var out []Front
	for _, h := range inv.ProbeHostnames(sc) {
		if p, ok := inv.Fronted(h); ok {
			out = append(out, Front{Host: h, Provider: p})
		}
	}
	return out
}

// Pairs combines current DNS history and probed services into at most max candidates per
// fronted host, using the caller's visibility rules.
func Pairs(sc *scope.Scope, inv *inventory.Inventory, vis *kinds.Visibility, records Records, max int) []Pair {
	fronts := FrontedHosts(sc, inv)
	if len(fronts) == 0 {
		return nil
	}
	var services []Service
	probes := map[string]kinds.WebServiceAttrs{} // the https service of each host
	for _, r := range records(kinds.WebService) {
		if !r.Current || !vis.Shown(kinds.WebService, r) {
			continue
		}
		a := kinds.WebService.Attrs(r)
		var names []string
		for n := range strings.SplitSeq(a.TLSSANs, ";") {
			if n != "" {
				names = append(names, n)
			}
		}
		services = append(services, Service{Host: a.Host, Title: a.Title, Names: names})
		if a.Scheme == "https" && a.Port == 443 {
			probes[a.Host] = a
		}
	}
	for i := range fronts {
		fronts[i].Title = probes[fronts[i].Host].Title
	}
	// Only fronted in-scope hosts need history for candidate selection.
	var hist []HistoricalAddr
	for _, r := range records(kinds.HistoricalAddress) {
		if !r.Current {
			continue
		}
		a := kinds.HistoricalAddress.Attrs(r)
		if addr, err := netip.ParseAddr(a.Addr); err == nil {
			hist = append(hist, HistoricalAddr{Host: a.Host, Addr: addr, LastSeen: a.LastSeen})
		}
	}
	cands := Candidates(fronts, hist, services, inv, sc, max)
	out := make([]Pair, len(cands))
	for i, c := range cands {
		p := probes[c.Host]
		out[i] = Pair{Candidate: c, Probe: Probe{Status: p.Status, Title: p.Title, BodyLen: p.BodyLen}, CertSubject: p.TLSSubject}
	}
	return out
}

// Answers indexes current origin_check evidence by host/address pair.
func Answers(records Records) map[string]Answer {
	out := map[string]Answer{}
	for _, r := range records(kinds.OriginCheck) {
		if r.Current {
			a := kinds.OriginCheck.Attrs(r)
			out[r.Key] = Answer{Status: a.Status, Title: a.Title, BodyLen: a.BodyLen, CertNamesHost: a.CertNamesHost}
		}
	}
	return out
}
