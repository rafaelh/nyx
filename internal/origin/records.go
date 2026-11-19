package origin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Records returns the current records of a kind: View.Records of a stage, and the findings' reader.
type Records func(kinds.Named) []store.Record

// Pair is a candidate with what the check and the findings need to decide it: what the probe saw
// of the fronted hostname's HTTPS service.
type Pair struct {
	Candidate
	Probe       Probe
	CertSubject string // the subject of the certificate the probe saw
}

// Probed says the fronted host's HTTPS service has a 2xx status: no check is made before that.
func (p Pair) Probed() bool { return p.Probe.Status >= 200 && p.Probe.Status < 300 }

// Key is the key of the pair's origin_check record.
func (p Pair) Key() string { return p.Host + "|" + p.Addr.String() }

// CheckKey is the key of the pair's check: the pair and a hash of the probe's title and certificate
// subject, so that a change in either checks the pair again.
func (p Pair) CheckKey() string {
	sum := sha256.Sum256([]byte(p.Probe.Title + "\x00" + p.CertSubject))
	return p.Key() + "|" + hex.EncodeToString(sum[:4])
}

// FrontedHosts are the in-scope hostnames that currently resolve to a CDN or WAF, in name order,
// with their provider. They are the probe hostnames, so a wildcard zone is one name.
func FrontedHosts(sc *scope.Scope, inv *inventory.Inventory) []Front {
	var out []Front
	for _, h := range inv.ProbeHostnames(sc) {
		if p, ok := inv.Fronted(h); ok {
			out = append(out, Front{Host: h, Provider: p})
		}
	}
	return out
}

// Pairs derives the candidates of every fronted hostname from the current records: the historical
// addresses and the probed web services, with at most max candidates for each hostname. vis is
// the caller's showing rules for sc and inv.
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
	// Candidates reads only a fronted host's history, and a fronted host is in scope.
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

// Answers are the current origin_check records, by pair key ("host|address").
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
