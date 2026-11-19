package findings

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/banner"
	"github.com/rafaelh/nyx/internal/eol"
	"github.com/rafaelh/nyx/internal/kinds"
)

// eolSoftware derives the end-of-life findings: a version nyx already captured (a Wappalyzer
// technology of a shown web service, or the version in the banner of a shown open port) whose
// release cycle's security support has ended (medium, type eol) or ends within eol_warn_days
// (low, type eol-approaching). A version that is a distribution build, or that only Shodan's
// report of a port names, is one step lower. A version that matches no cycle is no finding.
func (d *deriver) eolSoftware() []Finding {
	// With a window of 0 the horizon is today, which the eol case already takes.
	horizon, ok := d.horizon(d.in.Settings.EOLWarnDays)
	if !ok {
		return nil
	}
	a := &eolAssessor{d: d, horizon: horizon}
	a.webServices()
	a.ports()
	return a.out
}

// eolAssessor collects the end-of-life findings of one derivation.
type eolAssessor struct {
	d       *deriver
	horizon string // the last end date that is eol-approaching
	out     []Finding
}

// add assesses one product and version seen at a target: a web service's URL, or the
// address and port of a banner (port is the zero value for a web service). A sighting
// known only from a third party's report is unconfirmed.
func (a *eolAssessor) add(target string, port netip.AddrPort, product, version string, distro, unconfirmed bool) {
	cycle, end, ok := eol.Lookup(product, version)
	if !ok {
		return
	}
	var typ string
	switch {
	case end == "" || end <= a.d.in.Today:
		typ = "eol"
	case end <= a.horizon:
		typ = "eol-approaching"
	default:
		return
	}
	seen, hostnames := "web", ""
	if port.IsValid() {
		seen, hostnames = "banner", strings.Join(a.d.hostnamesByIP()[port.Addr()], ";")
	}
	severity := Severity(EOLSoftware, typ)
	if distro || unconfirmed {
		severity = StepDown(severity)
	}
	confirmed := "yes"
	if unconfirmed {
		confirmed = "no"
	}
	a.out = append(a.out, newFinding(EOLSoftware, typ, severity, target, eolDetail(typ, product, version, cycle, end, distro, unconfirmed),
		map[string]any{"hostnames": hostnames, "product": product, "version": version, "end_date": end, "seen": seen, "confirmed": confirmed}))
}

// webServices assesses the versioned technologies of each shown web service.
func (a *eolAssessor) webServices() {
	d := a.d
	// The Server and X-Powered-By values of each service, which say whether a version Wappalyzer
	// read from them is a distribution build.
	headers := map[string][]string{}
	for _, r := range d.current(kinds.WebPosture) {
		if v := kinds.WebPosture.Attrs(r).VersionDisclosure; v != "" {
			headers[r.Key] = strings.Split(v, ";")
		}
	}
	for key, r := range d.services() {
		attrs := kinds.WebService.Attrs(r)
		values := append([]string{attrs.Server}, headers[key]...)
		for tech := range strings.SplitSeq(attrs.Technologies, ";") {
			if name, version, ok := strings.Cut(tech, ":"); ok && version != "" {
				a.add(key, netip.AddrPort{}, name, version, banner.Distro(version) || headerDistro(version, values), false)
			}
		}
	}
}

// ports assesses the banner of each shown port. A port nyx opened is read from its own
// banner. A port only Shodan reports, or one whose banner named no version that Shodan's
// does, is read from Shodan's and is unconfirmed.
func (a *eolAssessor) ports() {
	p := a.d.portIndex()
	for addr, banner := range p.open {
		if !a.portBanner(addr, banner, false) {
			if rep, ok := p.reported[addr]; ok {
				a.portBanner(addr, rep, true)
			}
		}
	}
	for addr, banner := range p.reported {
		if !p.opened[addr] {
			a.portBanner(addr, banner, true)
		}
	}
}

// portBanner assesses the product and version a stored banner names, and reports
// whether it named both.
func (a *eolAssessor) portBanner(addr netip.AddrPort, stored string, unconfirmed bool) bool {
	product, version, distro := banner.Parse(kinds.DecodeBanner(stored))
	if product == "" || version == "" {
		return false
	}
	a.add(addr.String(), addr, product, version, distro, unconfirmed)
	return true
}

// headerDistro reports whether a header value names version as a distribution build. Wappalyzer
// reports only the number (2.4.41 from "Apache/2.4.41 (Ubuntu)", 7.4.3 from
// "PHP/7.4.3-4ubuntu2.19"), so the word of a value that carries the version is read, with the
// parenthesised words that follow it.
func headerDistro(version string, values []string) bool {
	for _, v := range values {
		words := strings.Fields(v)
		for i, w := range words {
			_, after, ok := strings.Cut(w, "/")
			rest, found := strings.CutPrefix(after, version)
			if !ok || !found || (rest != "" && strings.ContainsAny(rest[:1], "0123456789.")) {
				continue
			}
			// A comment may be several words: (Red Hat Enterprise Linux), (Amazon Linux).
			inComment := false
			for _, next := range words[i+1:] {
				if !inComment && !strings.HasPrefix(next, "(") {
					break
				}
				rest += " " + next
				inComment = !strings.Contains(next, ")")
			}
			if banner.Distro(rest) {
				return true
			}
		}
	}
	return false
}

// eolDetail is the sentence of an end-of-life finding.
func eolDetail(typ, product, version, cycle, end string, distro, unconfirmed bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s (release cycle %s) ", product, version, cycle)
	switch {
	case typ == "eol-approaching":
		fmt.Fprintf(&b, "reaches the end of security support on %s", end)
	case end == "":
		b.WriteString("is past the end of security support (endoflife.date gives no date)")
	default:
		fmt.Fprintf(&b, "reached the end of security support on %s", end)
	}
	if distro {
		b.WriteString("; distribution build, which may carry fixes under its own version")
	}
	if unconfirmed {
		b.WriteString("; reported by Shodan, not confirmed by nyx")
	}
	return b.String()
}
