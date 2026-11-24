package findings

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/banner"
	"github.com/rafaelh/nyx/internal/eol"
	"github.com/rafaelh/nyx/internal/kinds"
)

// eolSoftware checks captured web technologies and port-banner versions against
// security-support dates. Ended support is medium severity; approaching expiry is low.
// Distribution builds and third-party-only versions are downgraded one level. Unmatched release
// cycles produce no finding.
func (d *calc) eolSoftware() []Finding {
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
	d       *calc
	horizon string // the last end date that is eol-approaching
	out     []Finding
}

// add evaluates a product/version on a service URL or port. A zero port denotes a web service;
// third-party-only sightings are unconfirmed.
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
	for key, attrs := range d.serviceAttrs() {
		values := append([]string{attrs.Server}, headers[key]...)
		for tech := range strings.SplitSeq(attrs.Technologies, ";") {
			if name, version, ok := strings.Cut(tech, ":"); ok && version != "" {
				a.add(key, netip.AddrPort{}, name, version, banner.Distro(version) || headerDistro(version, values), false)
			}
		}
	}
}

// ports prefers nyx's banner for confirmed ports, falling back to Shodan when it supplies a
// version nyx did not capture. Shodan-only versions remain unconfirmed.
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

// headerDistro recovers distribution context lost by Wappalyzer's numeric version. It checks
// the word containing the version and following parentheses, such as Apache's "(Ubuntu)"
// suffix.
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
