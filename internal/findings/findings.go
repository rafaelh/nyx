// Package findings derives the severity-ranked list of obvious exposures from
// the evidence the stages stored. Derivation is pure: stages store only
// evidence, and findings are computed on read from it, the Scope, the
// Inventory, the settings and today's date, so a finding that is no longer true
// (a port excluded later, a certificate renewed, the clock moving on) is simply
// not derived any more and none can go stale.
package findings

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Input is everything Derive reads. Records returns the records of a kind
// (derivation uses only the current ones), and is called only for the kinds
// derivation needs. Roots and Orgs are the engagement's stored scope inputs.
type Input struct {
	Scope       *scope.Scope
	Inv         *inventory.Inventory
	Settings    config.Settings
	Today       string // YYYY-MM-DD
	Records     func(kinds.Named) []store.Record
	Roots, Orgs []string
	// Abusive is the snapshot of abusive networks and ASNs to check addresses against; nil checks none.
	Abusive *abusive.Snapshot
	// HistoryOnly reports whether DNS history alone names the address; nil means none is.
	HistoryOnly func(netip.Addr) bool
	// Vis, if set, is the Visibility of Scope and Inv to reuse, with the host
	// decisions it has already made.
	Vis *kinds.Visibility
}

// Finding is one derived exposure. Attrs holds every attribute of its stored
// record: category, type, severity, target and detail, plus the columns of the
// category's file.
type Finding struct {
	Category, Type, Severity, Target, Detail string
	Attrs                                    map[string]any
}

func newFinding(category, typ, severity, target, detail string, attrs map[string]any) Finding {
	a := map[string]any{"category": category, "type": typ, "severity": severity, "target": target, "detail": detail}
	maps.Copy(a, attrs)
	return Finding{Category: category, Type: typ, Severity: severity, Target: target, Detail: detail, Attrs: a}
}

// DeriveAll computes the findings and the storage Attribution together, so the
// references, guesses and public states they share are computed once.
func DeriveAll(in Input) ([]Finding, map[string]StorageAttr) {
	d := newDeriver(in)
	return d.findings(), d.attribution()
}

func (d *deriver) findings() []Finding {
	var out []Finding
	out = append(out, d.takeovers()...)
	out = append(out, d.storage()...)
	out = append(out, d.sensitivePaths()...)
	out = append(out, d.email()...)
	out = append(out, d.ports()...)
	out = append(out, d.certificates()...)
	out = append(out, d.webPosture()...)
	out = append(out, d.originExposure()...)
	out = append(out, d.eolSoftware()...)
	out = append(out, d.abusiveNetworks()...)
	// Sorted and deduplicated by key, each key built once.
	type keyed struct {
		key string
		f   Finding
	}
	ks := make([]keyed, len(out))
	for i, f := range out {
		ks[i] = keyed{f.Key(), f}
	}
	slices.SortStableFunc(ks, func(a, b keyed) int { return strings.Compare(a.key, b.key) })
	ks = slices.CompactFunc(ks, func(a, b keyed) bool { return a.key == b.key })
	out = out[:len(ks)]
	for i, k := range ks {
		out[i] = k.f
	}
	return out
}

type deriver struct {
	in   Input
	vis  *kinds.Visibility
	refs []cloudstorage.Reference // see references
	svcs map[string]store.Record  // see services

	public map[string][]bool // see publicStates

	hosts   map[netip.Addr][]string // see hostnamesByIP
	portIdx *portIndex              // see portIndex
}

func newDeriver(in Input) *deriver {
	vis := in.Vis
	if vis == nil {
		vis = kinds.NewVisibility(in.Scope, in.Inv)
	}
	return &deriver{in: in, vis: vis}
}

// current is the current records of a kind.
func (d *deriver) current(k kinds.Named) []store.Record {
	var out []store.Record
	for _, r := range d.in.Records(k) {
		if r.Current {
			out = append(out, r)
		}
	}
	return out
}

// services indexes the current, visible web services by key.
func (d *deriver) services() map[string]store.Record {
	if d.svcs != nil {
		return d.svcs
	}
	d.svcs = map[string]store.Record{}
	for _, r := range d.current(kinds.WebService) {
		if d.vis.Shown(kinds.WebService, r) {
			d.svcs[r.Key] = r
		}
	}
	return d.svcs
}

// hostnamesByIP is the in-scope hostnames behind each address, computed once.
func (d *deriver) hostnamesByIP() map[netip.Addr][]string {
	if d.hosts == nil {
		d.hosts = d.in.Inv.HostnamesByIP(d.in.Scope)
	}
	return d.hosts
}

// portIndex holds the ports the risky-port and end-of-life findings read.
type portIndex struct {
	opened   map[netip.AddrPort]bool   // every current open port: one nyx opened supersedes a report of it
	open     map[netip.AddrPort]string // the banner of each shown open port
	reported map[netip.AddrPort]string // the banner of each shown reported port
}

// portIndex indexes the current ports, computed once.
func (d *deriver) portIndex() *portIndex {
	if d.portIdx != nil {
		return d.portIdx
	}
	opens := d.current(kinds.OpenPort)
	d.portIdx = &portIndex{opened: kinds.OpenedPorts(opens), open: map[netip.AddrPort]string{}, reported: map[netip.AddrPort]string{}}
	for _, r := range opens {
		if addr, ok := kinds.ParsePortKey(r.Key); ok && d.vis.Shown(kinds.OpenPort, r) {
			d.portIdx.open[addr] = kinds.OpenPort.Attrs(r).Banner
		}
	}
	for _, r := range d.current(kinds.ReportedPort) {
		if addr, ok := kinds.ParsePortKey(r.Key); ok && d.vis.Shown(kinds.ReportedPort, r) {
			d.portIdx.reported[addr] = kinds.ReportedPort.Attrs(r).Banner
		}
	}
	return d.portIdx
}

// horizon is the date days after today, or false when today does not parse.
func (d *deriver) horizon(days int) (string, bool) {
	today, err := time.Parse(time.DateOnly, d.in.Today)
	if err != nil {
		return "", false
	}
	return today.AddDate(0, 0, days).Format(time.DateOnly), true
}

// isTrue reads an attribute that may be unknown: only a known true is true.
func isTrue(b *bool) bool { return b != nil && *b }

func (d *deriver) sensitivePaths() []Finding {
	svcs := d.services()
	severity := map[string]string{} // path|hash -> the entry's severity
	for _, e := range d.in.Settings.SensitivePathEntries {
		if k := e.Path + "|" + e.Hash(); severity[k] == "" {
			severity[k] = e.Severity
		}
	}
	var out []Finding
	for _, r := range d.current(kinds.SensitiveHit) {
		a := kinds.SensitiveHit.Attrs(r)
		if _, ok := svcs[a.Service]; !ok {
			continue
		}
		sev := cmp.Or(severity[a.Path+"|"+a.Hash], Medium)
		out = append(out, newFinding(SensitivePaths, a.Path, sev, a.URL,
			fmt.Sprintf("%s answered %d with %q", a.URL, a.Status, a.Signature),
			map[string]any{"url": a.URL, "path": a.Path, "status": a.Status, "size": a.Size, "signature": a.Signature}))
	}
	return out
}

func (d *deriver) email() []Finding {
	var out []Finding
	for _, r := range d.current(kinds.EmailPosture) {
		if !d.vis.Shown(kinds.EmailPosture, r) {
			continue
		}
		root := r.Key
		add := func(typ, detail string) {
			out = append(out, newFinding(Email, typ, Severity(Email, typ), root, detail, map[string]any{"root": root}))
		}
		a := kinds.EmailPosture.Attrs(r)
		spf := a.SPF
		invalid := a.SPFError != "" || a.SPFRecords > 1
		switch {
		case invalid:
			add("spf-invalid", "SPF is invalid: "+a.SPFError)
		case spf == "":
			add("spf-missing", "no SPF record")
		default:
			if n := a.SPFLookups; n > 10 {
				add("spf-lookups", fmt.Sprintf("SPF needs %d DNS lookups (the limit is 10)", n))
			}
		}
		// The record's own "all" is reported even when an include made it invalid:
		// a +all says so whatever the rest of the record does.
		switch a.SPFAll {
		case "+all":
			add("spf-all-plus", "SPF allows anyone to send: "+spf)
		case "?all":
			add("spf-all-neutral", "SPF ends in ?all: "+spf)
		}
		if a.DMARC == "" {
			add("dmarc-missing", "no DMARC record")
		} else if a.DMARCPolicy == "none" {
			add("dmarc-none", "the applicable DMARC policy is none: "+a.DMARC)
		}
		if a.MX == "" && !strings.EqualFold(strings.Join(strings.Fields(spf), " "), "v=spf1 -all") {
			add("no-mx-spf", "no MX record, and the domain does not say it sends no mail (v=spf1 -all)")
		}
		// mta_sts is empty for a root with no mail host, which has no policy to publish.
		if a.MTASTS == "absent" {
			add("mta-sts-missing", "the domain receives mail but publishes no single MTA-STS policy record (v=STSv1) at _mta-sts."+root)
		}
	}
	return out
}

// ports derives the risky-port findings. A port nyx opened is at the full
// severity and confirmed. A port only a third party reports (and nyx has not
// found closed, which the showing rule decides) is the same finding one step
// lower and unconfirmed, and becomes the full one when nyx opens it.
func (d *deriver) ports() []Finding {
	risky := map[int]bool{}
	for _, p := range d.in.Settings.RiskyPorts {
		risky[p] = true
	}
	var out []Finding
	add := func(addr netip.AddrPort, severity, banner, detail, confirmed string) {
		hostnames := d.hostnamesByIP()
		out = append(out, newFinding(Ports, "risky-port", severity, addr.String(), detail,
			map[string]any{"ip": addr.Addr().String(), "port": int(addr.Port()), "banner": banner,
				"hostnames": strings.Join(hostnames[addr.Addr()], ";"), "confirmed": confirmed}))
	}
	p := d.portIndex()
	for addr, banner := range p.open {
		if risky[int(addr.Port())] {
			add(addr, Severity(Ports, "risky-port"), banner,
				fmt.Sprintf("port %d is open on %s", addr.Port(), addr.Addr()), "yes")
		}
	}
	for addr, banner := range p.reported {
		if risky[int(addr.Port())] && !p.opened[addr] {
			add(addr, StepDown(Severity(Ports, "risky-port")), banner,
				fmt.Sprintf("port %d is reported open on %s by Shodan; nyx has not confirmed it", addr.Port(), addr.Addr()), "no")
		}
	}
	return out
}

func (d *deriver) certificates() []Finding {
	horizon, ok := d.horizon(d.in.Settings.CertExpiryDays)
	if !ok {
		return nil
	}
	var out []Finding
	for _, r := range d.services() {
		a := kinds.WebService.Attrs(r)
		var types []string
		expiry := a.TLSExpiry
		switch {
		case expiry == "":
		case expiry < d.in.Today:
			types = append(types, "expired")
		case expiry < horizon:
			types = append(types, "expiring")
		}
		if d.hostnameMismatch(a) {
			types = append(types, "hostname-mismatch")
		}
		legacy := a.TLSVersion == "TLS 1.0" || a.TLSVersion == "TLS 1.1"
		if legacy {
			types = append(types, "legacy-tls")
		}
		if isTrue(a.TLSSelfSigned) {
			types = append(types, "self-signed")
		}
		if len(types) == 0 {
			continue
		}
		typ := strings.Join(types, ";") // in the order of the types, which is alphabetical
		detail := fmt.Sprintf("%s certificate (%s), expires %s", typ, a.TLSSubject, expiry)
		if legacy {
			detail += ", negotiated " + a.TLSVersion
		}
		out = append(out, newFinding(Certificates, typ, Severity(Certificates, typ), r.Key, detail,
			map[string]any{"url": r.Key, "tls_subject": a.TLSSubject, "tls_issuer": a.TLSIssuer, "tls_expiry": expiry}))
	}
	return out
}

// hostnameMismatch reports whether the certificate does not name the host that
// was probed, for a host whose certificate is the target's to fix: not an IP
// literal, and not one that shared provider infrastructure (a CDN or SaaS
// platform) serves.
func (d *deriver) hostnameMismatch(a kinds.WebServiceAttrs) bool {
	if kinds.TLSTrust(a) != kinds.TrustHostnameMismatch {
		return false
	}
	_, isIP := input.IPLiteral(a.Host)
	return !isIP && !d.in.Inv.ProviderServed(a.Host)
}
