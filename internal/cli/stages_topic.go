package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
)

// stageHelp is what nyx help stages says about one stage: the key it needs ("" for none; in
// brackets when it works without one) and what it does.
type stageHelp struct{ key, does string }

// stageHelps describes every stage of defaultStages, by name.
var stageHelps = map[string]stageHelp{
	"asn":              {"", "Netblocks announced by each input ASN (RIPEstat)"},
	"org-asn":          {"", "Netblocks registered to each --org, as candidates (RIPEstat)"},
	"ct-org":           {"", "Root domains on certificates issued to each --org (crt.sh)"},
	"whoisxml":         {"whoisxml", "Root domains registered to each --org, by reverse WHOIS"},
	"crtsh":            {"", "Subdomains from certificate transparency logs (crt.sh)"},
	"wayback":          {"", "Subdomains and URLs archived by the Wayback Machine"},
	"commoncrawl":      {"", "Subdomains and URLs in the Common Crawl index"},
	"virustotal":       {"virustotal", "Subdomains VirusTotal knows of"},
	"securitytrails":   {"securitytrails", "Subdomains SecurityTrails knows of"},
	"hackertarget":     {"", "Subdomains from HackerTarget's host search"},
	"urlscan":          {"", "Subdomains seen in urlscan.io scans"},
	"certspotter":      {"(certspotter)", "Subdomains from certificate transparency logs (Cert Spotter)"},
	"censys":           {"censys", "Subdomains Censys knows of"},
	"chaos":            {"chaos", "Subdomains in ProjectDiscovery's Chaos dataset"},
	"github":           {"github", "Public code on GitHub that mentions an in-scope root"},
	"shodan":           {"shodan", "Addresses, hostnames and ports Shodan reports in each in-scope netblock"},
	"shodan-dns":       {"shodan", "Subdomains and DNS records Shodan holds for each root"},
	"providerranges":   {"", "Address ranges cloud and CDN providers publish, to tell shared infrastructure"},
	"resolve":          {"", "A and AAAA records of each hostname and root, from public resolvers"},
	"wildcard":         {"", "Lookups of random labels in each zone, to detect wildcard DNS"},
	"permutations":     {"", "Variations of found labels and the wordlist that exist in DNS"},
	"rdns":             {"", "PTR records of the addresses in in-scope netblocks"},
	"ipowner":          {"", "Origin AS of each address outside the in-scope netblocks (Team Cymru)"},
	"dnsroot":          {"", "NS, SOA, TXT, CAA and SRV records of each root, and the third parties they show"},
	"rdap":             {"", "Who registered each netblock, and what is registered to each --org"},
	"shodan-host":      {"shodan", "Ports, banners and hostnames Shodan holds for addresses its search missed"},
	"reverseip":        {"(securitytrails)", "Other hostnames that point at each dedicated address (HackerTarget)"},
	"dnshistory":       {"securitytrails", "Addresses each CDN- or WAF-fronted hostname resolved to in the past (SecurityTrails)"},
	"email":            {"", "Mail posture of each root (MX, SPF, DMARC, MTA-STS, DKIM) and its mail providers"},
	"nsreverse":        {"securitytrails", "Domains hosted on the name servers and mail hosts the organisation runs itself (SecurityTrails)"},
	"httpprobe":        {"", "HTTP and HTTPS services on each hostname and open port, as a browser sees them"},
	"crawl":            {"", "GET-only walk of each web service's own pages, robots.txt and sitemaps"},
	"jsparse":          {"", "URLs and hostnames named in the scripts the crawl found"},
	"identifier-pivot": {"shodan", "Shodan searches for hosts that share a site's analytics IDs or favicon"},
	"storage":          {"", "Cloud storage buckets that are referenced or guessed, checked anonymously"},
	"takeover":         {"", "One GET of each provider-hosted site, matched against unclaimed-resource pages"},
	"sensitive-paths":  {"", "Requests for the sensitive-path list on each web service"},
	"origincheck":      {"", "One GET of / to each candidate origin of a CDN- or WAF-fronted hostname, to see whether it serves the site"},
	"ports":            {"", "TCP handshakes to the configured ports, keeping any banner sent unprompted"},
}

// stagesHelp is the stages topic at depth d: a table of stages in registry order with whom each
// contacts, the key it needs and what it does, then how --passive, --redo and --skip treat them.
func stagesHelp(d palette.Depth, stages []run.Stage) string {
	type row struct{ name, contact, key, does string }
	header := row{"STAGE", "CONTACT", "KEY", "WHAT IT DOES"}
	rows := []row{header}
	for _, s := range stages {
		r := row{name: s.Name(), contact: "third party"}
		if s.Contact() == run.Target {
			r.contact = "target"
		}
		if slices.Contains(unskippable, r.name) {
			r.name += "*"
		}
		h := stageHelps[s.Name()]
		r.key, r.does = h.key, h.does
		rows = append(rows, r)
	}
	var wName, wContact, wKey int
	for _, r := range rows {
		wName, wContact, wKey = max(wName, len(r.name)), max(wContact, len(r.contact)), max(wKey, len(r.key))
	}
	// cell styles s and then pads it to w, so escape codes never upset a column. The header row is
	// bold.
	cell := func(header bool, s string, w int, style func(string) string) string {
		gap := strings.Repeat(" ", max(0, w-len(s)))
		switch {
		case header:
			return d.Bold(s) + gap
		case s != "":
			return style(s) + gap
		}
		return gap
	}
	text := func(g palette.Group, entry string) func(string) string {
		return func(s string) string { return d.Text(g, entry, s) }
	}
	var b strings.Builder
	b.WriteString(d.Bold("Stages, in the order each pass runs them:") + "\n")
	for i, r := range rows {
		contact := text(palette.Semantic, "success")
		if r.contact == "target" {
			contact = text(palette.Semantic, "warning")
		}
		h := i == 0
		line := fmt.Sprintf("  %s  %s  %s  %s", cell(h, r.name, wName, text(palette.Semantic, "info")),
			cell(h, r.contact, wContact, contact), cell(h, r.key, wKey, text(palette.Chrome, "TIMESTAMP")),
			cell(h, r.does, 0, func(s string) string { return s }))
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	b.WriteString(`
Third-party stages ask public sources and resolvers, and run under --passive. Target stages
contact the target's own systems: they are skipped under --passive and until you confirm you
are authorised. A stage with a KEY needs keys.<KEY> and is not-configured without it; a key in
brackets is optional. --redo <stage> performs every check of one stage again, and --skip <stage>
turns one off, except the stages marked *, which other stages' safety depends on.
`)
	return b.String()
}
