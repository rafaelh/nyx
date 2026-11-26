package cli

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
)

// procedureHelp supplies key requirements and purpose. Bracketed keys are optional; empty means
// unkeyed.
type procedureHelp struct{ key, does string }

// procedureHelps describes every procedure of defaultProcedures, by name.
var procedureHelps = map[string]procedureHelp{
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
	"learned-names":    {"", "Labels of found names tried under the other zones that have names"},
	"rdns":             {"", "PTR records of the addresses in in-scope netblocks"},
	"ipowner":          {"", "Origin AS of each address outside the in-scope netblocks (Team Cymru)"},
	"netblockowner":    {"", "Origin AS of the addresses inside the in-scope netblocks, once per /24 or /48, for the abusive-network check (Team Cymru)"},
	"dnsrecords":       {"", "NS, MX and TXT records of each name below the roots, and the names and third parties they show"},
	"dnsroot":          {"", "NS, SOA, TXT, CAA, MX and SRV records of each root, and the third parties they show"},
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

// proceduresHeading is the heading of the procedures topic.
const proceduresHeading = "Procedures, in the order each pass runs them:"

// proceduresFooter explains procedure controls after the table.
const proceduresFooter = `Third-party procedures ask public sources and resolvers, and run under --passive. Target procedures
contact the target's own systems: they are skipped under --passive, and unless --authorised
has confirmed, on this run or an earlier one, that you are authorised. A procedure with a KEY needs keys.<KEY>: without it
the procedure is not-configured, or left out of the run's output when its source has no free plan. A key in
brackets is optional. --redo <procedure> performs every job of one procedure again, and --skip <procedure>
turns one off, except the procedures marked *, which other procedures' safety depends on.`

// proceduresHelp lists procedures in registry order, their contacts, keys and purpose, followed by
// --passive, --redo and --skip behaviour.
func proceduresHelp(s layout.Stream, procedures []run.Procedure) string {
	return renderHelp(proceduresBlocks(procedures), s)
}

// procedureRow is a row of the procedures table.
type procedureRow struct{ name, contact, key, does string }

// procedureRows preserves registry execution order in help.
func procedureRows(procedures []run.Procedure) []procedureRow {
	var rows []procedureRow
	for _, s := range procedures {
		r := procedureRow{name: s.Name(), contact: "third party"}
		if s.Contact() == run.Target {
			r.contact = "target"
		}
		if isRequired(s) {
			r.name += "*"
		}
		h := procedureHelps[s.Name()]
		r.key, r.does = h.key, h.does
		rows = append(rows, r)
	}
	return rows
}

// proceduresBlocks assembles the procedures topic's heading, table and footer.
func proceduresBlocks(procedures []run.Procedure) []helpBlock {
	rows := procedureRows(procedures)
	var b helpBuilder
	b.heading(proceduresHeading)
	b.blocks = append(b.blocks, helpBlock{kind: blockTable, lines: plainProceduresTable(rows),
		table: func(s layout.Stream) layout.Table { return proceduresTable(s, rows) }})
	b.blank()
	b.free(proceduresFooter, nil)
	return b.blocks
}

// plainProceduresTable pads columns to their widest cell for non-terminal output.
func plainProceduresTable(rows []procedureRow) []string {
	all := append([]procedureRow{{"PROCEDURE", "CONTACT", "KEY", "WHAT IT DOES"}}, rows...)
	var wName, wContact, wKey int
	for _, r := range all {
		wName, wContact, wKey = max(wName, len(r.name)), max(wContact, len(r.contact)), max(wKey, len(r.key))
	}
	lines := make([]string, len(all))
	for i, r := range all {
		line := fmt.Sprintf("  %-*s  %-*s  %-*s  %s", wName, r.name, wContact, r.contact, wKey, r.key, r.does)
		lines[i] = strings.TrimRight(line, " ")
	}
	return lines
}

// proceduresTable colours procedure names as information, third-party contact as success, target
// contact as warning and key names as muted.
func proceduresTable(s layout.Stream, rows []procedureRow) layout.Table {
	text := func(entry string) func(string) string {
		return func(x string) string { return s.Depth.Text(palette.Semantic, entry, x) }
	}
	t := layout.Table{
		Indent:   2,
		Bordered: true,
		Columns: []layout.Column{{Header: "PROCEDURE"}, {Header: "CONTACT"}, {Header: "KEY"},
			{Header: "WHAT IT DOES", Wrap: layout.Spaces, Shrink: 1}},
	}
	for _, r := range rows {
		contact := text("success")
		if r.contact == "target" {
			contact = text("warning")
		}
		t.Rows = append(t.Rows, []layout.Cell{
			{{Text: r.name, Style: text("info")}},
			{{Text: r.contact, Style: contact}},
			{{Text: r.key, Style: text("muted")}},
			layout.Plain(r.does),
		})
	}
	return t
}
