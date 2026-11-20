package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/layout"
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

// stagesHeading is the heading of the stages topic.
const stagesHeading = "Stages, in the order each pass runs them:"

// stagesFooter is what the stages topic says after its table.
const stagesFooter = `Third-party stages ask public sources and resolvers, and run under --passive. Target stages
contact the target's own systems: they are skipped under --passive, and unless --authorised
has confirmed, on this run or an earlier one, that you are authorised. A stage with a KEY needs keys.<KEY> and is not-configured without it; a key in
brackets is optional. --redo <stage> performs every check of one stage again, and --skip <stage>
turns one off, except the stages marked *, which other stages' safety depends on.`

// stagesHelp is the stages topic for s: a table of stages in registry order with whom each
// contacts, the key it needs and what it does, then how --passive, --redo and --skip treat them.
func stagesHelp(s layout.Stream, stages []run.Stage) string {
	return renderHelp(stagesBlocks(stages), s)
}

// stageRow is a row of the stages table.
type stageRow struct{ name, contact, key, does string }

// stageRows are the rows of the stages table, the stages in registry order.
func stageRows(stages []run.Stage) []stageRow {
	var rows []stageRow
	for _, s := range stages {
		r := stageRow{name: s.Name(), contact: "third party"}
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
	return rows
}

// stagesBlocks are the blocks of nyx help stages: its heading, its table and its footer.
func stagesBlocks(stages []run.Stage) []helpBlock {
	rows := stageRows(stages)
	var b helpBuilder
	b.heading(stagesHeading)
	b.blocks = append(b.blocks, helpBlock{kind: blockTable, lines: plainStagesTable(rows),
		table: func(s layout.Stream) layout.Table { return stagesTable(s, rows) }})
	b.blank()
	b.free(stagesFooter, nil)
	return b.blocks
}

// plainStagesTable is the table's text for a stream that is not a terminal: its columns padded to
// their widest cell.
func plainStagesTable(rows []stageRow) []string {
	all := append([]stageRow{{"STAGE", "CONTACT", "KEY", "WHAT IT DOES"}}, rows...)
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

// stagesTable is the table of stages for s: a stage's name in the info colour, whom it contacts in
// the success colour for a third party and the warning colour for the target, and its key muted.
func stagesTable(s layout.Stream, rows []stageRow) layout.Table {
	text := func(g palette.Group, entry string) func(string) string {
		return func(x string) string { return s.Depth.Text(g, entry, x) }
	}
	t := layout.Table{
		Indent:   2,
		Bordered: true,
		Columns: []layout.Column{{Header: "STAGE"}, {Header: "CONTACT"}, {Header: "KEY"},
			{Header: "WHAT IT DOES", Wrap: layout.Spaces, Shrink: 1}},
	}
	for _, r := range rows {
		contact := text(palette.Semantic, "success")
		if r.contact == "target" {
			contact = text(palette.Semantic, "warning")
		}
		t.Rows = append(t.Rows, []layout.Cell{
			{{Text: r.name, Style: text(palette.Semantic, "info")}},
			{{Text: r.contact, Style: contact}},
			{{Text: r.key, Style: text(palette.Chrome, "TIMESTAMP")}},
			layout.Plain(r.does),
		})
	}
	return t
}
