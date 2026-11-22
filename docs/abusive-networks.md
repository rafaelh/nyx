# Abusive networks

nyx flags an address whose network, or whose origin AS, [ipapi.is](https://ipapi.is) counts among
the most abusive on the internet. ipapi.is publishes two lists: its
[Most Abusive Networks](https://ipapi.is/most-abusive-networks.html) (about 5,000 IP ranges) and its
[Most Abusive ASNs](https://ipapi.is/most-abusive-asn.html) (about 1,000 ASNs). The data is ipapi.is's,
and nyx credits it as the source. Each entry has a rank, a score tag, an abuse score (the percentage
of the network's addresses seen behaving abusively), the organisation and its type.

**nyx never contacts ipapi.is.** Both lists are embedded in the binary as a snapshot
(`internal/abusive/snapshot.json`), and a check is a lookup in it, so no command sends anything to
ipapi.is and a flag is information only: it never changes the scope, what is contacted, which
addresses are port-checked, or the ranking of candidates.

An address matches a network entry when a listed range holds it, and an ASN entry when its origin AS
is the listed one. A network is written as a CIDR when the range is exactly one, and otherwise as
`start-end`, as `rdap_netblock` is. Only the first origin AS Team Cymru gives is checked. Every
matching entry is reported, the most specific range first (ranges of one size by rank), then the AS.
Organisation names, score tags and types are cleaned of anything that acts on a terminal, as other
third-party text is.

- **`nyx ip`** reports an address's matches in the `abusive_networks` and `abusive_asn` keys (see
  [IP lookup](ip.md)). It is triage context for an address that is often untrusted, such as one
  seen in a log.
- **Recon** checks the addresses of the engagement, which belong to the target, where a high-abuse
  network is worth a look: the host may be compromised, shadow IT or on reallocated space, or at risk
  of being blocklisted. It checks every current address that an in-scope hostname resolves to
  (including a shared CDN or SaaS address and a wildcard-only name's), and every address inside an
  in-scope netblock that a current record other than DNS history names (a PTR answer, a resolution
  or a Shodan result). It never checks a candidate's address, an excluded address, or an address that
  only DNS history names.

Each address checked that has a match is one `abusive-network` finding in `risk-abusive-network.csv`,
with `severity`, `ip`, `hostnames` (its in-scope names), `type`, `networks` and `asn` (each entry as
`<entry> <score tag> <abuse score>% <organisation> (<type>)`, joined with `;`, the rank left out), and
`networks_updated` and `asns_updated` (the date of each list that matched). The finding is **medium**
(`network`) when any network entry holds the address, and **low** (`asn`) when only its AS is listed.
It sends no request, so it is derived under `--passive` too, and it appears wherever other findings of
its severity do: the summary (high and medium), the `--json` findings and `changes.csv`. `nyx help
findings` lists both types with the other finding severities.

The AS of an address outside the in-scope netblocks is the one the `ipowner` stage found. For an
address inside one, the `netblockowner` stage asks Team Cymru's origin service, through the public
resolvers, once for each covering /24 (IPv4) or /48 (IPv6) of the netblock addresses nyx knows, or
once for an in-scope netblock that is smaller: prefixes longer than those are filtered from the global
routing table, so the answer applies to every address in the unit. Team Cymru is a third party, so
this runs under `--passive`, and `--skip netblockowner` turns it off (the network matches are still
found). The AS learned this way is used only for this check: whether an address is shared provider
infrastructure, port-eligible, excluded, an origin candidate or part of an organisation candidate is
decided as before, and its owner in `ips.csv` still reads as an in-scope netblock. An engagement run
before a build that has the check looks up those origins once on its first run; after that a build
with a newer snapshot changes the findings on the next run with no request: an address that drops off
the lists loses its finding (it stays on record, not current), a newly listed address gains one, and
one that stays listed keeps its finding with the detail of the current snapshot, announced again only
if it rises from low to medium. `nyx recon export` shows the findings as of the last run.

**Refreshing the snapshot** is a maintainer's task, done when a build is made, not by a user:
`make abusive-data` fetches the two pages (two requests to ipapi.is, with `curl`), and a parser
(`internal/abusive/refresh`) checks them, prints what was added, removed and changed (a rank that alone
moved is left out), and replaces the snapshot as a whole, or not at all. It refuses a page whose date is
older than the snapshot's or later than tomorrow (UTC), whose rows do not parse or hold control
characters, that lists an entry twice, or that lists fewer than 90% of the entries it says it does.
Review the diff, update the two dates on this page, and commit. A test fails if this page does
not give the snapshot's dates.
