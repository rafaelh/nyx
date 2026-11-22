# Spec: Abusive networks and ASNs

## Goal

When someone triages an address with `nyx ip`, or reviews an engagement's own addresses in
`nyx recon`, they can see whether ipapi.is counts the address's network or AS among the most abusive
on the internet. The two lists are its "Most Abusive Networks" (about 5,000 IP ranges) and its "Most
Abusive ASNs" (about 1,000 ASNs). nyx never contacts ipapi.is to find this out.

- **In `nyx ip`** the flag is triage context for an address that is usually untrusted, such as one
  seen in a log.
- **In recon** the address belongs to the target, and a high-abuse network is worth a look: the host
  may be compromised, shadow IT or on reallocated space, or it may be at risk of being blocklisted.

Success: a listed address shows its entries in `nyx ip` and among recon's findings, and no run sends
anything to ipapi.is.

Maintenance outcome: a maintainer refreshes the snapshot built into nyx from time to time, and users
get it in the next build. ipapi.is gets two requests per refresh instead of one per address.

## Behaviours

### Snapshot and refresh

- **B1 Refresh.** A maintainer command fetches both ipapi.is pages and replaces the built-in
  snapshot: both lists, and each page's "last updated" date. The maintainer reviews the change and
  commits it. No `nyx` command contacts ipapi.is.
- **B2 Refresh fails safely.** The refresh fails, and changes neither list nor date, when any of
  these happens:
  - either page cannot be fetched;
  - a page has no "last updated" date, or its date is older than the current snapshot's or later
    than tomorrow (UTC);
  - a row's rank, network, ASN or score cannot be parsed, or the row contains C0 or C1 control
    characters;
  - an entry appears twice in its list;
  - a page does not state how many entries it lists, or has fewer than 90% of them.

  The two lists are updated together or not at all. (amended by D9, D12)
- **B3 Change summary.** A successful refresh prints the entries that were added, the entries that
  were removed, and the entries whose score tag, abuse score, organisation or type changed. An entry
  whose rank is the only thing that moved is not listed.

### Matching

- **B4 What counts as a match.** An address matches an entry when it falls inside a listed network
  or when its origin AS is a listed ASN. An IPv6 address matches a network entry only when a listed
  IPv6 range contains it.
  - **What a match carries:** the list it came from; the entry; the entry's rank, score tag, abuse
    score, organisation and type; and the "last updated" date of that list.
  - **How the entry is written:** a network is a CIDR when the range is exactly one CIDR, otherwise
    `start-end` (the same rule as `rdap_netblock`). An ASN is an integer, as `asn` is.
  - **Which origin AS:** only the first origin AS that Team Cymru gives is checked.
  - **Order:** every matching entry is reported, in a fixed order: network matches first, the most
    specific range first and ties by rank, then the ASN match.
- **B5 Sanitised.** Organisation names, tags and types from the snapshot are sanitised in every
  output, as other third-party text is.
- **B6 Information only.** A match never changes scope, what is contacted, port eligibility,
  `nyx ip --active`'s `not_contacted`, or the candidate ranking.

### nyx ip

- **B7 Record.** A public address's record has its network matches (a list) and its ASN match (a
  list of zero or one entries). The new keys come after `reverse_ip_count` and before the `--active`
  keys.
  - **Network matches:** `[]` when nothing matches. They need no request beyond resolving a hostname
    input. The built-in snapshot counts as a source that always answers. So an address whose only
    failed source is Team Cymru still has a record, with its network matches and a `null` ASN match,
    and the call exits 7.
  - **ASN match:** `[]` when the AS is known and not listed, and also when Team Cymru found no owner.
    It is `null` when Team Cymru failed. That failure appears in `failures` and makes the call exit
    7, as it already does for `asn`.
  - **Non-public address:** both keys are `null`.
  - **`--fields`:** each key can be picked on its own, and picking the ASN match asks Team Cymru.
    `failures` stays the last key (existing behaviour, kept).
- **B8 Stable types.** In the JSON record:
  - rank is an integer;
  - abuse score is a number (the percentage);
  - score tag, organisation and type are strings;
  - the list's date is `YYYY-MM-DD`.
- **B9 Human layout.** Without `--json`, each match shows its entry, score tag, abuse score,
  organisation, type and date. When nothing matches the key reads `none`, and an ASN match whose
  Team Cymru lookup failed reads `unknown`, as other keys do.

### Recon

- **B10 Which addresses.** Recon checks these addresses:
  - every current address that a current in-scope hostname resolves to, including shared CDN and
    SaaS addresses;
  - every address inside an in-scope netblock that a current record other than DNS history names,
    such as a PTR answer, a resolution or a Shodan result.

  It never flags candidate addresses, excluded addresses, or addresses that only DNS history names,
  inside an in-scope netblock or not.
- **B11 AS of netblock addresses.** Recon also learns the origin AS of the addresses inside in-scope
  netblocks, from Team Cymru. Team Cymru is a third party, so this also runs under `--passive`. The
  ASN match then applies to every address that is checked. Recon asks once per covering /24 (IPv4)
  or /48 (IPv6), or once per in-scope netblock when the netblock is smaller, and the answer applies
  to every address inside it. (amended by D6)

  The AS learned this way is used only for the abuse check. Nothing else about such an address
  changes: whether it is shared provider infrastructure, port-eligible, excluded, an origin
  candidate or part of an organisation candidate is decided exactly as before, and its owner in
  `ips.csv` still reads as an in-scope netblock.
- **B12 Finding.** Each checked address with at least one match gets one finding.
  - **Severity:** medium when any network entry matches, and low when the only match is the ASN.
  - **Content:** every matching entry with its score tag, abuse score, organisation, type and list
    date. Rank is left out.
  - **Where it appears:** in its own risk file, one row per address with its in-scope hostnames,
    every matching entry and the list dates, and wherever other findings of its severity appear (the
    summary, the `--json` findings and the changes report).
  - **Requests:** the check itself sends none.
- **B13 Recon and nyx ip agree.** For the same address, origin AS and build, recon's finding names
  exactly the entries `nyx ip` reports, except the ASN match when recon does not know the address's
  AS. For an address inside an in-scope netblock, recon's origin AS is the one Team Cymru gives for
  its covering /24, /48 or smaller netblock (B11). In the rare case where that differs from the
  address's own origin, the ASN match can differ too. (amended by D6)
- **B14 Refresh reaches old engagements.**
  - **First run under this build:** the first run of an existing engagement looks up, once, the
    origin AS of its netblock addresses (B11).
  - **After a refresh:** once the engagement has been run under a build with this check, a rebuild
    with a new snapshot changes its findings on the next run without any request.
  - **An address that drops off the lists** loses its finding, which stays on record marked not
    current.
  - **A newly listed address** gains a finding.
  - **An address that stays listed** keeps one finding whose detail follows the current snapshot, and
    is not reported as new. When a refresh raises that finding from low to medium, it is announced as
    a risen finding, as other findings are. The changes report does not list it, because the finding
    stayed shown.
  - **Export:** `nyx recon export` shows the findings as of the last run (existing behaviour, kept).

### Docs

- **B15 Docs.** The README and help cover these:
  - the finding, in `nyx help findings` and the README's severity table;
  - its risk file, in the README's output table;
  - the new keys, in the IP lookup key table and among the `--fields` names in `nyx ip --help`;
  - the AS lookup for in-scope netblock addresses, in `nyx help stages` and the README's stage text;
  - in the Passive boundary section, that no command contacts ipapi.is and that Team Cymru now
    receives in-scope netblock addresses.

  The README names ipapi.is as the source and credits it, gives both lists' dates, and explains how
  to refresh the snapshot.

## Out of scope

- Any runtime fetch of the lists by nyx, or a refresh run by a user.
- A warning that the snapshot is old. This is deliberate and differs from the end-of-life data, which
  does warn.
- A column on the IPs CSV. In recon the flag is a finding only.
- Flagging only some score tags. Every listed entry flags.
- Limiting recon's check to dedicated or port-eligible addresses. Shared CDN and SaaS addresses are
  checked too.
- A finding about a netblock as a whole. Findings are per address.
- A release gate for ipapi.is's permission. It is a follow-up instead.

# Design

## External facts

- *Confirmed live (2026-11-22).* `https://ipapi.is/most-abusive-networks.html` answers 200 with no
  key and no cookie. Its table (`id="abusiveNetworksTable"`) has the headers Rank, Network, Num
  Hosts, Score Tag, Abuse Score, Organization, Type, and 5,000 `<tbody>` rows of 7 `<td>` each.
  - The network cell is `<a ...>34.68.34.64 - 34.68.34.95</a>`: start, " - ", end.
  - The abuse score is the text `100%` or `10.16%`, with `data-order="100"` on the cell.
  - The score tag is a `<span class="tag ...">`, `High` or `Very High` today. Types today are
    business, hosting, isp, government, education and banking.
  - The organisation is a link, or plain text (508 rows). The text holds raw `&` and non-ASCII
    characters, and there are no HTML entities today.
  - Today there are no IPv6 ranges and no duplicates. 103 ranges are not a single CIDR, and 13
    ranges sit inside other listed ranges.
- *Confirmed live.* `https://ipapi.is/most-abusive-asn.html` has the same layout with no table
  `id`. Its headers are Rank, ASN (cell text `as64050`), Num IPs and Routes, Score Tag (Very High,
  Elevated, High), Abuse Score, Organization and Org Type (which includes `Spamhaus ASN-DROP` and
  `unknown`). It has 1,000 rows.
- *Confirmed live.* Both pages say `Data last updated on <strong>November 21, 2026</strong>` and
  state their size as `lists the <strong>5,000</strong>` and `lists the <strong>1,000</strong>`.
- *Confirmed live.* Neither page states a licence or terms of use (see Follow-ups).
- *Assumed.* ipapi.is dates its pages in a European time zone. That's why D9 allows one day after
  UTC today.
- *From docs (routing practice), assumed for nyx's purposes.* Prefixes longer than /24 (IPv4) and
  /48 (IPv6) are generally filtered from the global routing table. So Team Cymru's origin for one
  address of a /24 or /48 is almost always the origin of every address in it (D6).
- *Confirmed in code.* Team Cymru's origin answer is a TXT record, `ASN[ ASN...] | prefix | CC |
  registry | date`. `ipsource.Origin` takes the first AS. An NXDOMAIN, an AS0 or an unreadable
  answer means no owner, and anything else that isn't success is an error
  (`internal/ipsource/cymru.go`).

## Decisions

- **D1 Refresh is curl plus a Go parser that does no I/O (user).** `make abusive-data` runs in one
  recipe shell with `set -e`:
  1. It creates a `mktemp -d` directory, with `trap 'rm -rf "$$d"' EXIT`.
  2. It runs `curl -fsS --retry 3 -o` once for each page into that directory.
  3. It runs `go run ./internal/abusive/refresh -networks <file> -asns <file> -snapshot
     internal/abusive/snapshot.json`.

  The Go program reads the two files and the current snapshot. It parses, validates (B2), prints
  the change summary (B3), and writes the new snapshot to a temp file in the same directory before
  renaming it into place. Both lists live in that one file, so they change together or not at all.
  The summary ends with a reminder to update the README's two dates. A fetch failure stops `make`
  before the Go program runs.
  - Why: the boundary test (`internal/egress/boundary_test.go`) bans `net/http` in every package
    under `internal/` and `cmd/` outside egress, and `make eol-data` already fetches with curl. A
    shell pipeline can't do B2's checks or B3's summary.
- **D2 Snapshot format.** The snapshot is one embedded JSON file, `internal/abusive/snapshot.json`:
  `{"networks": {"updated": "YYYY-MM-DD", "entries": [...]}, "asns": {"updated": ..., "entries":
  [...]}}`.
  - A network entry is `{"rank", "start", "end", "score_tag", "abuse_score", "org", "org_type"}`.
    An ASN entry has `"asn"` (an integer) in place of `start` and `end`. `abuse_score` is a JSON
    number (`10.16`).
  - Network entries are sorted by start, then end. ASN entries are sorted by ASN. The writer puts
    one entry per line (each one `json.Marshal`ed), so a refresh diffs as the entries that changed,
    and a rank-only move is one changed line.
- **D3 `internal/abusive` is a pure knowledge package (no I/O).**
  - It has a `Snapshot` type and `Default()`, which parses the embedded file once and panics on a
    bad embed, as `provider.Default` does.
  - `Validate(Snapshot) error` rejects unsorted entries, duplicates, a range whose ends are invalid,
    of different families or out of order, an ASN outside 1..4294967295, a rank below 1, an abuse
    score outside 0..100, a bad date, and C0/C1 characters. The refresh calls it before writing,
    and a unit test runs it on the embedded file (critic M4).
  - When an entry is loaded, its network text is formatted once with `input.RangeText`, and its
    organisation, score tag and type go through `sanitize.Line`. That makes every output (JSON, CSV,
    console) sanitised (B5).
  - `(*Snapshot).Networks(addr netip.Addr) []NetworkMatch` unmaps the address, as nyx does
    everywhere, and scans linearly: about 5,000 comparisons per address is cheap enough even with
    the findings re-derived often. Matches are ordered by the smallest range first, then by rank. An
    IPv4 range can never contain an IPv6 address, so an IPv6 address matches only IPv6 ranges.
  - `(*Snapshot).ASN(n int) []ASNMatch` returns zero or one match, and `Dates()` returns both lists'
    dates. Each match carries the list date.
- **D4 `input.RangeText(start, end netip.Addr) string`.** It returns the CIDR when the range is
  exactly one, `start-end` otherwise, and `""` for an invalid range. `iplookup.Netblock`
  (`internal/iplookup/record.go:181`) and `inventory.rangeText` (`internal/inventory/inventory.go:632`)
  call it. `inventory.rangeText` keeps its current `start-end` result for an invalid range by
  handling that case itself. Land this as its own `refactor:` commit first.
- **D5 Test injection.** `cli.Deps.Abusive *abusive.Snapshot` (nil means `abusive.Default()`) is
  passed into `iplookup`'s config and into the runner, which puts it in `findings.Input.Abusive`.
  Test addresses are not on the real lists, and B14 needs a different snapshot on a later run.
- **D6 Recon learns netblock origins per /24 or /48, in a new stage and kind (user, on critic
  H1).**
  - It is a new `Contact: ThirdParty` stage, `netblockowner`, in `internal/stages/dns` (on the dns
    `base`, so it uses the public resolvers and declares no source host). It comes right after
    `ipowner` in `defaultStages()`, and it can be skipped.
  - Its checks: for each current `ip` record inside an in-scope netblock (`v.IPs(sc.InScopeIP)`),
    the unit is the covering /24 (IPv4) or /48 (IPv6). When the in-scope netblock holding the
    address is smaller than that, the netblock is the unit. There is one check per distinct unit,
    keyed by the unit's prefix text (such as `203.0.113.0/24`).
  - `Run` asks `ipsource.Origin` about the unit's first address. It writes
    `kinds.NetblockOwner.Obs(prefix, NetblockOwnerAttrs{ASN, Prefix})`, where `Prefix` is the
    announced prefix Team Cymru gives. No owner means a completed check with no observation, and an
    error is transient.
  - The new kind `netblock_owner` is not in `scopeKinds` (`internal/run/scopebuild.go`), so
    provider classification, `ips.csv`'s owner, port eligibility and both kinds of candidate can't
    see it (B6, B11). The findings deriver reads every non-derived kind, so it does see it.
  - History-only addresses are not filtered out of these checks (critic M1). B11 limits what the AS
    is used for, not what is asked, and `ipowner` already asks about history-only addresses.
  - Rejected: one check per address, which on a dense /16 means tens of thousands of new lookups on
    the first run, `--passive` included. Also rejected: widening `ipowner`'s filter with a guard in
    `ipOwners`, which is a subtle rule guarding B11. And rejected: having `ipowner` write a second
    kind under the same check key, which leaves an address with no `ip_owner` after it leaves the
    netblock.
- **D7 History-only addresses.** A new marker interface in `internal/run/stage.go`, `Historical`
  (method `HistoricalAddresses()`), is implemented by `dnshistory`. An `ip` record is history-only
  when every stage in its `store.Record.Stages` is historical. The runner builds
  `findings.Input.HistoryOnly func(netip.Addr) bool` from the current `ip` records and the stages'
  markers, so code outside a stage never names one.
- **D8 nyx ip (user: names and shape).**
  - Two keys, `abusive_networks` and `abusive_asn`, go between `reverse_ip_count` and
    `not_contacted` in `Record` and in the field table (`internal/iplookup/fields.go`).
  - A network match is `{"network": "34.68.34.64/27", "rank": 1, "score_tag": "Very High",
    "abuse_score": 100, "org": "Mandiant, Inc.", "org_type": "business", "updated": "2026-11-21"}`.
    An ASN match has `"asn": 64050` (an integer) in place of `network`.
  - In the field table, `abusive_networks` has no sources and `abusive_asn` has `{cymru}`. The help
    text and `--fields` names come from the table.
  - **Public address:** when `abusive_networks` is selected it is always set (non-nil). After the
    sources finish (after `wg.Wait()`, critic M3), `abusive_asn` is set to `ASN(*rec.ASN)` when the
    ASN is known, to `[]` when Team Cymru answered with no owner, and stays nil when the origin
    lookup failed. When the origin lookup succeeds but the AS-name lookup fails, `abusive_asn` is
    set and `cymru` is in `failures`, as `asn` behaves today.
  - **Answered:** `AddressResult` gains an `Answered` flag, set when a selected field with no
    sources has a value. `judge` (`internal/iplookup/outcome.go`) counts it as a source that
    answered, so an address whose only failed source is Team Cymru keeps its record and the call
    exits 7.
  - **Non-public address:** both keys are nil (`null`). This departs from the other list keys, so
    the doc comment at `record.go:117-120` changes (critic M5).
  - **Human layout:** two sections come after Reverse IP, "Abusive networks" and "Abusive ASN",
    each built with `b.items`. A line reads `34.68.34.64/27: Very High, 100%, Mandiant, Inc.
    (business), updated 2026-11-21`, or `AS64050: ...` for the ASN. An empty list reads `none`, and
    a nil `abusive_asn` reads `unknown` when Team Cymru failed, through `empty(key)`.
- **D9 Date check (user).** A refresh fails when a page's date is older than the current
  snapshot's date for that list, or later than tomorrow (UTC), which allows for ipapi.is's own time
  zone. B2 is amended. The date is parsed with the layout `January 2, 2006`.
- **D10 README dates (user).** A test in `internal/cli`, modelled on the end-of-life one
  (`internal/cli/eol_test.go:298`), checks that README.md contains both snapshot dates in
  `YYYY-MM-DD` form, `ipapi.is` and `make abusive-data`. The refresh never edits the README.
- **D11 No change to the derive signature.** Each deriver's `sig` and `stored` live only in memory
  (`internal/run/derive.go:48-49`), so every run derives again once, and a rebuilt snapshot takes
  effect on the next run (B14).
- **D12 Parsing the pages.**
  - The parser uses `golang.org/x/net/html`, which decodes entities. It finds the `<table>` whose
    `<th>` texts include the needed headers, and maps the columns by header text: Rank, Network or
    ASN, Score Tag, Abuse Score, Organization, and Type or Org Type. A missing header fails the
    refresh.
  - Cell text is trimmed. Any C0 or C1 character left in any cell of the row then fails the
    refresh.
  - Each field must parse:
    - rank: a positive integer (user: added to B2);
    - network: `start - end`, one family, start ≤ end;
    - ASN: `as<n>`, n in 1..4294967295;
    - abuse score: `<number>%`, 0..100;
    - score tag: not empty.
  - The stated size is read from the text `lists the <N> most abusive` (commas allowed). The refresh
    fails when that text is missing or the rows number fewer than 90% of N. A duplicate entry (the
    same start and end, or the same ASN) fails it too.
  - The change summary matches entries by network or ASN. For each list it prints the added
    entries, the removed entries, and the changed ones with `field: old -> new` for score tag, abuse
    score, organisation and type. An entry whose rank alone moved is not printed. When nothing
    changed it prints "no entries changed".
- **D13 The finding (user: names).**
  - The category is `abusive-network`, with type `network` (medium) or `asn` (low, when only the
    ASN matches). Its key is `abusive-network|<ip>`, with a custom key and parse as takeover has,
    so the finding keeps its record when its type and severity change, and the existing risen hook
    announces low → medium. The changes report is unaffected.
  - Checked addresses:
    - (a) every address in `inv.Addrs()` of a current in-scope hostname, wildcard-only names
      included, as B10 says (critic M2);
    - (b) every address inside an in-scope netblock of a current `ip` record that is not
      `HistoryOnly`;
    - minus those `sc.ExcludedFor(a, inv.Shared(a))` refuses.

    Candidates can't get in: an address outside the netblocks qualifies only through an in-scope
    hostname.
  - The AS is the `netblock_owner` of the address's unit (D6) when the address is inside an
    in-scope netblock, and the `ip_owner` AS otherwise. With neither, only network entries are
    checked.
  - `risk-abusive-network.csv` has the columns `severity, ip, hostnames, type, networks, asn,
    networks_updated, asns_updated`.
    - `hostnames` holds the in-scope names from `HostnamesByIP` and `inv.Addrs()`.
    - `networks` is a list of `<entry> <score tag> <abuse score>% <org> (<type>)` texts.
    - `asn` is the same for `AS<n>`.
    - The two `*_updated` columns hold the date of each list that matched.

    These are stored as finding attrs (`ip`, `hostnames`, `networks`, `asn`, `networks_updated`,
    `asns_updated`). Those names are then stable, and `fromKey` gives `ip`.
  - The detail lists every matching entry with its tag, score, organisation, type and list date,
    and leaves rank out.
  - The found line reads `address <ip> in abusive network <first entry> (<org>)` or `address <ip>
    in abusive AS<n> (<org>)`.
  - Two rows are added to the severity table in `internal/findings/table.go`, which feeds `nyx help
    findings`.

## Files

- `internal/input/input.go`: `RangeText`. `internal/iplookup/record.go` and
  `internal/inventory/inventory.go` call it (D4).
- `internal/abusive/abusive.go` (package doc defines *abusive network list*, *entry* and *match*),
  `snapshot.json`, `abusive_test.go`.
- `internal/abusive/refresh/` (package main): `main.go` (flags, `os`, the clock) and `refresh.go`
  (pure parse, validate, diff, write), with `refresh_test.go` and `testdata/` pages that include an
  IPv6 row.
- `Makefile`: the `abusive-data` target and `.PHONY`.
- `internal/kinds/table.go`: `NetblockOwner` and `NetblockOwnerAttrs`.
- `internal/stages/dns/netblockowner.go` and its test.
- `internal/stages/dnshistory/dnshistory.go`: the `Historical` marker.
- `internal/run`:
  - `stage.go`: the `Historical` interface;
  - the runner and `derive.go`: `HistoryOnly` and `Abusive` passed into `findings.Input`;
  - the runner config: `Abusive`.
- `internal/findings`:
  - `table.go`: the category constant and two severity rows;
  - `records.go`: the category entry, with key, parse, found, columns and fromKey;
  - `abusive.go`: the derivation;
  - `findings.go`: the `Input` fields and the call in `findings()`.
- `internal/iplookup`: `record.go`, `fields.go`, `sources.go`, `outcome.go`, `render.go`, `doc.go`.
- `internal/cli`:
  - `cli.go`: the registry and `Deps.Abusive`;
  - `stages_topic.go`: the `netblockowner` entry, plus `ipowner`'s text if needed;
  - `ip.go`: the snapshot passed to the lookup;
  - the help annotations if needed.
- `README.md`:
  - the severity table and `nyx help findings` text;
  - the output table (`risk-abusive-network.csv`);
  - the IP lookup key table;
  - the stage text (`netblockowner`);
  - Passive boundary: no command contacts ipapi.is, and Team Cymru gets one query per /24 or /48 of
    known in-scope netblock addresses;
  - a new "Abusive networks" section: the source and credit, both dates, and `make abusive-data`.
- `CLAUDE.md`: `make abusive-data` in Commands, and `abusive` among the pure knowledge packages.

## Tests

Fakes: Team Cymru through the harness's fake DNS server (`egresstest`), and injected snapshots
through `Deps.Abusive`. The harness canaries catch any unexpected request. **M** marks a behaviour
for a mutation check in `/spec-develop`.

- **B1** (**M**, passive boundary):
  - Refresh tests on testdata pages write the expected snapshot.
  - A Makefile test checks that `abusive-data:` uses curl and `go run ./internal/abusive/refresh`.
  - A test checks that no registered stage's `Sources()` names `ipapi.is`, and no egress source
    default names it.
  - The harness canaries see no request to it in any recon or ip test.
- **B2** (**M**, data integrity): table tests over each failure case, and after each one the
  snapshot file is byte-identical:
  - a missing date; a date older than the current one; a date the day after tomorrow (tomorrow
    passes);
  - a bad rank, network, ASN or score; an IPv4/IPv6 family mismatch; start > end; AS0;
  - a cell with a C0 character and one with a C1 character, entity-encoded too;
  - a duplicate network and a duplicate ASN;
  - no stated count; 89% of the stated rows (90% passes);
  - a missing header;
  - one page good and the other bad, which leaves both lists unchanged.

  An unreadable input file fails as a fetch failure would (curl's own failure stops `make`, which
  the Makefile test covers). Re-running after a failure, with good pages, succeeds. `Validate`
  passes on the embedded snapshot.
- **B3:** the summary lists additions, removals and changes of each of the four fields, leaves out
  rank-only moves, and prints "no entries changed" for identical pages. Running the refresh twice
  on the same pages gives the same file and "no entries changed" the second time.
- **B4:**
  - Unit tests: inside, outside and at the edges of a range; nested ranges come smallest first,
    and ties by rank; a CIDR-shaped range against a `start-end` one, checked against
    `iplookup.Netblock`'s output; an IPv6 address against an IPv4-only list (no match) and against
    an IPv6 range (a match); an ASN hit and miss; the list date on each match.
  - `nyx ip` uses the first origin AS of a multi-origin TXT answer.
- **B5:** a snapshot entry with an escape sequence or bidi override comes out sanitised in `nyx
  ip` JSON and human output, and in `risk-abusive-network.csv`.
- **B6** (**M**, scope): for a listed address, these are all unchanged against a run with an
  empty snapshot:
  - recon's `ips.csv` owner and provider columns, and port eligibility;
  - the egress Policy (no new address contacted);
  - `candidate_rank`;
  - `nyx ip --active`'s `not_contacted`.

  A `netblock_owner` record whose AS is in `providers.yaml`'s asns map doesn't make the address
  shared.
- **B7:**
  - The keys come in order, between `reverse_ip_count` and `not_contacted`. Each value can be
    `[]`, a match or `null`, by case.
  - Team Cymru fails (SERVFAIL, timeout) and `abusive_networks` is alone: the record is kept,
    `abusive_asn` is `null`, `cymru` is in `failures`, and the exit is 7.
  - Team Cymru returns NXDOMAIN: `abusive_asn` is `[]`.
  - The AS-name lookup fails after the origin succeeded: `abusive_asn` is set, `cymru` is in
    `failures`, and the exit is 7.
  - A non-public address has both keys `null`.
  - `--fields abusive_networks` with an address input makes zero requests, and with a hostname
    input only the resolution. `--fields abusive_asn` asks Team Cymru. `failures` stays last.
  - In a batch, one address's Team Cymru failure leaves the other addresses' records complete, and
    the partial outcome is reported.
- **B8:** in the JSON, rank, `asn` and `abuse_score` are numbers, the other fields are strings, and
  `updated` is `YYYY-MM-DD`.
- **B9:** human output for a match, `none`, `unknown` (Team Cymru failed), and a non-public
  address. Plain and terminal renderers.
- **B10** (**M**, what is flagged):
  - Flagged: a resolution address of an in-scope hostname, including a CDN or shared address and
    a wildcard-only name's address; a netblock address that only a PTR names; one that only a
    Shodan record names.
  - Not flagged: an address excluded by CIDR; an address of an excluded host that isn't shared; a
    candidate hostname's address outside the netblocks; a netblock address that only DNS history
    names. A netblock address named by both DNS history and a PTR is flagged.
- **B11:**
  - Under `--passive`, netblock addresses in one /24 cause one Team Cymru query, and two /24s
    cause two.
  - A /28 in-scope netblock is queried as the /28.
  - An IPv6 netblock address is queried per /48.
  - NXDOMAIN completes the check with no ASN match.
  - A SERVFAIL leaves the check to be retried on the next run, and the network matches still
    come out.
  - `ips.csv` still shows "in-scope netblock" as the owner.
- **B12:** severity is medium for a network match, medium for network plus ASN, and low for the
  ASN only. Also covered:
  - the risk file's columns and a row with every matching entry and its dates;
  - the finding in the summary, the `--json` findings and `changes.csv` (new on the first run);
  - the found line;
  - the derivation sends no request (a canary).
- **B13:** for the same address, AS and snapshot, recon's finding entries equal `nyx ip`'s
  `abusive_networks` and `abusive_asn` entries.
- **B14** (**M**, findings history):
  - Run 1 with snapshot A (this covers the first run of an engagement made before this build: its
    `netblockowner` checks run, each unit once). Run 2 with snapshot B and no new requests (a
    canary and the Cymru query count). Between the runs:
    - a dropped address's finding is not current;
    - a new address's finding is found and announced;
    - a kept address's detail follows B and the finding is not new;
    - a low → medium change is announced as risen and is not in `changes.csv`.
  - An interrupted run 1 (a check failing part-way) resumes and runs only the checks that are
    left.
  - `nyx recon export` after run 2 shows run 2's findings.
- **B15:** the README test (D10). `nyx help findings` lists both types. `nyx help stages` lists
  `netblockowner`. `nyx ip --help` lists both field names.

## Conventions

- `CLAUDE.md`:
  - the hard invariants (the egress boundary and the passive boundary);
  - stage rules (`Contact`, check keys, negative results as completed checks);
  - derived on read;
  - stable interfaces (the `nyx ip` keys and the finding attr names);
  - Australian English, with `organisation` in prose (the JSON key is `org`).
- `docs/specs/done/2026-11-spec-eol-software-14.md`: the precedent for embedded third-party data
  with a Makefile refresh and a README date test.

# Implementation

## Develop

Built in four groups, each with its tests: the snapshot package and refresh tool, the `netblockowner`
stage, the finding, and the `nyx ip` keys, then the docs.

- **Snapshot (B4, B5, B8).** `internal/abusive` holds `Snapshot` (the file's data: `Nets` and `ASNs`,
  named so that `Networks` and `ASN` can be its methods), `Load` (builds the sanitised, formatted index
  once; a snapshot not made by `Load` still matches, building it per call), `Default`, `Parse`,
  `Marshal`, `Validate`, `NetworkMatch`, `ASNMatch` and `Dates`. Matches are the most specific range
  first (range size as a `big.Int`, so IPv6 compares too), ties by rank. Tested in `abusive_test.go`.
- **Refresh (B1 to B3).** `internal/abusive/refresh` (`refresh.go`, `main.go`) parses with
  `golang.org/x/net/html`, checks every B2 case, writes through a temp file and a rename, and prints
  the summary. `make abusive-data` is D1's recipe. Tested in `refresh_test.go` against
  `testdata/networks.html` and `asns.html` (markup copied from the live pages, plus an IPv6 row, an
  entity, a plain-text organisation, a nested range and a non-CIDR range), with a table of every B2
  failure that also checks the snapshot file is byte-identical and no temp file is left. I ran
  `make abusive-data` for real, so `snapshot.json` holds the 2026-11-21 lists (5,000 networks, 1,000
  ASNs, no IPv6 range today) and a second run says "no entries changed".
- **Stage and kind (B11, D6, D7).** `kinds.NetblockOwner`, `dns.NetblockOwner` (`netblockowner`, after
  `ipowner`), `run.Historical` (implemented by `dnshistory`) and `Runner.historyOnly`. The /24, /48 or
  smaller-netblock rule is `scope.Scope.OwnerUnit`, so the stage and the finding cannot disagree; the
  spec's file list did not have it.
- **Finding (B10, B12, D13).** `findings/abusive.go` and the `abusive-network` category. It stores
  two attrs beyond the spec's list, `entry` and `org`, which the found line reads (parsing them out of
  the `networks` text would be ambiguous: a score tag can hold a space).
- **nyx ip (B7 to B9, D8).** The two table rows, `Record` fields, `Config.Abusive`, `state.abusive`,
  `AddressResult.Answered` and the two render sections.
- **Plumbing (D5).** `cli.Deps.Abusive` and `run.Config.Abusive`; nil means `abusive.Default()`.
  `findings.Input.Abusive` nil derives nothing, so the findings package's older tests are unchanged.
- **Docs (B15).** A new README section "Abusive networks", the output table, the Passive boundary text,
  the IP lookup key and source tables and the outcome paragraph; `nyx help findings` and `nyx help
  stages` come from the tables; `CLAUDE.md` has the command and the package.

How each behaviour is tested (the list is in `## Tests`; all but the first two groups run in
`internal/cli`):

- B1: refresh tests; `TestAbusiveDocs_MakefileTarget`; `TestAbusiveDocs_NoCommandContactsIpapi`; the
  harness canaries in every recon and ip test.
- B2, B3: `TestRefresh_FailsSafely` (42 cases), `_TheSizeCheckIsNinetyPercent`, `_DateWindow`,
  `_UnreadableInput`, `_Idempotent`, `_Summary`, `_SummaryNamesTheDates`.
- B4, B5: `abusive_test.go`; `TestIPAbusive_OnlyTheFirstOriginASIsChecked`,
  `_SnapshotTextIsSanitised`; `TestAbusiveRecon_SnapshotTextIsSanitised`.
- B6: `TestAbusiveRecon_InformationOnly` (the unit's AS is Cloudflare's; `ips.csv`, hostnames,
  netblocks and `candidate_rank` equal a run with the stage skipped) and
  `TestIPAbusive_ActiveIsNotChangedByAMatch`.
- B7 to B9: the `TestIPAbusive_*` tests and the `iplookup` unit tests (fields, render, outcome).
- B10 to B12: `TestAbusive_WhichAddressesAreChecked` (findings unit),
  `TestAbusiveRecon_WhichAddressesAreFlagged`, `_OriginIsAskedOncePerUnit`, `_OriginFailuresAndRetries`
  and the findings unit tests for severity, content and the risk file.
- B13: `TestAbusive_ReconAndIPAgree`.
- B14: `TestAbusiveRecon_ARebuiltSnapshotReachesAnOldEngagement` (run 1 with snapshot A, run 2 with B and
  zero new DNS queries; drop, new, kept, low to medium, `changes.csv`, export) and
  `_OriginFailuresAndRetries` for the resume.
- B15: `TestAbusiveDocs_ReadmeGivesTheSnapshotDates` and `_Help`.

Deviations from the plan:

- `snapshot.json` marshals without HTML escaping (D2 said `json.Marshal`), so `&` in an organisation
  reads as written in the diff.
- D8's "answered" rule has a visible consequence for the existing behaviour: while `abusive_networks` is
  selected (it is by default), an address whose every source failed now has a record and the call is
  partial (exit 7) instead of a failed input (exit 1). `TestIPOutcome_NoSourceAnsweringIs...` now names
  fields without the abusive keys; `TestIPAbusive_EverySourceFailingStillHasARecord` pins the new
  default, and the README's outcome paragraph says so.
- B15 says "the README's severity table", but the README has none: severities are in `nyx help
  findings`, and the README's new section gives the two types.
- The recon integration tests (`abusive_recon_test.go`) were written after the code they test, so they
  passed on their first run; the mutation checks below show they can fail.
  Everything else was written first and watched failing on assertions (the packages `abusive`, `refresh`,
  `findings`, `iplookup`, the stage's `Run`), except `scope.OwnerUnit`, which I wrote together with its
  test and checked by breaking the /24 width by hand.
- The refactor of D4 is not its own commit: nothing is committed.

External facts that differed: the header cell of "Abuse Score" holds a newline and spaces in the markup,
so headers are compared with their whitespace collapsed. A numeric character reference from 0x80 to 0x9f
is decoded by the HTML parser through Windows-1252 (`&#x85;` is an ellipsis), so only the unmapped ones
(0x81, 0x8d, 0x8f, 0x90, 0x9d) and a raw C1 character reach the control-character check.

Mutation checks (the behaviours `## Tests` marks **M**). Each was broken by hand, the tests run, and the
edit undone by hand; "killed" means a test failed on an assertion, not on a build error.

- **B1.** Adding `ipapi.is` to `nyx ip`'s source hosts: killed by `TestAbusiveDocs_NoCommandContactsIpapi`.
  Dropping `-f` from one `curl` in the Makefile target **survived** the first version of
  `TestAbusiveDocs_MakefileTarget`, which now counts both calls; killed after that.
- **B2.** Accepting an older date, an 80% size check, ignoring a bad ASN page, a missing stated count,
  an unsorted or repeated ASN in `Validate` and control characters in a cell: all killed by
  `TestRefresh_*` and `TestValidate`. Skipping the refresh's per-cell control check **survived** at first,
  because `Validate` also rejects control characters in the fields the file keeps; the new case "a
  control character in a cell the snapshot does not keep" kills it.
- **B6.** Making `--active` skip an address that matches: killed by `TestIPAbusive_ActiveIsNotChangedByAMatch`
  (which first **survived**: its `--fields` left the abusive keys out, so no match was ever made; it
  selects them now). Letting `netblock_owner` records into the scope build's owners (and `scopeKinds`):
  killed by `TestAbusiveRecon_InformationOnly` (`ips.csv` shows the unit's AS 13335 as the provider).
  The first version of that mutation did not add the kind to `scopeKinds`, so the scope build never ran
  again and the test passed: a second line of defence, not a gap.
- **B10.** Flagging history-only addresses (findings and recon), flagging an excluded address inside an
  in-scope netblock (**survived** until `TestAbusive_WhichAddressesAreChecked` gained `198.51.100.70`),
  flagging a candidate's address, skipping shared addresses, ignoring PTR and Shodan `ip` records, the
  runner never naming history-only addresses, and `dnshistory` losing its `Historical` marker (**survived**
  until `TestStageIsHistorical` was added): all killed.
- **B14.** Putting the type in the finding key, and ignoring the injected snapshot: killed by
  `TestAbusiveRecon_ARebuiltSnapshotReachesAnOldEngagement` (and the findings tests for the key).
- **Other.** `Answered` always false, an ASN match after a failed origin, matches on a non-public
  address, a swallowed origin failure, and one check for each address instead of each unit: killed by
  `TestIPAbusive_*` and `TestAbusiveRecon_*`.

## Known limitations

- **B2.** An entity-encoded C1 character that Windows-1252 maps (0x80 to 0x9f except the five above)
  is not rejected, because the parser has already turned it into ordinary text. A newline or tab inside
  a cell (not at its ends) is rejected as a control character: the live pages have none, and a layout
  change makes the refresh fail safe rather than write.
- **B3.** The first refresh, with no snapshot, lists every entry as added.
- **B11.** The refresh and the stage trust that ipapi.is's two dates and Team Cymru's /24 or /48
  answer apply to the whole unit, as the spec assumes. Not checked against a real prefix longer than
  that.
- **B14.** "An engagement made before this build" is tested as a first run of the stage on an
  engagement with no `netblock_owner` records; no older database is used.
- **Release.** `snapshot.json` and the README dates are in the working tree, not committed. The
  refresh summary reminds the maintainer to update the README dates, and a test fails if they are stale.

## Simplify

Four reviewers looked at the change for reuse, simplification, efficiency and altitude. Where they
differ from the `## Develop` notes above, these notes are the current state.

Fixed:

- **`abusive`.**
  - A snapshot is matched only through `Load` or `Default`. The fallback that rebuilt the index on
    every call is gone.
  - `Dates` and the `Dates()` method are gone. Their only callers were tests, which now read
    `Nets.Updated` and `ASNs.Updated`.
  - A range's size is two `uint64`s, not a `*big.Int`, which saves an allocation per entry on every load.
  - `Networks` returns `[]` when nothing matches, as `ASN` does, so `iplookup` no longer turns nil
    into `[]`.
  - `Marshal` writes each list with a generic helper instead of index closures.
  - `HasControl` uses `unicode.IsControl`.
  - New exported helpers: `CompareNetworks` (the file's order) and `ScoreText`. `ScoreText` replaces
    three copies of the score formatting, in findings, the `nyx ip` render and the refresh summary.
- **Refresh.**
  - It sorts with `abusive.CompareNetworks`. Its own "listed twice" loops are gone, because
    `abusive.Validate`, which runs right after, already rejects a repeat.
  - The test case "the good page and a bad one" was a copy of "AS0" and is gone, so
    `TestRefresh_FailsSafely` has 41 cases.
- **`iplookup`.**
  - `Netblock` was an alias of `input.RangeText`. It and `TestNetblock`, which repeated
    `TestRangeText`, are gone.
  - The snapshot is read only when `abusive_networks` or `abusive_asn` is selected. Each key is set
    only when it is selected.
  - `Answered` comes from the field table (`Fields.Sourceless`: a selected key that is not always
    present and needs no source), instead of naming `abusive_networks`.
- **Findings.**
  - The `ip_owner` AS comes from the inventory's decoded owners, through a new `Inventory.Owner`.
    The findings no longer decode the kind a second time.
  - `HostInScope` replaces a hand-written class comparison.
  - `abusiveFinding` takes the first match for `entry`, `org` and `type` directly, with no tracking
    inside the loops.
  - The found line switches on `f.Type`, not on whether the entry starts with "AS".
  - `TestAbusive_SeverityTable` is gone: `TestSeverityTable` and the help golden file already cover it.
- **Scope and stage.**
  - `OwnerUnit` finds the most specific holding netblock in one pass.
  - `netblockowner` relies on `OwnerUnit`'s `ok` instead of filtering with `InScopeIP` first, and it
    collects its units with `slices.SortedFunc(maps.Keys(...))`.
- **Tests.**
  - The test snapshot builders no longer sort, since `Load` does not depend on order. `sorted` in
    `abusive_test.go` uses `CompareNetworks`.
  - Removed a dead special case in `TestValidate` and a dead clause in the rebuilt-snapshot test.
    That test's row checks moved into a helper, to keep it under the lint's complexity limit.
  - The terminal branch of the render test is simpler.

Skipped:

- **Binary search over the network ranges.** D5 chose a linear scan, about 17 µs an address. It
  matters only for engagements with tens of thousands of current addresses.
- **Finding a netblock address's AS by containment over `netblock_owner` records.** This would
  replace recomputing `OwnerUnit` and change which record answers after a scope change. The plan
  made `OwnerUnit` shared so that the stage and the finding cannot disagree.
- **Defaulting the snapshot once in `cli.withDefaults`.** That would parse it for every command,
  `nyx cve` and `nyx setup` included.
- **Using `input.ParseASN` in the refresh.** Its accepted forms differ: the refresh requires an "as"
  prefix in any case.
- **Narrowing `abusiveHostnames`' second loop to wildcard-only names.** It would tie the loop to how
  `HostnamesByIP` picks names, for little gain.
- **Merging the two page generators in `refresh_test.go`.** They differ in three places, and one
  generator taking those as parameters reads worse.
- **A shared test builder for snapshots in `testkit`.**
- **Sharing `writeAtomic` with the other temp-file writers.** None of those writers fits as is.

# Verification

## Result

The implementation meets the goal. A listed address shows its entries in `nyx ip` and as a recon
finding, and nothing contacts ipapi.is: the snapshot is embedded, and no stage or egress source
names the host. I checked it by hand with a fresh binary. `nyx ip 2.27.26.100 --fields
abusive_networks` reports `2.27.26.96/27` (High, 3.13%, H2.NEXUS Hanoi Network) from the real
snapshot, with no request and exit 0. A private address gets `null` for both keys. `go test ./...`,
`make lint` and `go vet` for all four targets pass.

By behaviour:

- **B1 Met.** `make abusive-data` matches D1: curl into a `mktemp -d` directory, then the Go parser,
  which does no network I/O. No `nyx` command contacts ipapi.is. The snapshot holds the 2026-11-21
  lists.
- **B2 Met, after a fix.** Every listed failure stops the refresh before anything is written, and
  both lists live in one file that is replaced whole. The gap in `## Known limitations` was real: a
  C1 character written as a numeric reference that Windows-1252 maps to a printable one (`&#x85;`,
  `&#155;`) got through, because the HTML parser had already decoded it. I fixed it. `readPage` now
  turns each numeric reference to 0x80 to 0x9f (hex or decimal, with or without the semicolon) into
  the raw character before parsing, so the per-cell control check rejects it. Three new
  `TestRefresh_FailsSafely` cases failed before the fix and pass after it. Cells are trimmed before
  the check, as D12 says.
- **B3 Met.** The summary lists added and removed entries, and changes to the four fields. A change
  in rank alone is left out. "no entries changed" is printed when nothing changed.
- **B4 Met.** Matching covers ranges and the origin AS. An IPv6 address matches only IPv6 ranges,
  and only the first origin AS is checked. The order is the most specific range first, ties by rank,
  then the ASN. Networks are written as `input.RangeText` writes them, which `rdap_netblock` shares.
- **B5 Met.** `Load` sanitises the text once, so the JSON, the CSV and the console all get clean
  text, and the human render sanitises it again.
- **B6 Met.** `netblock_owner` is not in `scopeKinds`. `ips.csv`, port eligibility, `candidate_rank`
  and `--active`'s `not_contacted` are the same as in a run without the check.
- **B7 Met.** The key order, the `[]`/`null` cases, the outcome when Team Cymru fails (record kept,
  exit 7), `--fields` alone, and the batch case all behave as specified. D8's "always answers" rule
  has one consequence beyond B7's own case: while `abusive_networks` is selected, an address whose
  every source failed is a partial result, not a failed input. The README says so, and it follows
  from B7's "a source that always answers".
- **B8 Met.** In the JSON, rank and `asn` are integers, `abuse_score` is a number, the text fields
  are strings and `updated` is `YYYY-MM-DD`.
- **B9 Met.** The two sections read `none` when empty and `unknown` when Team Cymru's origin lookup
  failed. A non-public address reads `none`, as other list keys do for one.
- **B10 Met.** Recon checks the addresses of in-scope names, including shared and wildcard-only
  ones, and the netblock addresses of current `ip` records that come from more than DNS history
  alone. It leaves out excluded addresses, candidate addresses and addresses that only DNS history
  names.
- **B11 Met.** `netblockowner` makes one Team Cymru query per /24, per /48, or per smaller
  netblock, and it runs under `--passive`. `ips.csv` still shows "in-scope netblock" as the owner.
- **B12 Met.** Severity is medium for a network match and low for an ASN match alone. The risk file
  has the columns D13 lists. The finding appears in the summary, the `--json` findings and
  `changes.csv`, and deriving it sends no request. It stores two attrs beyond D13's list, `entry` and
  `org`, for the found line. That is a compatible addition.
- **B13 Met.** Recon and `nyx ip` use the same snapshot functions, and a test compares their entries.
- **B14 Met.** A rebuilt snapshot changes the findings on the next run with no requests: a dropped
  address goes not current, a new one is announced, and a kept one keeps its record. A rise from low
  to medium is announced but not listed in `changes.csv`, and export shows the last run. The case of
  an engagement made before this build is tested as a first run of the stage, not with an older
  database.
- **B15 Met.** The README covers all of it. One wording difference: the README has no severity
  table, so the two types are listed in `nyx help findings` (generated from the severity table in
  code) and described in the new README section.

Out of scope is respected: no runtime fetch, no warning that the snapshot is old, no column on
`ips.csv`, every score tag flags, shared addresses are checked, and findings are per address.

Changed during verification: the C1-reference fix to the refresh (B2, above), in
`internal/abusive/refresh/refresh.go` and `refresh_test.go`.

## Code review

`/code-review high --fix` reviewed the change. By then the user had committed it as `ea67e39`.
The review made four fixes, and I kept all of them after checking each against the spec:

- **README, Passive boundary (B15).** The committed README had lost the sentence "No command
  contacts ipapi.is", so `TestAbusiveDocs_ReadmeGivesTheSnapshotDates` failed at `ea67e39`. The
  review restored the sentence. It also reworded the Team Cymru paragraph: the query names the
  first address of each /24, /48 or smaller netblock, and the paragraph links the Abusive networks
  section.
- **Refresh summary order (B1, B3).** The summary is now printed before the snapshot is replaced,
  which is D1's order. As a result, the "snapshot is unchanged" error is always true, even when
  printing fails.
- **Found line with a blank organisation (B12).** The found line drops the empty `()` when an
  entry's organisation is blank. I added `TestAbusive_FoundLineWithABlankOrganisation` to pin it.
  Today's snapshot has no blank organisation.

Left unfixed:

- **The "always answers" outcome in `nyx ip` (B7).** The review rated this important. While
  `abusive_networks` is selected (the default), an address whose every source failed now gets a
  record of nulls and exit 7 (PARTIAL), where before it got exit 1 with the source's error code.
  B7 calls the snapshot "a source that always answers", and the README documents the result, so I
  left it as built. Changing it is the user's decision (see Follow-ups).
- **Linear scan in `Snapshot.Networks`.** `## Simplify` already weighed a binary search and
  declined it, and no behaviour depends on the change.
- **`;` inside an organisation in the risk file's `networks` and `asn` cells.** The CSVs are read
  by people (CLAUDE.md). Changing the cell format is not something the spec asks for.

After the fixes, `make test` passed except for one run of `TestPorts_WorkerBounds` ("peaked at 5,
want 4"). That test does not touch this change, and it passed 20 times on its own under `-race`,
then passed again in a full `go test -race ./...`. `make lint` reports 0 issues.

# Follow-ups

1. Before release, ask ipapi.is (https://ipapi.is, contact page) whether nyx may embed and
   redistribute both lists and fetch the two pages for `make abusive-data`. Neither page states a
   licence or terms of use.
2. Decide whether an address in `nyx ip` whose every source failed should still count as answered
   while `abusive_networks` is selected (see `## Code review`). Today it gets exit 7 with a record of
   nulls, where before it got exit 1. To change it, edit the `Answered` rule in `lookupAddress`
   (`internal/iplookup/sources.go`) and the outcome paragraph in `README.md` ("The snapshot of
   abusive networks is a source that always answers"). `TestIPAbusive_EverySourceFailingStillHasARecord`
   pins the current rule.
3. Live check of `netblockowner` against the real Team Cymru on an engagement you are authorised to
   look at that has an in-scope netblock:
   `nyx recon --passive --cidr <netblock> <domain> --output-dir /tmp/nyx-live`. Confirm that Team
   Cymru gets one origin query per /24 and that `risk-abusive-network.csv` and `ips.csv` read as
   expected.
4. Run the build against an engagement made by an older nyx (B14 was tested only as the stage's
   first run on a fresh store): `nyx recon -e <old engagement> --passive --output-dir <its dir>`.
   Confirm the `netblockowner` checks run once and the findings appear.
5. Before each release, refresh the snapshot with `make abusive-data`, review the diff of
   `internal/abusive/snapshot.json`, update the two dates in the README's "Abusive networks"
   section, and commit.
6. Unrelated to this spec: `TestPorts_WorkerBounds` (`internal/cli/ports_test.go`) failed once under
   `make test` ("peaked at 5, want 4"). Look into it with
   `go test -race ./internal/cli/ -run TestPorts_WorkerBounds -count=200`.
