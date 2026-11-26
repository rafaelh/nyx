# Spec 2 of 4: Records of every name, and SPF addresses

## Goal

nyx reads the DNS records that point at other hosts for every in-scope name, not just the input
roots, so that delegated zones, mail hosts, alias targets and names written in TXT records are
found, and the
addresses an organisation's SPF records authorise are listed as netblock candidates.

Depends on: nothing. (With Spec 1, a parent name that does not resolve is asked too; see B1.)

Done when:

- the NS, MX and TXT records of an in-scope subdomain are in `resolutions.csv`;
- an in-scope name that only such a record mentions is listed as a hostname and resolved;
- an in-scope name that is only the target of an in-scope hostname's CNAME is listed as a hostname;
- an `ip4:` range in an in-scope root's SPF record is a `netblock` candidate.

## Behaviours

- **B1 Which names.** Every in-scope hostname under an input root whose address lookup was not
  answered NXDOMAIN, and that is neither wildcard-only nor an alias (a name with a CNAME), is asked
  for its NS, MX and TXT records through the public resolvers. A parent name that does not resolve
  (Spec 1 B9) is asked too. Input roots keep the lookups they get today and gain an MX lookup.
  (amended by D4, D8)
- **B2 Own records only.** Only records owned by the name itself are kept, for input roots too. A
  name that is an alias (it has a CNAME) gets none of its target's records. (amended by D9)
- **B3 Listed.** Each record is a row of `resolutions.csv` with its type (`NS`, `MX` or `TXT`). An
  input root's MX records are also rows, and so are the TXT records of an in-scope domain that an
  SPF record includes or redirects to (B8), which is asked for its TXT records only. (amended by
  D5)
- **B4 Names in scope.** The target of an NS or MX record, the target of an in-scope hostname's
  CNAME (which nyx records today but never lists as a hostname), and any hostname written in a TXT
  value, that is under an in-scope root becomes a hostname: it is resolved like any other and asked
  for its own records (B1). A name with a label that starts with `_` is not a hostname. A name in a TXT
  value is read in lower case, and one followed by further labels outside scope
  (`www.example.com.evil.net`) gives nothing.
- **B5 Names outside scope.** An NS or MX target outside scope is a row of `third-parties.csv` for
  the name's input root, with the mechanism `ns` or `mx` and the target's registrable domain. A TXT
  value that verifies a known platform is a `txt-verification` row. An `include:`, `redirect=`,
  `a:`, `mx:` or `exists:` domain outside scope in the SPF record of a subdomain, or of an included
  domain (B3), is an `spf` row at the depth it is found (0 in the subdomain's own record), and is
  not followed. None of these becomes a candidate or is resolved. A root's own `mx` and `spf` rows
  still come from `email` only. A name that is asked for its own records has depth 0, even when a
  record also includes it. (amended by D5, D6, D26, D29)
- **B6 Shared infrastructure unchanged.** Only input roots' name servers and mail hosts are
  searched for shared infrastructure (`nsreverse`, and the `shared-ns` and `shared-mx` candidates),
  as today. A subdomain's NS and MX records are never used to search for shared infrastructure.
- **B7 Delegated zones.** A name asked under B1 that has NS records of its own also gets the SOA
  and CAA lookups and the SRV service list that an input root gets today, recorded the same way,
  with failures as B10 says. It gets no email posture.
- **B8 SPF addresses.** Each `ip4:` and `ip6:` term, with no qualifier or with `+`, in the SPF
  record of an in-scope name, and in a record it includes or redirects to whose domain is in scope,
  gives a candidate: a term's address or range that is public and not wholly inside an in-scope
  netblock is a `netblock` candidate in `candidates.csv` (a single address as a /32 or /128), with
  the source `spf`, a family of its own, and the name whose record named it as its evidence item.
  These give no candidate: a term qualified `-`, `~` or `?`; a term after `all`; a range wider than /16 (IPv4) or /32
  (IPv6); a range (not a single address) whose first and last addresses are both known shared
  provider addresses; and any term in an included record whose domain is outside scope. A netblock
  candidate from any source that is wholly inside an in-scope netblock is left out of
  `candidates.csv`, and of the candidate count, whenever they are written. (amended by D2, D3, D27)
- **B9 Candidates unchanged.** An SPF candidate is treated as any netblock candidate: nothing in it
  is contacted or looked up until it is passed as `--cidr`.
- **B10 Failures.** For the lookups this spec adds, a timeout fails only that name's lookup of that
  type, which is retried on the next run. SERVFAIL, NXDOMAIN and an empty answer are results, so a
  broken delegation never keeps a run partial. Input roots' lookups fail as they do today.
- **B11 Passive.** All of this is DNS through the public resolvers: it runs under `--passive` and
  needs no `--authorised`.
- **B12 Documented.** `docs/output.md` describes the new rows of `resolutions.csv` and
  `third-parties.csv`, and `docs/candidates.md` lists the `spf` source and its family.

## Out of scope

- Email posture (SPF, DMARC and MTA-STS findings) for names below the input roots.
- Searching a subdomain's name servers or mail hosts for shared infrastructure. It would ask a
  third-party source about deeper names, which the user declined.
- PTR lookups for addresses outside in-scope netblocks, and of the other addresses in an address's
  /28 (bbot's `ipneighbor`). Declined by the user.
- SERVFAIL as a failure that is retried, for the lookups this spec adds. Declined: a broken
  delegated zone would make every run exit 7.
- Names under a name that is in scope by its address (Spec 4): it is not asked for these records.
- Engagements created before this change. The user will start fresh engagements.
- A candidate for an SPF range inside known shared provider space (D2). Declined: it is the
  provider's sending pool, not the organisation's. A single address there is kept.
- Asking an alias for its NS, MX and TXT records (D4). Declined: it can own none.
- An aliased input root's target records as rows of the root (D9). Declined: B2 holds for roots.
- Moving SPF addresses (B8, B9) to a spec of their own (D7). Declined: they come out of the TXT
  lookup this spec already makes.

# Design

## External facts

No external data is embedded by this spec.

- **An alias answers with its target's records, owned by the target.** Asking TXT, MX or NS of a
  name that has a CNAME returns the CNAME chain and then the target's records with the target as
  owner name (`www.github.com TXT` and `MX`; `aws.amazon.com NS`). *Confirmed live* on 2026-11-26
  against nyx's three default resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9). `egress` keeps such records in
  `DNSResult.Answers` with `Answer.Name` set to the target, lower-cased with no final dot, so
  `a.Name == <asked name>` is the own-records test (B2, D9, D12).
- **NS of a name that is not delegated answers NOERROR with no records**, and NS of a delegated
  subdomain answers NS records owned by the name (`docs.github.com`; `corp.google.com`,
  `eecs.berkeley.edu`, `s3.amazonaws.com`). *Confirmed live*, same date and resolvers. B7 rests on
  it: own NS records mark a delegated zone.
- **A broken zone answers SERVFAIL** (`www.dnssec-failed.org NS`). *Confirmed live*, same date and
  resolvers. `egress` tries the next resolver on SERVFAIL and returns the last such answer as an
  RCode, not an error; only "no resolver answered" is an error (the timeout of B10).
- **A large TXT answer is truncated over UDP and complete over TCP** (`github.com TXT`).
  *Confirmed live*. `egress` retries a truncated answer over TCP (`internal/egress/dns.go`) and
  joins a TXT record's character-strings with no separator, so an SPF record split across strings
  reads whole.
- **SPF grammar** (RFC 7208): terms are separated by spaces; a mechanism may be prefixed by one
  qualifier `+`, `-`, `~` or `?` (none means `+`); mechanism names are case-insensitive;
  `ip4:<address>[/<bits>]` and `ip6:<address>[/<bits>]`; `redirect=<domain>` is ignored when the
  record has an `all` mechanism (section 6.1); a name with more than one `v=spf1` record has no
  usable SPF record (section 4.5). *From docs*, not probed; `internal/recon/procedures/risk/email.go`
  already relies on the same rules. The live `github.com` record shows the shapes this spec reads:
  `ip4:192.30.252.0/22`, `ip4:62.253.227.114`, `include:_netblocks.google.com`.

Check the live facts again with:

```sh
for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
  dig +noall +comments +answer www.github.com TXT @$r | grep -e status: -e CNAME -e spf1
  dig +noall +comments +answer +authority docs.github.com NS @$r | grep -e status: -e 'IN'
  dig +noall +comments +answer corp.google.com NS @$r | grep -e status: -e 'IN'
  dig +noall +comments www.dnssec-failed.org NS @$r | grep status:
done
```

## Decisions

Decided by the user:

- **D1 Procedure.** A new procedure, `dnsrecords`, asks the names below the input roots. `dnsroot`
  keeps the roots. `--skip dnsrecords` and `--redo dnsrecords` work as for any procedure. Why: on a
  large engagement the new lookups are worth being able to turn off alone.
- **D2 Provider ranges in SPF.** A range (a prefix shorter than /32 or /128) whose first and last
  addresses are both known shared provider addresses gives no candidate; a single address there is
  kept. Why: a range in provider space is the provider's sending pool, and a single cloud address an
  organisation authorises is most likely its own host.
- **D3 Inside an in-scope netblock.** Applied when records are read, for every source: a netblock
  candidate that a different in-scope netblock contains is not listed. It changes `rdap` and
  `org-asn` candidates too. Why: promoting a wider range with `--cidr` should clear the candidates
  inside it without `--redo`.
- **D4 Aliases.** A name with a CNAME of its own is not asked. Why: it can own no other record, and
  B2 would discard the answers.
- **D5 Included SPF domains.** An in-scope domain that an SPF record includes or redirects to is
  asked for its TXT records by a job of its own. Its TXT records are rows, its `ip4:` and `ip6:`
  terms are candidates with that domain as the evidence item, and it is not a hostname.
- **D6 SPF third-party terms.** For a subdomain and an included domain, the domains of `include:`,
  `redirect=`, `a:`, `mx:` and `exists:` terms are `spf` third parties, as `email` records for a
  root.
- **D7 One spec.** SPF addresses (B8, B9) stay in this spec.
- **D8 Root MX.** `dnsroot` gains an MX lookup per root (job `<root>|MX`), handled as a
  subdomain's is. `email` keeps its own MX lookup. Why: the rows then exist under `--skip email`,
  and one handler serves roots and subdomains.
- **D9 Aliased roots.** `dnsroot` keeps only records owned by the root, for every type (today for
  NS and SOA only). An aliased root's target's TXT and CAA rows are no longer listed. Why: with this
  spec they would become SPF candidates, hostnames and include lookups taken from a provider's
  records.

Decided from the code:

- **D10 Jobs.** `DNSRecords` in `internal/recon/procedures/dns/records.go` embeds `base`
  (`ThirdParty`, no sources, always configured). It is not `Required`, `Retiring` or `Budgeted`.
  - One job per name and type, as `dnsroot` has: `<name>|NS`, `<name>|MX`, `<name>|TXT`.
  - For a name in the list (D11, parents included) that has a current NS `resolution` row of its
    own: `<name>|SOA`, `<name>|CAA` and `<name>|SRV|<srvKeyToken>` (B7). They are yielded on the
    pass after the NS job; the runner repeats passes until none has work.
  - For an included SPF domain (D16): `<domain>|TXT` only.
  - A name that is both in the list and an included domain has one TXT job, at depth 0.
  - Why per type: a timeout then fails one name's one type (B10) by the runner's completed-job
    rule, and a second run sends nothing.
  - Cost, stated for the docs and the follow-up: 3 lookups per listed name and 16 more per
    delegated zone (SOA, CAA and 14 SRV names), once per engagement. There is no cap.
- **D11 The name list (B1).** A new inventory method, exposed on `run.View` (name it for what it
  returns, for example `RecordNames`), gives the current `hostname` records that are in scope,
  have `Scope.RootOf(name) != ""` (comment: this is what keeps Spec 4's names out), are not an
  input root, are not wildcard-only and have no CNAME of their own. `DNSRecords.Jobs` keeps such a
  name when:
  - `resolve` has completed it: `v.DoneBy("resolve", name)` or
    `v.DoneBy("resolve", parentPrefix+name)` (both procedures are in package `dns`);
  - it has no `unresolved` record with RCode `NXDOMAIN`;
  - its zone's wildcard check is not pending (`wildcardPending`, as Spec 1 D16 and D17).

  It adds each name of `v.ParentNames("resolve")` that is in scope, has no `hostname` record, whose
  `parent|` job is done and whose zone's wildcard check is not pending: the parents that do not
  resolve. Spec 1 B9 treats a parent that only its zone's wildcard answered as one that does not
  resolve, so it is asked too.
- **D12 One record handler.** `dnsroot` and `dnsrecords` share one function in package `dns` that
  turns an answer into observations. Its input: the asked name, its input root
  (`Scope.RootOf(name)`), the type, the scope snapshot, the SPF depth, the shared-address function
  (D18) and whether to write `spf` third parties.
  - Every type keeps only answers with `a.Name == name` (B2, D9).
  - A target becomes a `hostname` when `Scope.HostInScope(t) && Scope.RootOf(t) != ""` and no
    label of it starts with `_` (one predicate, used by D13 too). Otherwise an NS or MX target is
    `kinds.ThirdPartyObs(root, "ns"|"mx", dnsname.Registrable(t), 0)`.
  - NS: a row per record. MX: a row with the value as `egress` gives it (`"10 mail.example.com"`);
    the null MX `"0 ."` is a row and names no host.
  - TXT: a row per record; `provider.Default().Verification` gives the `txt-verification` third
    party as today; hostnames in the value (D14); SPF (D15).
  - SOA, CAA and SRV: as `dnsroot` does today.
  - SERVFAIL: `dnsroot` returns an error before the handler, as today; `dnsrecords` treats it as
    an empty answer. `runSRV` takes the same switch, since it fails the job on SERVFAIL itself.
  - `serveraddr.Observations` stays in `dnsroot`'s NS job only (B6).
  - `dnsroot`'s TXT job passes "no `spf` third parties": a root's are `email`'s, which applies a
    different filter and retires its jobs. It still gives hostnames, candidates and, through D16,
    include jobs.
- **D13 CNAME targets (B4).** `Resolve.Run` adds `kinds.Hostname.Obs(target)` for each CNAME link
  whose owner is in scope and whose target passes D12's predicate. The scope snapshot goes in the
  job input, as `dnsroot`'s `rootInput.sc` does. `View.ResolvableHostnames("resolve")` leaves out a
  name only `resolve` produced, so `Resolve.Jobs` itself adds a normal job for each such target of
  a current CNAME row that the list lacks, and yields no `parent|` job for a name that has a normal
  job. The `View` method is untouched (`learned-names` uses it too). Accepted: a name asked earlier
  as a parent is asked once more when it turns out to be a CNAME target.
- **D14 Hostnames in text.** A pure `dnsname.HostnamesIn(text string) []string`: the maximal runs
  of `[A-Za-z0-9._-]`, lower-cased, with leading and trailing dots trimmed, kept when they have at
  least two labels and every label is a `ValidLabel`. The run is maximal, so
  `www.example.com.evil.net` is read whole and gives nothing in scope, and `_dmarc.example.com` is
  rejected whole rather than cut at the `_`. The handler keeps the names that pass D12's predicate
  and are neither the asked name nor an input root. Spec 3 extends this helper.
- **D15 SPF.** A new pure package `internal/knowledge/spf`:
  - `Record(txts []string) (string, bool)`: the one `v=spf1` record, or false when there are none
    or several (`email`'s rule);
  - `Parse(record)`: the terms, each with its qualifier, lower-cased mechanism or modifier name
    and value, and whether the record has `all`;
  - a term's network: for `ip4` and `ip6`, the masked prefix, a single address as /32 or /128;
    false for anything malformed or of the wrong family;
  - a term's domain: for `include`, `redirect`, `a`, `mx` and `exists`, the normalised name with
    any `/bits` removed, false for a macro, an address literal or a name that cannot be looked up
    (`email.go`'s `lookupable` rule).

  `email.go` is not changed; a `docs/todo.md` entry notes that its `walk` could use this package.
  The handler, for the name's one SPF record:
  - each `ip4`/`ip6` term with qualifier `+` whose prefix is at most as wide as /16 (IPv4) or /32
    (IPv6), is public (a new `addrkind.PublicPrefix`: no special-purpose row overlaps it, and an
    IPv6 prefix is inside 2000::/3) and is not dropped by D2 gives
    `kinds.Netblock.Obs(prefix.String(), kinds.NetblockAttrs{})`;
  - when asked to write `spf` third parties, each domain of an `include`, `redirect`, `a`, `mx` or
    `exists` term that is not under the root's registrable domain gives
    `kinds.ThirdPartyObs(root, "spf", domain, depth)`; the kind's visibility already hides a domain
    that is in scope. `redirect=` is ignored when the record has `all`.
- **D16 Included domains and depth (D5).** `DNSRecords.Jobs` walks breadth-first from the in-scope
  input roots and the listed names (depth 0) over the current TXT `resolution` rows: for a name's
  one SPF record, each `include` domain, and the `redirect` domain when the record has no `all`,
  that passes `HostInScope && RootOf != ""` and is not an input root is an included domain at the
  includer's depth plus one, unless already seen. One set is built before any job is yielded, so a
  name has one depth, the smallest. A `_` label is allowed here (`_spf.example.com`). Following is
  therefore lazy across passes: no job recurses, a loop cannot happen, and a timeout fails one
  domain's job. An included domain that is an alias gives nothing (B2).
- **D17 Evidence and family.** `DNSRecords` and `DNSRoot` implement `Evidencer`: a key ending
  `|TXT` gives `("spf", <name>)`; any other key gives the default (the procedure's name and the
  key). Both declare `CandidateSources{"spf": "spf"}`, as `rdns` and `crawl` declare theirs, which
  puts the source under `TestCandidates_DocsListEverySource`.
- **D18 Shared provider addresses.** A new `View.SharedAddr(netip.Addr) bool` over
  `inventory.Shared`. `Jobs` puts it in each TXT job's input, and the handler asks it of a range's
  first and last address (D2). It is judged when the job runs: `providerranges` is `Required` and
  earlier in the registry.
- **D19 Placement (D3).** A new `scope.Scope` method reports whether an in-scope netblock contains
  a prefix. `placeNetblock` (`internal/recon/kinds/table.go`) asks it only after `HasNetblock` is
  false, and then returns unlisted. So an in-scope netblock nested in another (a `--cidr` inside
  another, an ASN's more-specific) stays in scope and counted, and a contained candidate leaves
  `candidates.csv`, the candidate count and `candidate_rank`.
- **D20 nsreverse (B6).** `nsreverse.Jobs` takes an NS row only when its name is an in-scope input
  root (today: any in-scope name). Without this, a subdomain's self-hosted name server would start
  a paid SecurityTrails search.
- **D21 `resolutions.csv`.** `output.resolutionRows` fills `self_hosted` only on a current NS row
  of an input root and leaves it blank on a subdomain's, whose servers' addresses are never looked
  up. It also indexes an MX row under `<name>|MX|<host>`, so Shodan's MX claim, which holds the
  host without its preference, merges with nyx's row instead of making a second one.
- **D22 Registry.** `dns.NewDNSRecords()` goes after `dns.NewLearnedNames()` and before
  `dns.NewRDNS()` in `defaultProcedures()` (`internal/cli/cli.go`), with a line in its ordering
  comment: it follows `resolve` and `wildcard` so it reads their completion as of this pass.
  `TestRiskProcedureRegistry` pins the order from `ipowner` on and is untouched. A `procedureHelps`
  entry (`"dnsrecords": {"", "NS, MX and TXT records of each name below the roots, and the names and third parties they show"}`),
  and `dnsroot`'s entry gains MX.
- **D23 Fake DNS.** `egresstest.DNS` gains `DropType(name, qtype)` and `UndropType`: `Drop` is per
  name and would fail `resolve` too.
- **D24 Docs.** `docs/output.md`: the `resolutions.csv` row says which names have NS, MX and TXT
  rows (every in-scope name below a root that is asked, included SPF domains for TXT, roots for
  MX), that a delegated zone also has SOA, CAA and SRV rows, and that `self_hosted` is filled for
  roots only; the `third-parties.csv` row says a subdomain's dependencies are listed under its
  root and what depth means for a subdomain's SPF. `docs/candidates.md`: `spf` in the sentence of
  sources that are each a family of their own, the name as an evidence item, the rules of B8, and
  that a candidate inside an in-scope netblock is not listed. `docs/sources.md`: a short section on
  the records of every name (what is asked, of which names, the cost, `--skip dnsrecords`), and the
  parent-names sentence of `## Name guessing` gains "apart from rows of its own records in
  `resolutions.csv`" inside that section. `docs/todo.md`: the `email` entry of D15.
- **D25 Accepted.**
  - A third party's depth across jobs is the store's last-writer merge, not the smallest; `email`
    is later in the registry, so a root's depth wins.
  - An included domain's depth is as of when its job ran.
  - Rows, third parties and candidates from a name that later leaves the list or is excluded stay
    current, as `dnsroot`'s do (neither procedure retires jobs).
  - A range judged under D2 is not judged again when provider ranges change, until
    `--redo dnsrecords`.
  - A parent that only a wildcard answered is asked (D11); a wildcard TXT or MX gives it rows.
  - An SPF term inside an `--exclude` CIDR is still a candidate: `placeNetblock` has no excluded
    class today.

Decided by the user during development:

- **D26 Root MX third parties.** `dnsroot`'s MX job writes the root's MX rows and in-scope
  hostnames but no `mx` third parties: a root's are `email`'s, which filters them its own way (no
  address literal, nothing from a failed job), as D12 already says of its `spf` ones. A
  subdomain's MX job writes them (B5). Why: two existing `email` tests pinned that filter.

Settled after verification:

- **D27 Terms after `all`.** A mechanism written after `all` is never evaluated (RFC 7208 section
  5.1): it gives no candidate, no `spf` third party and no included domain. `spf.Parse` marks such
  mechanisms and `Policy.Applies` leaves them out. `email` still reads them (noted in its
  `docs/todo.md` entry). Why: a range after `-all` is not one the organisation authorises.
- **D28 Targets in the root's registrable domain.** Kept as B5 says: an out-of-scope NS, MX or SRV
  target is a third party by its registrable domain, even the one above a sub-domain root. The
  code review's edit that dropped such rows was undone. Why: the parent organisation's name server
  is a real dependency of a sub-domain root, and for a root that is its own registrable domain the
  row is already hidden.
- **D29 Depth of a listed included domain.** Kept as D16 says: a name asked for its own records
  (a hostname, which an `include:` domain without a `_` label also becomes under B4) is at depth
  0, so the domains its record names are `spf` rows at depth 0. `docs/output.md` says so. Why:
  depth is per asked name; computing it from the include graph would need a second notion of
  depth for listed names.

Dropped from the critic's review:

- Not declaring `CandidateSources`: declaring is what puts `spf` under the docs test (D17).
- B1's wording for wildcard-answered parents: Spec 1 B9 already defines them as not resolving.

## Files

New:

- `internal/recon/procedures/dns/records.go`: `DNSRecords` (Jobs, Run, Evidence,
  CandidateSources), the shared record handler and the name list.
- `internal/recon/procedures/dns/records_test.go`: unit tests of the list, the include walk and
  the handler.
- `internal/knowledge/spf/spf.go` and `spf_test.go`.
- `internal/cli/dnsrecords_test.go`, `internal/cli/spf_candidates_test.go`: the behaviour tests.

Changed:

- `internal/recon/procedures/dns/dnsroot.go`: the MX type, the shared handler, own records for
  every type, `runSRV`'s SERVFAIL switch, `Evidence` and `CandidateSources`.
- `internal/recon/procedures/dns/resolve.go`: CNAME-target hostnames and their jobs (D13).
- `internal/recon/procedures/nsreverse/nsreverse.go`: roots only (D20).
- `internal/recon/run/procedure.go`: the `View` methods of D11 and D18.
- `internal/recon/inventory/inventory.go` and `inventory_test.go`: the method behind D11.
- `internal/recon/kinds/table.go`: `placeNetblock` (D19). `internal/scope/scope.go` and its test:
  the containment method.
- `internal/knowledge/addrkind/addrkind.go` and its test: `PublicPrefix`.
- `internal/knowledge/dnsname/dnsname.go` and its test: `HostnamesIn`.
- `internal/recon/output/output.go`: `resolutionRows` (D21).
- `internal/egress/egresstest/dns.go`: `DropType`, `UndropType`.
- `internal/cli/cli.go`, `internal/cli/procedures_topic.go`.
- `docs/output.md`, `docs/candidates.md`, `docs/sources.md`, `docs/todo.md`.
- Existing tests (see Tests).

## Tests

Behaviour tests drive `cli.Execute` through the harness and the fake DNS (`w.dns`: `NS`, `MX`,
`TXT`, `SOA`, `CAA`, `SRV`, `CNAME`, `Wildcard`, `RcodeType`, `Count`, `Queried`, `Total`, and the
new `DropType`). The fake is UDP-only, so keep one name's TXT records small. Use `runRoot` and
`w.table(eng, "resolutions.csv")`, `tpRows`, `w.lines(eng, "subdomains.txt")` and the candidate
helpers of `candidates_test.go`. SPF fixtures need addresses `addrkind.Of` calls public, which the
documentation ranges the other tests use are not: use their neighbours (`192.0.3.0/24`,
`198.51.101.0/24`, `203.0.114.0/24`) and assert in the test that they are public. Nothing in a
candidate is contacted, and the harness canaries catch it if something is.

Mutation checks in `/spec-develop`: **B2/D9** (own records), **B4** (the `evil.net` rule and the
`_` rule), **B6/D20** (a bug spends paid credits), **B8** (qualifier, width, public and provider
filters) and **B9**, since a bug in any of them puts another party's hosts or addresses in front
of the user as the organisation's.

- **B1.**
  - A subdomain with an address is asked NS, MX and TXT once each (`Count`).
  - Not asked: a name answered NXDOMAIN, a wildcard-only name, an alias, a candidate hostname, an
    excluded name, an input root by `dnsrecords` (its `Count` stays one per type).
  - A name answered NODATA (it has only an MX record) is asked.
  - A parent that does not resolve is asked; one that resolves is asked as the hostname it is.
  - A name in a zone whose wildcard probes fail (SERVFAIL) is not asked; after a run in which the
    check succeeds, it is.
  - A root's MX is asked by `dnsroot` (job `<root>|MX`).
- **B2.** An alias's target has NS, MX and TXT records: none is a row under the alias, and none of
  their targets or SPF terms is recorded. The same for an aliased input root, for TXT, CAA and MX
  (D9), and for an included SPF domain that is an alias.
- **B3.** Rows with name, type and value for a subdomain's NS, MX and TXT; a root's MX row; an
  included domain's TXT rows, with no NS or MX lookup of it; a null MX row; `self_hosted` blank on
  a subdomain's NS row and filled on a root's; a Shodan MX claim merges into nyx's MX row
  (`resolve;shodan`).
- **B4.**
  - An in-scope NS target, MX target, CNAME target and a name written in a TXT value each appear in
    `subdomains.txt`, are resolved, and are asked for their own records in the same invocation.
  - A CNAME target that does not resolve is in `unresolved.txt`; one that is also a parent name is
    not given a `parent|` job as well.
  - A target outside scope, an excluded target and a target with a `_` label are not hostnames.
  - In a TXT value: `API.Example.COM` gives `api.example.com`; `www.example.com.evil.net`,
    `_dmarc.example.com` and `sel._domainkey.example.com` give nothing; `*.cdn.example.com` gives
    `cdn.example.com`; a name after `@`, `:` or `//` is read.
- **B5.** A subdomain's NS and MX targets outside scope are `ns` and `mx` rows under its input
  root with the registrable domain; a verification TXT is a `txt-verification` row; `include:`,
  `redirect=`, `a:`, `mx:` and `exists:` domains are `spf` rows at depth 0, and those of an
  in-scope included domain at depth 1; a `redirect=` beside `all` gives none; none of the domains
  is in `candidates.csv` or is ever queried (`Queried` over every type). A root's own SPF third
  parties still come from `email` only.
- **B6.** With a SecurityTrails key set, a subdomain's in-scope (self-hosted) name server creates no
  `nsreverse` job and no request, while the root's does.
- **B7.** A subdomain with its own NS records gets the SOA, CAA and 14 SRV lookups, in the
  invocation that found the NS records; one without gets none; a parent that does not resolve but
  is delegated gets them; an in-scope SRV target becomes a hostname and one outside is an `srv`
  row under the root; no `email_posture` record and no email finding exists for the subdomain.
- **B8.**
  - A root's `ip4:192.0.3.0/24` is a `netblock` candidate with sources `spf`, evidence count 1,
    confidence `low`; the same range in a subdomain's record too raises the count to 2 and keeps
    one source and one family.
  - `ip4:` of one address is a /32, `ip6:` of one a /128; host bits are masked; `IP4:` and `+ip4:`
    count.
  - No candidate: `-`, `~` and `?` terms; `/15` and IPv6 `/31`; private, loopback, documentation
    and multicast ranges; a malformed term; two `v=spf1` records.
  - A range inside a provider range (use the world's provider-range fixture, as
    `providerranges_test.go` does) gives none; a single address inside it gives a /32.
  - An in-scope `include:` and `redirect=` are followed and their terms are candidates with the
    included domain as the evidence item (two includers of one domain count once); one outside
    scope is never asked for TXT.
  - A candidate inside a `--cidr` added on a later run leaves `candidates.csv` and the candidate
    count without `--redo`; an `rdap` candidate does too; an in-scope netblock nested in another
    stays in `netblocks.csv`.
  - `TestCandidates_FamiliesOfTheRealSources` gains `"spf": "spf"`.
- **B9.** After a run that lists SPF candidates, no PTR, A or other lookup names an address in
  them, and the TCP and HTTP canaries are silent, with `--authorised` too.
- **B10.**
  - `DropType(name, "TXT")`: that job alone fails, the name's NS and MX rows are recorded, the run
    exits 7 naming `dnsrecords 1`, and the next run asks only that TXT.
  - `RcodeType` SERVFAIL, NXDOMAIN and an empty answer each complete the job with no rows and exit
    0, for NS, MX, TXT, SOA, CAA and the SRV job.
  - A root's SERVFAIL still fails its `dnsroot` job (`TestDNSRoot_Outcomes` stays as it is).
- **B11.** Everything above runs under `--passive` with no `--authorised`; `--skip dnsrecords`
  sends none of its lookups and leaves `dnsroot`'s.
- **B12.** Doc tests with `docPage` or `docsSection`: `docs/output.md` names MX among the
  `resolutions.csv` types and says subdomains' records are listed; `docs/candidates.md` has
  `` `spf` `` among the sources that are a family of their own.
- **Failure and re-run cases.**
  - External dependency: the resolvers are the only one; timeout and SERVFAIL are the B10 cases.
  - One item failing in a batch: the `DropType` case (jobs are per name and type).
  - Interrupt part-way: an interrupted run (as in `partial_test.go`) keeps the jobs already
    completed and the re-run asks only the rest. No secret is involved: the procedure has no key.
  - Re-run after success: a second run sends no lookup (`w.dns.Total()` unchanged). Re-run after a
    partial failure: the `DropType` case. Order: a name found from a record in one pass is
    resolved, then asked, in the same invocation (B4), and SOA, CAA and SRV follow the NS job (B7).
- **Unit.** `spf` (record choice, qualifiers, networks, domains, macros, `redirect` beside `all`);
  `dnsname.HostnamesIn`; `addrkind.PublicPrefix` (a prefix that contains a special-purpose block
  is not public); the scope containment method (equal prefixes do not count); the inventory
  method; the include walk's depths (a name that is both listed and included is depth 0).
- **Existing tests to update.** `TestDNSRoot_JobsAndPassive` (the MX job key);
  `TestHelp_ProceduresTopic` and the procedure count in `setup_info_internal_test.go`; any `rdap`
  or candidate test whose candidate sits inside an in-scope netblock; tests that count every row of
  `third-parties.csv` or every query in a world where a subdomain has records. The worlds of
  `world_test.go` run the new procedure; add `--skip dnsrecords` only where a test is about
  something else and counts queries.

## Conventions

- `CLAUDE.md`: the hard invariants (only `internal/egress` does network I/O; procedures get
  `egress.Clients`), the procedure rules (a job key encodes every input that changes the work;
  negative results complete a job; code outside a procedure never names a procedure, so `View`
  methods take the generator's name), knowledge packages are pure, the testing rules
  (`t.Parallel()` first, harness environment only, behaviour tests in `internal/cli`), and
  Australian English in docs, comments and messages.
- The keys of the `--json` envelope and the attribute JSON names in the state database are a
  stable interface: this spec adds none and renames none.
- Targeted tests without `-race` while iterating; `make test` and `make lint` before finishing.
- Doc tests read `README.md` and `docs/*.md`; a sentence a test names must stay in its `## `
  section.
- Commit messages use conventional prefixes (`feat:`, `fix:`, `docs:`).

## Handed to later specs

- **Spec 3.** `dnsname.HostnamesIn` (D14) is the reader of hostnames in text; Spec 3 adds the
  unescaping of its B4 and its cap, and uses the same in-scope predicate (D12).
- **Spec 4.** A name in scope by its address must not be asked for these records. D11 and D12 key
  on `Scope.RootOf`, so this holds as long as Spec 4 does not make `RootOf` answer for such a name.
  D19's placement rule already hides a candidate netblock inside an in-scope one, which Spec 4's
  netblock rules can rely on.

# Implementation

## Develop

Base commit: 179a47d5b781e3a3be225d09761986c65119b9cb

Frozen test files: `internal/cli/{dnsrecords,spf_candidates,dnsroot,candidates,help,nsreverse}_test.go`,
`internal/cli/setup_info_internal_test.go`, `internal/egress/egresstest/dns.go` (the fake's
`DropType`), `internal/knowledge/{spf/spf,dnsname/dnsname,addrkind/addrkind}_test.go`,
`internal/scope/scope_test.go`, `internal/recon/inventory/inventory_test.go`,
`internal/recon/procedures/dns/records_test.go`.

**How it was built.** Four test writers wrote the tests in parallel by file group: the pure helpers
(`spf`, `dnsname.HostnamesIn`, `addrkind.PublicPrefix`, `Scope.InsideNetblock`,
`Inventory.RecordNames`), the `dns` package's handler and include walk (`recordObservations`,
`includedDepths`), the `dnsrecords` behaviour tests (B1–B7, B10, B11, B12's output page, the
failure and re-run cases, with the fake's `DropType`) and the SPF candidate tests (B8, B9, B12's
candidates page). Every new test failed on its assertions before the code was written; two passed
already by design (`"spf"` is a family of its own because an undeclared source already is, and
nested in-scope netblocks stay in scope). I wrote the code myself:

- `internal/recon/procedures/dns/records.go`: `DNSRecords` (D10, D11, D16, D17), the shared
  handler `recordObservations` with `recordInput` (D12), the one hostname rule `recordHost`, the
  SPF candidate filters (D2, D15) and `includedDepths`. `dnsroot.go` now builds `recordInput` for
  every type, adds `<root>|MX` (D8), keeps own records only (D9), and `runSRV` takes the SERVFAIL
  switch. `resolve.go` records in-scope CNAME targets as hostnames and gives them jobs (D13); its
  job input carries the scope snapshot.
- `View.RecordNames` and `View.SharedAddr` (D11, D18); `placeNetblock` hides a candidate inside an
  in-scope netblock (D19); `nsreverse` takes roots' NS rows only (D20); `resolutionRows` fills
  `self_hosted` for roots only and indexes an MX row by host for Shodan's claim (D21); registry
  and help topic (D22); docs (D24).

**Deviations.**

- D26 (settled with the user): the root's MX job writes no `mx` third parties; `email` keeps
  them. Two existing `email` tests (`TestEmailThirdParties_MX`,
  `TestEmailThirdParties_IncludeServfailRecordsNothing`) failed otherwise.
- An address literal written as an NS, MX or SRV target is neither a hostname nor a third party
  (`TestRecordObservations_AddressTargets`, added after the freeze); `email` already rejects one
  for a root.
- `## Tests` says a nested in-scope netblock "stays in `netblocks.csv`": there is no such file.
  The test checks `scope.csv` and the summary's netblock total instead.
- With your agreement, the assertions added to the frozen `TestHelp_ProceduresTopic` moved
  unchanged into `TestHelp_ProceduresTopicRecords`, because lint's cognitive-complexity limit
  failed on the longer test.
- The test writers' fixtures give each `world.owner` call its own ASN: the fake DNS is UDP-only
  and Team Cymru's TXT answer for one ASN grows with each owner.

**Tests that fail on the base too.** `go test ./internal/cli/ -run '^TestSetup_FailedSaveKeepsTheEdits$' -count=20`
and `go test ./internal/lookup/iplookup/ -run '^TestActive_EndToEnd$' -count=20` failed 20/20 both
with the change and on the base commit (macOS). Both are already listed in `docs/todo.md`.

No external fact turned out different from `## External facts`.

**Mutation checks** (each break made by hand, the tests run, the file restored from a copy):

| Behaviour | Break | Tests that failed |
|---|---|---|
| B2/D9 own records | `owned` keeps records of any owner | `TestRecordObservations_OwnRecordsOnly`, `TestDNSRecords_OwnRecordsOnly`, `TestDNSRoot_AliasRootTakesNoTargetRecords` |
| B4 `_` rule (targets) | `recordHost` drops the `_` label check | `TestRecordObservations_{NS,MX}Targets`, `TestDNSRecords_TargetsThatAreNotHostnames` |
| B4 `_` rule (text) | `HostnamesIn` cuts a run at `_` | `TestHostnamesIn`, `TestRecordObservations_TXTHostnames`, `TestDNSRecords_NamesInTXTValues` |
| B4 `evil.net` rule | `HostnamesIn` also gives each shorter prefix of a run | `TestHostnamesIn`, `TestDNSRecords_NamesInTXTValues` |
| B6/D20 | `nsreverse` takes any in-scope name's NS rows | `TestNSReverse_SubdomainServersAreNotSearched` |
| B8 qualifier | any qualifier gives a candidate | `TestRecordObservations_SPFNetblocks`, `TestSPFCandidates_TermsThatGiveNone` |
| B8 width | no width limit | the same two |
| B8 public | no public check | the same two, and two `nsreverse` tests |
| B8 provider | shared ranges kept | `TestRecordObservations_SPFSharedRanges`, `TestSPFCandidates_ProviderRanges` |
| B9 | `dnsroot`/`dnsrecords` netblocks counted in scope | eight `TestSPFCandidates_*` tests, `NothingInThemIsContacted` among them |

## Simplify

Four reviewers (altitude, reuse, efficiency, simplification). Applied:

- `lastAddr` removed for `input.LastAddr`.
- The redirect-beside-`all` rule moved into `spf.Policy.Applies` (with `TestPolicy_Applies`), used
  by the handler and the include walk.
- One `runRecord` step applies the SERVFAIL rule from `servFailFails` for both procedures and the
  SRV list, and returns the owned records `dnsroot` needs for its server addresses. One `owned`
  helper holds the own-records rule.
- `recordObservations` lost its second TXT slice and early return; `DNSRecords.Jobs` builds each
  name's types in one loop and yields the jobs without an identity mapper.
- `DNSRoot` and `DNSRecords` embed `recordProcedure`, which holds the shared `CandidateSources`
  and `Evidence`.
- `resolve`'s job input is always set, so the comma-ok and the nil-scope guard went;
  `Resolve.Jobs` checks the type before normalising and its CNAME-target scan is
  `cnameTargets` (also to keep it under lint's complexity limit).
- `Scope.InsideNetblock` looks up only the prefix lengths that occur in scope instead of scanning
  every netblock for each candidate.
- `docs/todo.md`'s `email` entry notes that `withPrefix` accepts `v=spf1;` and `spf.Record` does
  not.

Skipped:

- Merging `spfThirdParties`, `mxByEmail` and `servFailFails` into "is a root": the frozen handler
  tests pin `spfThirdParties` on a non-root name.
- Moving `email.go` onto the `spf` package: D15 defers it to `docs/todo.md`.
- `self_hosted` from inventory knowledge rather than "is a root" (D21 chose the rule) and a
  `scope.IsRoot` helper (low value).
- Test-helper duplication in the frozen tests (`testNSType`, `drPublic`, `spfLast`, `drRow`,
  `spfCandidate`, `drDocRow`, `spfAddrOf`, `spfQueryTypes`) and renaming `rootType`, which the
  frozen tests use: each would change a frozen file for no change in what it pins.
- Running the SRV list concurrently, caching `DoneBy` across passes, scanning resolutions once,
  memoising `ParentNames`/`RecordNames`, and the root's MX asked by both `dnsroot` and `email`:
  each costs milliseconds or one query per root.

## Known limitations

- **B1.** A parent name is asked whatever its `parent|` job answered, NXDOMAIN included (D11 lists
  no NXDOMAIN filter for parents). A parent below an existing name rarely answers NXDOMAIN.
- **B8.** `addrkind.PublicPrefix` treats a prefix that overlaps any non-public special-purpose row
  as not public, so an SPF term for a globally reachable exception inside one (`192.0.0.9/32`)
  gives no candidate.
- **B8.** A provider range that is only half in provider space is not covered by a behaviour test
  (the world's fixture cannot build one); the unit test covers a range whose first address alone
  is shared.
- **B8 / D19.** The placement rule is tested for `spf` and `rdap` candidates, not for `org-asn`
  ones or under `nyx recon export`, which use the same `placeNetblock`.
- **B12.** The doc tests check that `docs/output.md` names MX and the names below the roots, and
  that `docs/candidates.md` lists `spf` as a family of its own; the rest of D24's wording is not
  tested.

# Verification

## Result

Checked against the base `179a47d` (35 files, the three spec files included). `go test ./...`
passes apart from `TestSetup_FailedSaveKeepsTheEdits`, which fails on the base too (`## Develop`,
`docs/todo.md`); `make lint` reports 0 issues. Nothing was changed before the code review.

- **Goal.** Met. A subdomain's NS, MX and TXT records are rows of `resolutions.csv`; a name only a
  record mentions, and the in-scope target of an in-scope CNAME, become hostnames and are resolved
  and asked in the same invocation; a root's `ip4:` range is a `netblock` candidate.
- **B1.** Met. `recordNames` (in `records.go`) takes `View.RecordNames` (in scope, under a root,
  not a root, not wildcard-only, no CNAME of its own), keeps a name once `resolve` has completed it,
  it has no NXDOMAIN `unresolved` record and its zone's wildcard check is done, and adds the parents
  that have no hostname record. `dnsroot` has `<root>|MX`. The NXDOMAIN parent noted under
  `## Known limitations` agrees with B1 as written (a parent that does not resolve is asked), and
  a parent job never writes an `unresolved` record, so there is nothing to filter on.
- **B2.** Met, for subdomains, roots (every type, D9) and included domains: `recordInput.owned`
  keeps `a.Name == name` only.
- **B3.** Met: rows per type, the root's MX, included domains' TXT only, the null MX, and the
  Shodan MX claim merged through the host-only index in `resolutionRows`.
- **B4.** Met. `recordHost` is the one predicate for NS, MX, SOA and SRV targets, CNAME targets
  (`cnameHost`) and names in TXT; `dnsname.HostnamesIn` reads maximal runs, so the `evil.net` and
  `_dmarc` cases give nothing. An in-scope `include:` domain with no `_` label is written in a TXT
  value, so B4 makes it a hostname as well as an included domain; D5's "not a hostname" holds for
  the inclusion itself.
- **B5.** Met: `ns`, `mx`, `txt-verification` and `spf` rows under the input root, `spf` at the
  depth of the record, redirect beside `all` ignored, nothing outside scope asked. A root's `mx`
  and `spf` rows are `email`'s alone (D26).
- **B6.** Met: `nsreverse` takes only an input root's NS rows; `resolutions.csv`'s `self_hosted`
  is filled for roots only.
- **B7.** Met: a listed name with a current NS row of its own gets SOA, CAA and the SRV list on the
  next pass of the same invocation, with SERVFAIL as a result; no email posture.
- **B8.** Met: `+` terms only, /16 and /32 limits, `addrkind.PublicPrefix`, the shared-range rule
  of D2, included in-scope domains followed lazily by `includedDepths`, `spf` as its own family
  with the asked name as the item, and `placeNetblock` hiding any netblock candidate inside an
  in-scope netblock (`Scope.InsideNetblock`, which mixes IPv4 and IPv6 prefix lengths in one sorted
  list correctly, since a prefix of the other family is never in the set).
- **B9.** Met: no procedure reads netblock candidates; the passive and `--authorised` canary test
  passes.
- **B10.** Met: `servFailFails` is false for every `dnsrecords` job, including the SRV list; a
  timeout fails one name's one type; roots still fail on SERVFAIL.
- **B11.** Met: `ThirdParty` contact, DNS only.
- **B12.** Met: `docs/output.md`, `docs/candidates.md`, `docs/sources.md` (`## Records of every
  name`, and the parent sentence inside `## Name guessing`) and `docs/todo.md` say what D24 asks.

External facts: the four live DNS facts were re-checked on 2026-11-26 with the spec's `dig`
commands against 1.1.1.1, 8.8.8.8 and 9.9.9.9 and hold (`www.github.com TXT` answers the CNAME and
`github.com`'s records; `docs.github.com NS` is NOERROR with only an SOA in authority;
`corp.google.com NS` answers four NS records owned by the name; `www.dnssec-failed.org NS` is
SERVFAIL). The SPF grammar was read in RFC 7208 (sections 4.5, 4.6.1, 4.6.2, 5.1, 5.6 and 6.1)
and holds as stated. The RFC also says (section 5.1) that mechanisms after `all` must be ignored,
which the spec does not mention: an `ip4:` written after `-all` still gives a candidate, and
`email`'s own walk also reads terms after `all` (see `# Follow-ups`).

## Code review

`/code-review high --fix` ran on the changed files. Its written report never reached this session
(the review agent finished without handing one back), so this section rests on the working tree:
the review made one edit, in `internal/recon/procedures/dns/records.go`.

- **Left unfixed (undone by hand): `recordInput.target` dropped a target whose registrable domain
  is the root's own.** It touched B5 and D12 (and `dnsroot`'s NS and SRV targets). For an input
  root below a registrable domain (`corp.example.com`), an NS or MX target `ns1.example.com` is
  outside scope, and B5 makes it an `ns` or `mx` row with the domain `example.com`; the edit
  removed that row, and changed what `dnsroot` already wrote for such a root. Where the root is
  the registrable domain, the row it aimed at is already hidden by the third-party kind's
  visibility. D15's "not under the root's registrable domain" rule is for `spf` domains only.
  Put to the user under `# Follow-ups`.

Nothing else changed. After the undo, the `dns` package tests and the `dnsrecords`, SPF candidate,
`dnsroot`, `nsreverse` and `email` behaviour tests pass. `make test` (with `-race`) fails only on
`TestSetup_FailedSaveKeepsTheEdits` and `TestActive_EndToEnd`, which fail on the base too and are
in `docs/todo.md`; `make lint` reports 0 issues. The new behaviour tests passed 5 times in a row
(`-count=5`).

The review's full report reached this session after verification. Besides the edit above it had
four findings, settled as follows: wildcard-answered parents are asked (D11, D25); a listed
included domain's depth is 0 (D29, docs fixed); no job retirement (D25); `PublicPrefix` stricter
than `Of` (`## Known limitations`, `docs/todo.md`).

# Follow-ups

Settled earlier: provider ranges in SPF by D2; the split by D7 (SPF addresses stay in this spec).

- **SPF terms after `all`:** ignored (D27).
- **A target in the root's own registrable domain:** kept as B5 says (D28).
- **Depth of a listed included domain:** kept as D16 says, docs fixed (D29).
- **`addrkind.PublicPrefix` stricter than `Of`:** in `docs/todo.md` under Design changes.
- **Test gaps (B8, D19, B12):** in `docs/todo.md` under CI improvements/fixes.
- **`TestSetup_FailedSaveKeepsTheEdits`, `TestActive_EndToEnd`:** fail on the base too; already in
  `docs/todo.md`.

**Manual steps:**

1. **A live run** against a large domain you are authorised to test, to see what the new lookups
   cost: `nyx recon --passive --output-dir /tmp/nyx-live <root>`, then compare the `resolve` and
   `dnsrecords` lines of the summary and the run time with `--skip dnsrecords`. There is no cap
   (D10): expect about 3 lookups per hostname that is not an alias, and 16 more per delegated zone.
