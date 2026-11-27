# Spec 4 of 4: Candidate names on in-scope addresses

## Goal

A hostname outside the input roots that is served from an address the user already put in scope
enters scope on its own, as bbot does, so that the other names hosted on an organisation's
netblocks are probed and reported without the user promoting each one. Because of it, nothing
outside the in-scope netblocks receives anything but DNS lookups through the public resolvers.

This changes a rule nyx has held until now, that nothing enters scope on its own. It is the only
automatic promotion in the series: bbot's default does not follow related domains either, it only
promotes a name whose address is inside a target netblock.

Depends on: nothing. (Specs 1, 2 and 3 each say what they leave out for a name that entered scope
this way; B9 says the same here.)

Done when:

- a candidate hostname whose address is inside a `--cidr` netblock is listed in `scope.csv` and
  `subdomains.txt` and, with `--authorised`, probed at that address;
- the same name with promotion turned off stays in `candidates.csv` and is never resolved.

## Behaviours

- **B1 Candidate lookups.** While the engagement has an in-scope netblock, nyx asks the public
  resolvers for the A and AAAA records of each current candidate hostname and candidate root in
  `candidates.csv` that a source other than `in-netblock` found, in the file's order, up to a
  per-run cap, `in_netblock.max_lookups` (`--in-netblock-max-lookups`, default 1,000, at least 1).
  The rest are deferred, not failed, and counted under `Deferred to the next run`. A candidate is
  asked once per engagement and again only after `--redo in-netblock`, which also asks again each
  name in scope by address; a candidate that stops being current and is found again later is asked
  again. A candidate looked up before a netblock entered scope is judged against it without being
  asked again. A candidate is still never contacted. (amended by D4, D7, D9)
- **B2 Reverse-IP hostnames.** For an address inside an in-scope netblock, each hostname
  `reverseip` returns that is under no in-scope root is kept as a candidate hostname, as well as
  its registrable domain as a candidate root. For any other address, and above
  `reverseip.max_domains`, `reverseip` behaves as today. An address `reverseip` asked before a
  netblock holding it came into scope is asked once more. (amended by D2)
- **B3 Rule.** A candidate with at least one address inside an in-scope netblock (a `--cidr` input
  or a netblock of an `--asn` input) enters scope.
- **B4 Root names.** A candidate root whose own name meets the rule enters scope as one hostname,
  and stays a candidate root in `candidates.csv`: passing it as a domain is still how its
  subdomains are enumerated.
- **B5 Generic names.** A name that contains the decimal octets of an IPv4 address it resolves to,
  in forward or reverse order, separated by `.` or `-`, with or without zero padding
  (`203-0-113-5.static.example.net`, `5.113.0.203.example.net`, `203-000-113-005.example.net`),
  never enters scope this way. Names are not tested against IPv6 addresses.
- **B6 Shared hosting.** An address with more than a set number of names whose looked-up addresses
  include it (`in_netblock.max_names_per_address`, `--in-netblock-max-names-per-address`, default
  100, at least 1) brings none of them into scope, and a WARN line names the address. The count is
  of names that are candidates or in scope by address. Until an address passes the setting, its
  names enter scope as their lookups come in; when it passes the setting after it brought names
  in, every name it brought in leaves scope (B11). A name that also has another qualifying address
  still enters scope through that one. (amended by D1, D4)
- **B7 In scope.** A name that entered scope this way is listed in `scope.csv` with the address and
  netblock that brought it in, is in `subdomains.txt`, is no longer a candidate hostname row of
  `candidates.csv`, and is probed, crawled, port-checked and checked for findings like any in-scope
  hostname, except that it gets no origin check and no origin finding, and identifiers found only
  on its pages are not pivoted on. Its rows in `resolutions.csv` and `ips.csv` come from its
  candidate lookup: `resolve` does not ask it again. Wildcard rules apply to it as to any in-scope
  name. (amended by D3, D5, D10)
- **B8 Addresses.** It is contacted only at its addresses inside in-scope netblocks. An address of
  its outside every in-scope netblock is listed in `ips.csv` but is never dialled for it and does
  not become port-eligible because of it.
- **B9 Only the name.** Its registrable domain does not become a root: no source is asked about it,
  no name is guessed or learned under or beside it (the wildcard check of a zone that is itself in
  scope by address is the one exception), its parents are not resolved, it is not asked for the
  records Spec 2 adds, it gives no `third-parties.csv` row, and names under its registrable domain
  that appear in response text stay ignored. Its other names stay candidates until B3 brings each
  in. The registrable domain is a candidate root in `candidates.csv`, with this as evidence from a
  new source, `in-netblock`, a family of its own; a root only `in-netblock` found is not itself
  looked up (B1). (amended by D6, D9, D10)
- **B10 Exclusions.** An excluded name, or one that resolves into an excluded CIDR, never enters
  scope.
- **B11 Leaving.** A name stays in scope only while the rule holds. When, after `--redo
  in-netblock` or a change of scope, the addresses of its candidate lookup no longer fall inside an
  in-scope netblock, or the name is excluded, or no source but `in-netblock` finds it any more (a
  job about a name in scope by address does not count), it is a candidate (or excluded, or gone)
  again, its records stop being shown or stop being current, and `changes.csv` reports it.
  (amended by D3, D9, D25)
- **B12 Setting.** Promotion is on by default. `in_netblock.enabled: false` (`--no-in-netblock`)
  turns it off: candidates are then not looked up and none enters scope, and names that had
  entered scope this way are candidates again. Lookups already made are kept, unless
  `--redo in-netblock` is given while it is off, which discards them. (amended by D4, D13)
- **B13 Authorisation.** Entering scope does not relax the passive boundary: without
  `--authorised`, or under `--passive`, such a name is listed and resolved but not contacted.
- **B14 Reported.** The summary gives the number of hostnames in scope by address, and the `--json`
  envelope carries the same number under a new key.
- **B15 Documented.** `docs/passive-boundary.md` says candidate hostnames and roots are looked up
  through the public resolvers and never contacted; `docs/sources.md` and `docs/candidates.md` no
  longer say of hostnames that nothing enters scope on its own or that no candidate is resolved
  (which replaces the tested statement "No candidate root is resolved"); `docs/candidates.md` lists
  the `in-netblock` source; `docs/output.md` describes the new `scope.csv` rows;
  `docs/configuration.md` lists the three new settings.

## Out of scope

- Bringing a candidate into scope on its confidence alone, and enumerating candidate roots through
  third-party sources. Declined: the user chose bbot's rule (an address inside an in-scope
  netblock) and nothing wider.
- Promoting candidate hostnames only. Declined: a candidate root's own name enters scope too, and
  its root row stays.
- Leaving `reverseip` as it is. Declined: it keeps the hostnames on in-netblock addresses, since
  they are the names this spec exists to find.
- Promotion with no shared-hosting guard. Declined: the guard is 100 names per address.
- Testing names against IPv6 addresses for the generic-name rule.
- PTR lookups for addresses outside in-scope netblocks. Declined by the user.
- Engagements created before this change. The user will start fresh engagements.
- Holding an address's names back until every candidate has been looked up (D1). Declined: the
  names enter as their lookups come in and leave if the guard trips.
- Storing the hostnames of every address `reverseip` asks, and a `--redo reverseip` caveat (D2).
  Declined: an affected address is asked once more.
- `resolve`'s answer deciding whether a name stays in scope (D3). Declined: the candidate lookup
  alone decides, and no second DNS lookup is made.
- Origin checks and origin findings for a name in scope by address (D5).
- Looking up a root that only `in-netblock` found (D9). Declined: the user passes it as a domain.
- Pivoting on identifiers seen only on the pages of names in scope by address (D10).
- The listing of a name's rows using a place of the lookup cap (D8). Declined: it is exempt.

# Design

## External facts

- **HackerTarget's reverse IP lookup** (`https://api.hackertarget.com/reverseiplookup/?q=<ip>`,
  one name per line, a text reply when the free quota is spent). *From code*, not re-confirmed:
  `ipsource.ReverseLines` and `internal/recon/procedures/reverseip` already parse it and their
  tests pin the shapes; `hackertarget.com` answered 403 to an automated fetch on 2026-11-27. This
  spec changes no request and no parsing. D2 adds one request per address that was asked before
  its netblock came into scope. The size of the free daily quota is *assumed* small and was not
  confirmed; it changes only how many runs D2's repeat requests take (see Follow-ups).
- **SecurityTrails' reverse-IP search**, used by `reverseip` when keyed. *From code*, unchanged.
- **A DNS answer's addresses and CNAME chain** come from `egress.DNSResult` (`Addrs()`, `CNAMEs`),
  as `resolve` reads them today. *From code.*
- **The registrable domain** of a name is `dnsname.ETLDPlusOne` (the embedded public suffix list).
  *From code.*
- **bbot's behaviour**, as the Goal describes it. *Assumed*; no decision rests on it.
- No external data is embedded.

Facts about this codebase the plan rests on, checked on 2026-11-27:

- Scope is rebuilt from records on every read (`run.BuildScope`, `internal/recon/run/scopebuild.go`)
  and nothing stores a hostname's class. `scope.ClassifyHost` (`internal/scope/scope.go`) gives
  InScope only under a root. The runner rebuilds scope when the version of a kind in `scopeKinds`
  changes, after any procedure does work, and at the start of each pass.
- `View.ResolvableHostnames` (`internal/recon/run/procedure.go`) leaves candidates out, so no
  candidate is resolved today. Candidate hostnames are `hostname` records under no root: from
  `httpprobe` (redirect hosts and certificate SANs), `rdns` (PTR names) and `shodan` (netblock
  search). Candidate roots are `root` records: from `reverseip`, `shodan-host`,
  `identifier-pivot`, `nsreverse` and the organisation pivots.
- HTTP to a hostname dials every recorded address of it: `Policy.vetted`
  (`internal/egress/http.go`) drops only excluded and non-public addresses, and reads
  `Scope.Addrs`, which is the recorded A and AAAA rows. Nothing resolves at dial time. TCP and TLS
  check `scope.PortEligible` per address; `scope.New` makes every address of an in-scope,
  non-wildcard-only name port-eligible (`hostAddrs`) when its owner is known and not shared.
- `ips.csv` has a row for every `ip` record and every address of a resolved name that is not
  excluded (`inventory.namesByIP`); `resolutions.csv` lists every `resolution` record with no
  scope filter and the source `resolve` (`resolutionRows`, `internal/recon/output/output.go`).
- A candidate's evidence is its completed jobs: `Store.Observers` joins the `jobs` table, so a
  record an analysis writes with `Store.Put` carries none. `Families.Of` gives an undeclared
  source a family of its own.
- A `Retiring` procedure's completed jobs that `Jobs` no longer lists are swept with their
  observations after a successful enumeration (`procedureRun.sweep`); deferred jobs stay listed,
  and a cancelled run skips the sweep. `Store.Complete` replaces a job's earlier observations.
  `--redo` deletes the procedure's completion markers and sweeps what is not listed again.
- A `Budgeted` procedure's first deferred job defers every later one, and a job's cost of zero
  counts as one (`procedureRun.withinBudget`).
- `changes.csv` keys each entry by its placement label (`entriesOf`,
  `internal/recon/run/changes.go`), so a name that moves between candidate and in scope already
  gives a `gone` row and a `new` row.
- `nyx recon export` builds scope with `run.BuildScope` from a read-only snapshot and loads only
  the config file, not the flags of the last run (`internal/cli/export.go`).
- `kinds.All()` feeds the export and the root help; a test requires every kind name in the help.

## Decisions

Decided by the user:

- **D1 Guard timing (B6).** A name enters scope as soon as its lookup is in. If later lookups push
  its address over the guard, every name that address brought in leaves, and `changes.csv` reports
  it. Why: only an address inside a netblock the user put in scope is dialled, the guard already
  sees a whole pass of up to 1,000 lookups before anything is probed, and waiting needs a record
  of every unanswered lookup and stalls on one that keeps failing.
- **D2 Reverse IP asked before the netblock (B2).** `reverseip`'s job key gains the suffix
  `|names` when the address is inside an in-scope netblock (`"<addr>|max=<n>|names"`), so such an
  address gets one new job. `Evidence` already cuts the key at the first `|`, so support is not
  counted twice. Cost: one more request per affected address. The names such a job kept stay
  candidates if the netblock later leaves scope (`reverseip` is not `Retiring`); accepted.
- **D3 Which lookup decides (B11).** The candidate lookup's addresses alone decide. The
  `in-netblock` procedure lists the name's own rows (D14) and `resolve` never asks it (D15).
- **D4 Names.** `in-netblock` is the procedure, the candidates source and the settings group:
  `in_netblock.enabled` (`--no-in-netblock`), `in_netblock.max_lookups`
  (`--in-netblock-max-lookups`, default 1,000, at least 1) and
  `in_netblock.max_names_per_address` (`--in-netblock-max-names-per-address`, default 100, at
  least 1).
- **D5 No origin checks (B7).** `origin.FrontedHosts` (`internal/recon/origin/records.go`) leaves
  out a name in scope by address. That one rule stops `dnshistory` asking SecurityTrails about it
  (B9), `origincheck` sending its Host header to an address that is not its own (B8), and the
  origin finding.
- **D6 Wildcards (B7, B9).** `wildcardZones` (`internal/recon/procedures/dns/wildcard.go`) is
  unchanged: a zone is checked when it is itself in scope, which now includes a zone in scope by
  address. A parent that is not in scope is never checked, so a `*.hosting.example` wildcard that
  points into a netblock is held back only by B6.
- **D7 B1's wording.** `--redo in-netblock` also asks again each name in scope by address, and a
  candidate that stops being current and is found again is asked again (its lookup was retired).
- **D8 The cap counts lookups only (B1).** `run.Job` gains `Unbudgeted bool`; `withinBudget`
  admits such a job without charging or deferring it. The job that lists a name's rows (D14) is
  unbudgeted, so a name whose lookup lands in a netblock is listed and probed in the same run
  however many candidates are waiting. This replaces the user's earlier answer that it would use
  a place of the cap, given before D14 removed its DNS lookup.
- **D9 Roots only `in-netblock` found (B1, B9, B11).** A candidate is looked up only when a
  producer other than `in-netblock` observes its `hostname` or `root` record
  (`inventory.FoundByOther`). So the registrable domain of a name in scope is listed with
  `in-netblock` evidence and never looked up on that evidence, and a name whose only remaining
  support is its own promotion loses its lookup and leaves scope.
- **D10 No identifier pivot (B7, B9).** `identifier-pivot`'s `Jobs`
  (`internal/recon/procedures/shodan/pivot.go`) counts a web service as pivotable only when its
  host is not in scope by address. An identifier also seen on another pivotable service is still
  sent.

Decided from the codebase:

- **D11 The rule lives in `scope`, derived on read (B3, B5, B6, B10).** `scope.Config` gains
  `Lookups map[string][]netip.Addr` (the candidate lookups' addresses by name; nil when promotion
  is off) and `MaxNamesPerAddress int`. `scope.New` works out, for each name in `Lookups` that is
  under no root and matches no name exclusion:
  - it never qualifies if any of its lookup addresses is inside an excluded CIDR (B10), or if the
    name is generic (D19) for any of its IPv4 lookup addresses (B5);
  - an address counts for it when it is inside an in-scope netblock and at most
    `MaxNamesPerAddress` names of this set list that address (B6; generic names and names with an
    excluded address are still candidates, so they are counted);
  - the name is in scope by address when it has such an address; the lowest one, and the
    narrowest in-scope netblock holding it, are kept for `scope.csv`.

  New methods: `ByAddress(host) (addr netip.Addr, block netip.Prefix, ok bool)`;
  `SharedHosting() []netip.Addr` (the in-netblock addresses over the guard, sorted);
  `ClassifyName(host) Classification` (today's rule: exclusions and roots, never in scope by
  address); `DialAddrs(host) []netip.Addr` (D16). `ClassifyHost` keeps its order and adds one
  step: name exclusion, a resolved address in an excluded CIDR, under a root, `ByAddress`, else
  candidate. `RootOf` is unchanged, which is what Specs 1 to 3 rely on. `ByAddress` implies
  `ClassifyHost` gives InScope (a unit test holds this), because the name's resolved rows are
  written from the same lookup (D14). Why here: scope, inventory and findings are pure functions
  of current records, and a netblock added later must apply without a new lookup (B1).
- **D12 A kind of its own for the lookups.** `kinds.CandidateLookup`, named `candidate_lookup`,
  keyed by the name, with the attributes `addrs` (sorted strings) and `cnames` (a list of
  `{"name", "target"}` links, in answer order). It has no category, is in no file and is not
  printed. It joins `scopeKinds`, so the scope signature and the candidate-rank analysis follow
  it. Why not `resolution` and `ip`: those would put every unpromoted candidate's addresses in
  `ips.csv` and `resolutions.csv` and into port eligibility. These attribute names are a stable
  interface from now on.
- **D13 The `in-netblock` procedure** (`internal/recon/procedures/dns/innetblock.go`, on the
  package's `base`: third-party contact, no sources, so it runs under `--passive`). It implements
  `Budgeted` (`in_netblock.max_lookups`), `Retiring`, `Evidencer` and `CandidateSourcer`
  (`{"in-netblock": "in-netblock"}`, as `rdns` declares itself, so the docs test of
  `candidates.md` requires the source). Two kinds of job:
  - a lookup job, key `<name>`, cost 1: A and AAAA through `lookup()`. A timeout is an error and
    is retried on the next run. Any other answer completes the job, with one `candidate_lookup`
    observation when there is an address and none otherwise.
  - a rows job (D14), key `in|<name>|<hash>`, unbudgeted (D8). `Evidence` of such a key is
    (`in-netblock`, `<name>`); a lookup key gives nothing that is a candidate.

  `Jobs` yields, in this order: the rows jobs, sorted; the lookup jobs of names in scope by
  address, sorted (so `--redo` refreshes them first and retirement keeps their lookups); then the
  lookup jobs of the current candidate hostnames and roots in `candidates.csv` order. A name is
  listed only if D9 holds for it, it is under no root and `ClassifyName` gives candidate. The
  order comes from a new `View.Candidates()`: membership from the candidate kinds and
  `Visibility.Category`, as `candidateRows` takes it, and the rank only for order, through one
  comparison in the `candidates` package that `output/candidates.go` uses too. When promotion is
  off, or the scope has no netblock, `Configured` still answers true and `Jobs` yields only the
  lookup keys that are already done (`v.Done`), and no rows job: nothing is asked, the lookups are
  kept and every rows job is retired, so the names' rows stop being current (B12). A "disabled"
  state would skip the sweep and leave those rows current. `--redo in-netblock` while off empties
  the done set, so the lookups are swept and made again once it is on (B12 says so).
  `--skip in-netblock` leaves promotion on: names already in scope stay, nothing new is looked up
  or listed. `Jobs` also calls `v.Warn` once per address of `SharedHosting()`, with a text that
  names the address and the setting and has no count in it, since the runner prints each distinct
  text once per run.
- **D14 One lookup, and rows written from it (B7, B8, B11).** `resolve()` in
  `internal/recon/procedures/dns/resolve.go` is split into the part that asks (giving an answer:
  addresses and CNAME links) and the part that turns an answer into observations. `resolve` uses
  both. The lookup job stores the answer; the rows job receives it in its `Input`, from the
  current `candidate_lookup` record, asks nothing, and returns the same observations `resolve`
  would (`resolution` rows for the addresses and links, an `ip` per address, a hostname for an
  in-scope target of a link under `cnameHost`'s rule) plus `kinds.Hostname.Obs(name)` and, when
  the registrable domain is not the name itself, `kinds.Root.Obs(registrable domain)`. `<hash>` is
  a short hash of the answer, so a changed lookup gives a new rows job and the old one is retired.
  Why: one answer then decides membership, the listed rows and what is dialled; a second lookup
  could disagree with the first (round-robin DNS) and, by making the name excluded, unlist its own
  job in an endless loop of passes. The `hostname` observation is what gives a promoted candidate
  root its hostname record (B4), and the `root` observation gives B9's evidence from a real
  completed job, which disappears when the job is retired. Because the procedure is `Retiring`, a
  name that leaves scope loses its rows job, so those observations stop being current (B11), and
  it is listed again if it re-enters.
- **D15 `resolve` never asks it.** `View.ResolvableHostnames` skips a name with `ByAddress` true.
- **D16 Only its in-netblock addresses are dialled (B8).** Three places:
  `Scope.DialAddrs(host)` gives, for a name in scope by address, its resolved addresses that are
  inside an in-scope netblock, and `Addrs(host)` for any other name; `Policy.vetted` reads it.
  `scope.New`'s `hostAddrs` loop skips names in scope by address, so their other addresses never
  become port-eligible (the in-netblock ones already are, by the netblock). `View.HostsFor`
  indexes by `DialAddrs`, so `httpprobe`'s pinned requests never choose such a name for an address
  it may not be dialled at, which would lose the request for the name that may.
- **D17 A candidate root stays one (B4).** `kinds.Root`'s placement uses `ClassifyName`, so a
  candidate root in scope by address keeps its row in `candidates.csv` while its `hostname` record
  is placed in scope. `Visibility.outside` uses `ClassifyName` too, so a third party whose domain
  is in scope by address is still shown.
- **D18 Guards for B9.** Each asks whether the name has a root, as `ParentNames`, `Learnable`,
  `RecordNames`, `recordHost`, `takeable` and `thirdparty.CNAME` already do:
  `inventory.Seeds` (no permutations beside it); `includedDepths` in `dns/records.go` (an SPF
  include is not asked for TXT); `hostnames` in `github/github.go` and `record` in
  `shodan/dns.go` (a name is taken only under a root); `nameObs` in `shodan/host.go` and `Run` in
  `reverseip.go` treat a name as a hostname only when it is under a root or excluded, so what they
  record for a name does not change when it enters scope.
- **D19 The generic-name rule (B5)** is a pure function in `internal/knowledge/dnsname`: for an
  IPv4 address, the name is generic when it holds four runs of one to three digits, joined by `.`
  or `-` (each separator either), not touching another digit at either end, whose values are the
  four octets forwards or backwards. Leading zeros are allowed.
- **D20 The settings reach every reader of the engagement.** The runner writes the run's
  `in_netblock.enabled` and `in_netblock.max_names_per_address` to the store's `meta` table before
  its first scope build; `ScopeSource` gains `Meta(key)`, `store.Reader` a `Meta` method, and
  `BuildScope` reads the two values from it (absent: on, 100). Why: scope now depends on settings,
  and `nyx recon export` loads only the config file, so after a run with `--no-in-netblock` it
  would otherwise class names differently from the files that run wrote. The settings themselves
  follow the existing recipe in `internal/config/config.go` (struct, `Defaults`, `settingTable`
  for the two numbers, `RegisterFlags`, `rawSettings`, `setDefaults`, `numbers`, and `choices` for
  the switch as `permutations.enabled` and `--no-permutations` do).
- **D21 `scope.csv` (B7).** One row per current `hostname` record with `ByAddress` true: type
  `hostname`, value the name, source `<address> in <netblock>` (`scopeRows`). `changes.csv` needs
  nothing new.
- **D22 The count (B14).** A new `Summary` field, JSON key `hosts_in_scope_by_address`, the number
  of current `hostname` records with `ByAddress` true, following `unconfirmed_risky_ports`
  (`report/summary.go`, the copy in `envelope.go`, `run/result.go`), with the console line
  `N hosts in scope by address` when it is above zero.
- **D23 Registry and help.** `dns.NewInNetblock()` goes after `rdns` and before `ipowner` in
  `defaultProcedures()`, which keeps the pinned orders (`dnsrecords` between `learned-names` and
  `rdns`; the tail from `ipowner` to `ports`). Its ordering comment, a `procedureHelps` entry and
  the golden help files follow.
- **D24 Left as they are.** The `source` column of `resolutions.csv` says `resolve` for every
  answer nyx got itself, these rows included. Egress's third-party client still refuses a source
  host that is in scope, now possibly by address.

Settled after verification:

- **D25 Support from names in scope by address (B9, B11).** An observation made by a job about a
  name in scope by address (an httpprobe of it, say, recording the names its certificate or
  redirects give) does not count as a source other than `in-netblock` finding a name, so two such
  names that name each other cannot keep each other in scope. The names it records stay listed as
  candidates. A job counts as about such a name when its procedure contacts targets and its key
  names a hostname under no input root (judged by the root, so it holds after the name leaves
  scope). `View.Observers` gives the procedure each record's supporting jobs.
- **D26 The summary line (B14).** It reads `1 host in scope by address` for one, and
  `N hosts in scope by address` otherwise, through `layout.Plural` (amends D22's wording).

## Files

- `internal/scope/scope.go`, `scope_test.go`: D11, D16.
- `internal/knowledge/dnsname/dnsname.go`, `dnsname_test.go`: D19.
- `internal/recon/kinds/candidatelookup.go` (new), `table.go` (D17), `visibility.go` (D17).
- `internal/recon/run/scopebuild.go`: `scopeKinds`, the lookups and the two meta values into
  `scope.Config`, `ScopeSource.Meta` (D12, D20). `runner.go`: write the meta values (D20).
  `procedure.go`: `Job.Unbudgeted` (D8), `View.Candidates()` (D13), `ResolvableHostnames` (D15),
  `HostsFor` (D16). `procedurerun.go`: `withinBudget` (D8). `result.go`: D22.
- `internal/recon/store/store.go`: `Reader.Meta` (D20).
- `internal/recon/analysis/candidates/candidates.go`: the shared row comparison (D13);
  `internal/recon/output/candidates.go` uses it.
- `internal/recon/procedures/dns/innetblock.go` (new) and a test beside it; `resolve.go`: the
  split of D14.
- `internal/recon/procedures/reverseip/reverseip.go`: D2, D18, and its doc comment.
- `internal/recon/procedures/shodan/host.go`, `dns.go`, `pivot.go`;
  `internal/recon/procedures/github/github.go`; `internal/recon/procedures/dns/records.go`;
  `internal/recon/inventory/inventory.go` (`Seeds`); `internal/recon/origin/records.go`: D5, D10,
  D18.
- `internal/egress/http.go`: `vetted` (D16).
- `internal/recon/output/output.go`: `scopeRows` (D21).
- `internal/recon/report/summary.go`, `envelope.go`: D22.
- `internal/config/config.go`, `config_test.go` (`TestIntSettings` rows, a test of the switch).
- `internal/cli/cli.go` (registry and its comment), `procedures_topic.go`, `export.go`
  (`snapshotSource.Meta`), `testdata/plain/help-*.txt` (regenerate with
  `go test ./internal/cli/ -run 'TestPlain_|TestHelp_PlainJoin' -update-plain`).
- `internal/cli/innetblock_test.go` (new): the behaviour tests below.
- Existing tests that assert a candidate is never resolved, to re-read: those with a `--cidr` in
  their world now see a lookup of the candidate (`TestParentNames_NoParentOfACandidateIsQueried`
  uses `--cidr 198.51.100.0/30`); those without one must stay green unchanged
  (`TestReverseIP_RootOnTwoAddressesIsMedium`, `TestNSReverse_NothingFoundIsContacted`).
- `docs/passive-boundary.md`, `docs/sources.md` (lines near 7, 80 to 85 "the hostname itself is
  not kept", 96, 194 and 205), `docs/candidates.md`, `docs/output.md`, `docs/configuration.md`,
  `docs/commands.md` if it lists flags, `CLAUDE.md` (the registry notes, `Job.Unbudgeted`, the
  rule that scope reads two settings from `meta`).

## Tests

Harness: the web world in `internal/cli/web_helpers_test.go` (`newWeb`, `x.host`, `x.plain`,
`x.secure`, `mapTo`, `x.fill`, `x.run`, `x.mustRun`, `x.passive`, `x.candidate`, `site.hits()`,
`hostHeaders()`), the fake DNS (`w.dns.A`, `CNAME`, `PTR`, `Wildcard`, `Count`, `Queried`), the
reverse-IP fake (`x.hackerTarget().set`, `x.htAsked()`), `deferredOf` in `budget_test.go`, and the
canaries (`h.network()`). `TestProbeIP_ANameWinsOverTheIP` is the template for a `--cidr` world.
Candidates come from a PTR name (`rdns`), a certificate SAN or redirect (`httpprobe`) and
`reverseip`. Because scope is derived on read, a promotion usually completes within one run: no
test asserts "on the next run" except where a cap or `--redo` makes it so.

- **Unit, `scope` (B3, B5, B6, B10, B8; mutation check).** A table over `scope.New`: an address
  in a `--cidr` and in an ASN netblock qualifies; outside does not; a name under a root is never
  `ByAddress`; a name exclusion, and any lookup address in an excluded CIDR, stop it; a generic
  name is stopped but counted; 100 names on one address all qualify and 101 give none and
  `SharedHosting` names the address; a name with a second qualifying address stays; `Lookups` nil
  gives none; `ByAddress` true implies `ClassifyHost` InScope and `ClassifyName` candidate;
  `DialAddrs` of a two-address name gives only the in-netblock one and of a rooted name gives
  all; `PortAllowed` is false for the outside address of a name in scope by address with a known,
  dedicated owner, and true for the same address of a rooted name.
- **Unit, `dnsname` (B5; mutation check).** The three forms of B5; reversed with `-`; mixed
  separators; `1203-0-113-5` and `203-0-113-50` are not generic for `203.0.113.5`; `0203` (four
  digits) is not; an address whose octets appear in another order is not; a name with no digits.
- **Unit, the procedure.** The rows job returns exactly what `resolve` returns for the same
  answer, plus the hostname and the root; no root observation when the name is its own
  registrable domain; the key changes with the answer; `Evidence` of both key forms.
- **Unit, `run`.** An unbudgeted job is admitted after the budget is spent and after another job
  was deferred, and adds nothing to the deferred count.
- **B1.** With no netblock, no candidate is looked up (`w.dns.Queried`). With one, each candidate
  hostname and root is asked A and AAAA once; a second run asks nothing; the order of the lookups
  is the order of `candidates.csv`; with `--in-netblock-max-lookups 2` and five candidates, two
  are asked, `deferred` has `in-netblock: 3`, and later runs finish the rest; `--redo in-netblock`
  asks again, names in scope included; a candidate dropped by `--redo` of its source and found
  again is asked again; a netblock added on a later run brings a looked-up name in with no new
  lookup; the canaries see nothing for any candidate (mutation check). A root that only
  `in-netblock` found is never asked (D9).
- **B2.** An address inside the `--cidr`: the returned names under no root are `hostname`
  candidates and their registrable domains `root` candidates; an address outside it: roots only,
  as today; above `reverseip.max_domains`: nothing, as today; an address asked on a run without
  the `--cidr` is asked exactly once more after it is added, and its support is still one item.
- **B3, B4, B7.** A PTR-found name and a reverse-IP root that resolve into the `--cidr`:
  `scope.csv` has the `hostname` rows with `<address> in <netblock>`; both are in
  `subdomains.txt`; the hostname's candidate row is gone and the root's stays; `resolutions.csv`
  and `ips.csv` have their rows; `resolve` asked neither (`Count` is one A and one AAAA each);
  with `--authorised` the fake site at the in-netblock address gets the request with the name as
  Host. With a cap smaller than the candidate count, a name found in this run is still probed in
  this run (D8).
- **B5.** The three generic forms stay candidates and are not probed; a near miss enters scope.
- **B6.** 100 names on one address enter; with a 101st none does and one WARN names the address
  (events and `--json` warnings); a name with another qualifying address stays in; with a cap that
  spreads the lookups over two runs, the names that entered on the first leave on the second and
  `changes.csv` has their `gone` hostname and `new` candidate rows; a `*.hosting.example` wildcard
  into the netblock whose zone is not in scope is held only by the guard (D6).
- **B8 (mutation check).** A name with one address in the `--cidr` and one outside, each with a
  listening fake: only the in-netblock one is hit, on probe, crawl and ports; the outside address
  is a row of `ips.csv` with `port_eligible` no; a rooted name on the same outside address is
  still probed there.
- **B9.** For a name in scope by address: no subdomain source, `dnshistory` or Shodan pivot
  request names it or its identifiers; no learned-name, permutation, parent, NS, MX or TXT lookup
  under or beside it; no `third-parties.csv` row; a name under its registrable domain in a page it
  serves is not a hostname; its registrable domain is a `root` candidate with the source
  `in-netblock`. When the zone itself is in scope by address and has a wildcard, the names under
  it that only the wildcard answers are wildcard-only and one representative is probed.
- **B10 (mutation check).** A name matching `--exclude`, and one whose lookup has an address in an
  excluded CIDR, are never in scope and never dialled; an exclusion added on a later run makes a
  name in scope leave.
- **B11.** After `--redo in-netblock` with the fake DNS now answering outside the netblock, and
  after an exclusion is added, and after the name's only other source stops finding it: the name
  is no longer in `subdomains.txt` or `scope.csv`, its `resolutions.csv` rows are not current, its
  web rows are not shown, the root loses its `in-netblock` evidence, and `changes.csv` reports it.
  A run in which the answer puts the name in an excluded CIDR ends (no endless passes).
- **B12.** With `--no-in-netblock` and with the config key: no candidate lookup, nothing in scope
  by address; names that had entered are candidates again and their rows not current; turning it
  on again asks nothing already asked. `--redo in-netblock --no-in-netblock` then a run with it on
  asks everything again. `nyx recon export` after a `--no-in-netblock` run classes the names as
  that run's files do (D20).
- **B13 (mutation check).** Under `--passive`, and without `--authorised`: the name is in
  `scope.csv`, `subdomains.txt` and `resolutions.csv`, and the HTTP and TCP canaries and the fake
  site count zero.
- **B14.** The summary line and `data.hosts_in_scope_by_address`, zero and non-zero.
- **B15.** Doc tests with `docsSection`/`docPage`: the passive-boundary sentence; `candidates.md`
  lists `in-netblock` (`TestCandidates_DocsListEverySource` requires it); `output.md` names the
  `hostname` rows of `scope.csv`; `configuration.md` has the three keys and flags; `sources.md` no
  longer says "No candidate root is resolved".
- **Settings.** `TestIntSettings` rows for the two numbers; the switch as
  `TestPermutationsEnabled` does; the help goldens; `--skip in-netblock` and `--redo in-netblock`
  are accepted, and `nyx help procedures` lists it.
- **Across behaviours.**
  - An error from a dependency: a DNS timeout fails only that candidate's lookup, the run exits 7
    and the next run asks it alone; SERVFAIL, NXDOMAIN and an empty answer complete the job. A
    HackerTarget quota reply behaves as today.
  - One item failing in a batch: the other candidates of the pass are still looked up and the
    ones that qualify enter scope.
  - Interrupt part-way: a run cancelled during slow lookups keeps the completed ones, retires
    nothing (the sweep is skipped), and the next run asks only the rest. No secret is involved:
    the procedure has no key.
  - Re-run after success: no DNS query, and the files are byte-identical. Re-run after the
    partial failure: the same end state as an uninterrupted run.
  - A crash point in the rows job (`in-job-tx`) leaves either all of a name's rows or none.

## Conventions

- `CLAUDE.md`: only `internal/egress` does network I/O (the new procedure uses `egress.Clients`'
  DNS client); the passive boundary (a candidate gets DNS lookups through the public resolvers
  only, and B8 narrows what is dialled for a name in scope by address); a procedure is
  `ThirdParty` or `Target`, never both; a `Job.Key` encodes what changes the work (D2's suffix,
  D14's hash); `Run` reports negative results as completed jobs; procedures read state only
  through `run.View`, and code outside a procedure never names one (`scope`, `inventory` and the
  runner ask `ByAddress`, never `in-netblock`; D9 passes the procedure's own name to
  `FoundByOther` from inside it); scope, inventory and findings are derived on read.
- Stable interfaces: this adds the kind `candidate_lookup` with `addrs` and `cnames`, the
  envelope key `data.hosts_in_scope_by_address`, three settings and three flags, and renames
  nothing. `scope.csv` columns are read by people and gain no column.
- Testing: `t.Parallel()` first; harness environment only; behaviour tests in `internal/cli`;
  targeted tests without `-race` while iterating, `make test` and `make lint` before finishing.
- Doc tests read `README.md` and `docs/*.md`; a sentence a test names stays in its `## ` section.
- Australian English in docs, comments and messages; commit prefixes `feat:`, `docs:`, `test:`.

## Handed to later specs

None: this is the last spec of the series.

# Implementation

## Develop

Base commit: 14475eb6668790b641740ffebba2fe39015b02eb

Frozen test files (staged before the code was written): `internal/scope/byaddress_test.go`,
`internal/knowledge/dnsname/generic_test.go`, `internal/recon/procedures/dns/innetblock_test.go`,
`internal/recon/run/unbudgeted_test.go`, `internal/config/config_test.go` (two `TestIntSettings`
rows and `TestInNetblockEnabled`), `internal/cli/innetblock_test.go`,
`internal/cli/innetblock_lookup_test.go`, `internal/cli/innetblock_names_test.go`,
`internal/cli/innetblock_docs_test.go`, `internal/cli/innetblock_crash_test.go` and one line in
`internal/cli/crash_test.go` (the `TestChildProcesses` entry). All failed on their assertions
against stubs, apart from four that pin today's behaviour (no netblock means no lookup; reverse IP
outside the netblock and over the cap; `--no-in-netblock` looking up nothing).

How it was built:

- **Scope (D11, D16).** `scope.New` works out the names in scope by address in `promote`;
  `ClassifyName` is the old `ClassifyHost`, and `ClassifyHost` adds `ByAddress` after the roots.
  `DialAddrs` filters a name in scope by address to its in-netblock addresses, and `hostAddrs`
  skips such names. `dnsname.Generic` scans the name's digit runs once (D19).
- **Lookups (D12, D13, D14).** `kinds.CandidateLookup` is in `scopeKinds`. `resolve()` is split
  into `ask` (an `answer` of distinct addresses and CNAME links, and the rcode when it has no
  address) and `answer.observations`; `resolve` adds the `unresolved` row. The `in-netblock`
  procedure (`internal/recon/procedures/dns/innetblock.go`) yields rows jobs, then lookup jobs of
  the names in scope by address, then of `View.Candidates()`, which sorts with
  `candidates.Compare` as `candidates.csv` does. Where D12 is silent, `addrs` is sorted in
  address order (`netip.Addr.Compare`), so IPv4 comes before IPv6. The rows key's hash is the
  first six bytes of the SHA-256 of the answer's JSON.
- **Settings (D20, D4).** `config.InNetblock`, the three flags and keys; the runner stores the two
  scope settings in `meta` (`storeScopeSettings`) before `loadBaseline`, `store.Reader.Meta` and
  `ScopeSource.Meta` read them, and `snapshotSource` answers them for the export.
- **Guards (D5, D10, D15, D17, D18, D2).** `origin.FrontedHosts`, `identifier-pivot`'s `Jobs`,
  `ResolvableHostnames`, `placeRoot` and `Visibility.outside` as the decisions say; `Seeds` asks
  `RootOf`; `nameObs`, the Shodan DNS record, GitHub's hostnames, `includedDepths` and
  `reverseip`'s `Run` use `ClassifyName`. `reverseip`'s key gains `|names` inside an in-scope
  netblock.
- **Output (D21, D22).** `scopeRows` adds the `hostname` rows; `Summary.HostsInScopeByAddress`
  (`hosts_in_scope_by_address`) and its console line.
- **Docs (B15).** A new `## Names on in-scope addresses` in `docs/sources.md`, with the Reverse IP,
  name-guessing and records sections amended; `docs/passive-boundary.md`, `docs/candidates.md`,
  `docs/output.md`, `docs/configuration.md` and `CLAUDE.md`.
- **Frozen tests changed with the user's agreement.** `TestInNetblock_LeavesScope`'s
  "excluded on a later run" case no longer requires the name's `resolutions.csv` rows to stop
  being current: `resolve` asks every excluded name another source finds, as before this change,
  so that its addresses are excluded too (`nbWantLeft` gained an `excluded` flag).
  `TestInNetblockNames_ItsDomainIsOnlyACandidateRoot` requires other.org's sources to include
  `in-netblock` rather than equal it, since the root inherits the rdns evidence of the candidate
  hostname legacy.other.org under it (brand.org stays exact). The spec IDs the test writers put
  in comments were removed (comment-only).
- **Existing tests changed by the spec's own rules.** `TestReverseIP_AsksOnlyDedicatedKnownOwnerAddresses`
  (D2's `|names` key); `TestEnvelope_ExactBytes`, `TestEnvelope_ZeroValueShape` and `dataKeys` (the
  new envelope key); `TestParentNames_NoParentOfACandidateIsQueried` and
  `TestDNSRecords_NamesThatAreNotAsked` (their PTR name resolves into the `--cidr`, so it is now in
  scope by address; the tests still check nothing is asked of it or its parents);
  `TestNSReverse_NothingFoundIsContacted`, which the design listed as having no `--cidr` but runs
  with `--cidr 198.51.100.0/24`, now allows one A and one AAAA lookup per candidate root. The help
  goldens were regenerated: the three flags and the kind `candidate_lookup`.
- **Failing on the base too** (both already in `docs/todo.md`): `TestSetup_FailedSaveKeepsTheEdits`
  (`internal/cli`) and `TestActive_EndToEnd` (`internal/lookup/iplookup`).
- No external fact differed from `## External facts`.
- **After verification (D25, D26).** The tests were written and staged first:
  `TestInNetblockSettled_NamesInScopeByAddressDoNotKeepEachOtherIn` and
  `TestInNetblockSettled_SummaryLineIsPluralForTwoHosts` (new), and, with the user's agreement, the
  one-host case of `TestInNetblock_SummaryCountsHostsInScopeByAddress` now expects
  `1 host in scope by address`. `lookupNames` takes its support from `foundByOther`, which reads
  the new `View.Observers` (each current record's supporting jobs from `Store.Observed`, with
  whether the procedure contacts targets) and leaves out a target procedure's job whose key names a
  hostname under no input root. The rule is judged by the root, not by whether the name is in scope
  by address now: httpprobe is not `Retiring`, so its probes of a pair that left scope stay current,
  and judging them by the pair's present class would bring the pair back in on the next pass.
  `Store.Observed` reads observations rather than completed jobs, since a pending redo clears the
  completion marks first (`TestInNetblockLookup_InterruptKeepsCompletedLookups` caught this). The
  summary line uses `layout.Count`. Mutation checks: counting such a job as support fails both
  cases of the new test; an always-plural line fails the one-host case.
- **Mutation checks** (each edit made by hand, the tests run, the edit undone by hand), all caught:
  - scope, any looked-up address qualifying, not only one in a netblock: `TestByAddress`,
    `TestByAddress_GuardCounts`; through the CLI, `TestInNetblockLookup_CandidatesAreNeverContacted`
    (a candidate outside the netblock is then contacted);
  - the guard doubled, in the count and in the qualifying test: `TestByAddress_GuardCounts`,
    `TestByAddress_SharedHostingGuard`;
  - an excluded CIDR in the lookup ignored: `TestByAddress`, `TestInNetblock_LeavesScope`;
  - the generic-name test skipped: `TestByAddress`; in `Generic`, four-digit runs allowed, the
    reversed order not matched, any separator accepted: `TestGeneric`;
  - a name exclusion, or a rooted name, counted against the guard: first survived the CLI tests, so
    `TestByAddress_GuardLeavesOutExcludedAndRootedNames` (`internal/scope/guard_test.go`, new) was
    added, and it and `TestByAddress` catch both;
  - every address of a name in scope by address dialled, and its outside address made
    port-eligible: `TestInNetblock_OnlyItsInNetblockAddressesAreDialled`;
  - the runner's gate for target procedures and egress's passive and authorisation refusals all
    turned off together: `TestInNetblock_EnteringScopeDoesNotRelaxThePassiveBoundary`.

## Known limitations

- **B1.** The order of the lookups is pinned only through the cap (the first N asked are the first
  N rows of `candidates.csv`): the fake DNS does not record query order.
- **B1, across behaviours.** The crash test cannot prove the `in-job-tx` fault fires inside the rows
  job's transaction; its second run is arranged so that writing the rows is the only work.
- **B5.** `Generic` of an IPv4-mapped IPv6 address (it unmaps) and whether `ByAddress` normalises
  its argument are not pinned by tests.
- **B7.** "Checked for findings like any in-scope hostname" has no test of its own; no origin
  check and no identifier pivot are tested with B9.
- **B9.** Labels of a name in scope by address being learned and tried under an input root is not
  tested: `Learnable` already asks `RootOf`.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) read the change against the base
commit.

Fixed:

- `Scope.NameInScope` (in scope by name, under a root) replaces the three spellings of that test
  in `github`, `shodan-host`, `shodan-dns`, `includedDepths`, `Visibility.outside` and
  `inventory.Seeds` (whose parent check now uses it too, so a parent in scope only by address does
  not make a seed). `Scope.InScopeByAddress` answers the callers that need only the bool, and
  `ResolvableHostnames` and the `hostAddrs` loop use `ClassifyName` directly.
- `promote` stores each name's netblock beside its address, so `ByAddress` is one map lookup; it
  checks for a qualifying address before the exclusion and generic tests, returns at once with no
  netblock, and reuses its count map. `InScopeIP` uses the existing `blockSet`/`blockBits` index
  instead of scanning every netblock, and `holder` is shared with `OwnerUnit`.
- Whether promotion is on now has one source: `Scope.PromotesByAddress`, which the procedure asks
  rather than reading the setting itself.
- `kinds.CandidateRecords` and `CandidateRecord.Compare` are shared by `candidates.csv` and
  `View.Candidates`, which now returns names only. `CandidateLookupAttrs.Addresses` is the one
  decoder of a lookup's addresses (the rows job and the scope build differed on `Unmap`), and
  `kinds.ByAddressHosts` gives both the `scope.csv` rows and the summary count.
- The scope build's fallback for the guard reads `config.Defaults()`; `config` gained a `toggle`
  helper for the two on/off settings; `reverseip`'s `Run` branch is flat; the procedure decodes a
  lookup once and sorts its addresses in place.

Skipped:

- Duplicated helpers across the new `internal/cli` test files, `nmUnder`, the envelope decoding by
  hand, `inNetblockClients`, and the crash child's `init()` dispatch and copied start-up: all are
  in frozen test files.
- Caching the two `meta` values and the decoded lookups between scope builds: two point queries and
  a few small decodes per build, next to the resolution decoding each build already does.
- The repeated normalising of lookup keys, and unexporting `Scope.Addrs` (tests use it): no gain.

# Verification

## Result

Read against the base commit 14475eb (60 files, the untracked `internal/scope/guard_test.go`
included). `go build`, `go vet` and `go test ./...` pass apart from the two tests that fail on the
base too and are in `docs/todo.md` (`TestSetup_FailedSaveKeepsTheEdits`, `TestActive_EndToEnd`).

The goal is met: a candidate served from an in-scope netblock is in `scope.csv` and
`subdomains.txt` and probed at that address with `--authorised`, and with `--no-in-netblock` it
stays a candidate and is never looked up (`TestInNetblock_PTRNameAndReverseIPRootEnterScope`,
`TestInNetblockLookup_OffLooksUpNothing`). Nothing outside the in-scope netblocks receives more
than the candidate lookups through the public resolvers (`DialAddrs` in `Policy.vetted` and
`HostsFor`, the `hostAddrs` skip, and `TestInNetblockLookup_CandidatesAreNeverContacted`).

- **B1** met. Lookups go through `View.Candidates()`, sorted with the same `CandidateRecord.Compare`
  as `candidates.csv`; the order is pinned only through the cap (Known limitations). Once per
  engagement, `--redo`, re-asking a candidate found again, a netblock added later and D9's rule
  are each tested.
- **B2** met: the `|names` key suffix, hostnames kept only on in-netblock addresses, and one more
  request for an address asked before its netblock.
- **B3, B4, B10** met in `scope.promote` and `ClassifyHost`; `placeRoot` keeps a promoted root a
  candidate root.
- **B5** met by `dnsname.Generic`. Its two untested edges in Known limitations are now pinned:
  `TestGeneric_IPv4MappedAddress` (a mapped address is judged as its IPv4 address) and
  `TestByAddress_NormalisesTheName` (`ByAddress`, `InScopeByAddress`, `ClassifyHost` and
  `DialAddrs` normalise the name).
- **B6** met: names enter as lookups arrive and leave when the guard trips (D1), with one WARN per
  address. Under `--skip in-netblock` the guard still applies but no WARN line is printed, since
  the procedure's `Jobs` is what warns.
- **B7** met. "Checked for findings like any in-scope hostname", which had no test, is now pinned by
  `TestInNetblock_ItsServiceIsCheckedForFindings` (a disclosed version on its page is a web-posture
  finding). No origin check (D5, `FrontedHosts`) and no identifier pivot (D10) are covered by
  `TestInNetblockNames_NoSourceIsAskedAboutIt`, which asserts that neither SecurityTrails' history
  nor a Shodan search names a fronted by-address name or its identifier, so that limitation no
  longer holds.
- **B8, B9, B11, B12, B13, B14, B15** met as tested. In B11's "excluded on a later run" case the
  name's `resolutions.csv` rows stay current but are no longer shown (it is excluded), which the
  behaviour's "stop being shown or stop being current" allows; that frozen test was changed with
  the user's agreement. B9's learned-name labels rest on `Learnable` asking `RootOf`, unchanged and
  untested here.
- **Settings and help**: three keys and flags, `TestIntSettings` rows, `TestInNetblockEnabled`, the
  help goldens and `nyx help procedures`.

External facts: HackerTarget's quota page still answers 403 to an automated fetch (2026-11-27), so
its free daily quota stays unconfirmed; no behaviour rests on its size (it only changes how many
runs D2's repeat requests take). The API itself answered a probe of a documentation address.

Changed in this verification: the three tests above were added (to `internal/cli/innetblock_test.go`,
`internal/scope/guard_test.go` and `internal/knowledge/dnsname/generic_test.go`, as new functions).
No code bug was found before the code review.

## Code review

`/code-review high --fix` read the change against the base and applied no fix. Its two findings,
both left unfixed:

- **Two names in scope by address can keep each other in scope (B9, B11; important).** httpprobe
  records a certificate SAN or redirect host of a probed name as a hostname with the producer
  `httpprobe`. When two names in scope by address name each other (a shared certificate, say),
  each has a producer other than `in-netblock`, so `lookupNames` keeps both lookups after the
  source that first found them (rdns) stops finding them, and they stay in scope. The same path
  makes SAN and redirect names under the name's registrable domain candidates that are then
  looked up. Left unfixed: which observations count as a source other than `in-netblock` is a
  choice the spec does not make (B11 says "no source but `in-netblock`", and httpprobe is one), so
  it is a decision below.
- **"1 hosts in scope by address" (B14; nit).** The console line has no singular form. Left
  unfixed: D22 gives the wording `N hosts in scope by address`,
  `TestInNetblock_SummaryCountsHostsInScopeByAddress` pins it, and the neighbouring
  `N risky ports reported by Shodan` line has no singular either. It is a decision below.

The tests still pass (only the two base failures above), and `make lint` reports 0 issues.

# Follow-ups

**Decisions:**

1. **Whether a probe of a name in scope by address can keep another such name in scope:** settled
   by D25 (it cannot; the names stay candidates).
2. **"1 hosts in scope by address":** settled by D26 (`1 host in scope by address`).

**Deferred work:**

1. `TestSetup_FailedSaveKeepsTheEdits` (`internal/cli`) and `TestActive_EndToEnd`
   (`internal/lookup/iplookup`) fail on the base too: already in `docs/todo.md`.

**Manual steps:**

1. **HackerTarget's free daily quota** could not be read (its site still answers 403 to an
   automated fetch on 2026-11-27). Before relying on D2 for an engagement with many recorded
   addresses, check the current limit at `https://hackertarget.com/ip-tools/`: each address asked
   before its netblock came into scope costs one more request, and a spent quota stops
   `reverseip` for the run.
2. **A live run** against netblocks you are authorised to test, to see how many names enter scope
   and whether the 100-name guard is right:
   `nyx recon --authorised --output-dir /tmp/nyx-live --cidr <netblock> <root>`, then read the
   `hostname` rows of `scope.csv`, the `hosts in scope by address` line of the summary and any
   WARN line naming an address.
