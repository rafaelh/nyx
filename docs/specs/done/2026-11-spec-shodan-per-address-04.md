# Spec 4: passive ports and hostnames per address from Shodan

## Goal

With a Shodan key, a `--passive` run shows the open ports, banners and hostnames Shodan holds for
each dedicated in-scope address, up to a per-run limit, and an active run gains Shodan's view
alongside its own handshakes without Shodan's claims ever widening what nyx connects to.

## Behaviours

1. The existing `shodan` netblock search also records the ports and banners it returns, so
   addresses it returned need no extra lookups. Existing engagements get those ports only after
   `--redo shodan`; the README says so. A new `shodan-host` stage, available under `--passive` and
   `not-configured (no key)` without `keys.shodan`, performs one host lookup per address that
   `ips.csv` marks port-eligible and that either is not inside an in-scope netblock or is inside
   one whose search stopped at its page cap and did not return the address. The summary says when
   a netblock search was truncated.
2. Lookups per run are capped by `shodan.max_hosts` (default 500), taken in address order. Deferred
   checks are not counted as failures, the stage shows `done`, and the summary always says how
   many addresses were deferred to the next run. Shodan data for an address is refreshed only by
   `--redo shodan-host`.
3. `open-ports.csv` gains `source` (`nyx`, `shodan` or `nyx;shodan`) and `shodan_last_seen`
   (empty on rows only nyx saw). When both have a banner, nyx's is shown. Shodan's banner is
   cut to its first line or 256 characters, whichever is shorter, and sanitised like nyx's own.
   A TCP port Shodan reports outside the configured port list is shown as unconfirmed and nyx
   never connects to it. UDP services Shodan reports are not recorded.
4. A hostname Shodan associates with the address is recorded as a hostname when it is under an
   in-scope root; any other becomes a candidate root in `candidates.csv`.
5. nyx's own handshake result takes precedence over Shodan, whichever came first. A port
   nyx finds closed (the connection is rejected) marks that address-and-port row not current; a
   port that does not answer within the connect timeout leaves it unconfirmed. A
   risky port reported only by Shodan is a finding in `risk-ports.csv` one severity step below the
   confirmed equivalent (medium becomes low) with a `confirmed` column of `no`. When the `ports`
   stage confirms it, the same row is updated to the full severity, `confirmed` becomes `yes`, and
   a new `+` line is printed at the raised severity.
6. The console summary has a line `N risky ports reported by Shodan, unconfirmed` whenever N is
   above zero, and the `--json` summary event carries N. The open-port count is split into
   confirmed (nyx completed a handshake) and third-party reported (all others).
7. An address Shodan does not know (404) completes the check with no observations. Keyed-source
   abort rules are unchanged.
8. The README's passive-boundary section says Shodan is queried per dedicated in-scope address up
   to the cap, that host lookups are rate-limited rather than credited (to be confirmed against
   Shodan's current terms before the README is written), and that netblock search pages cost
   credits as today.

# Design

**Status:** ready to build (wave 2). Every spec it depends on has merged, and the design was
re-checked against them on 2026-11-14. **Depends on:** Spec 6 (`run.Budgeted`, built as
`Budget(config.Settings) int` with `Check.Cost`), Spec 1 (`CleanName`, `ErrQuota`), Spec 3
(`Kind.Found`, for the reported-port line) and Spec 15 (candidate evidence, for the candidate
roots of behaviour 4). **Owns for Spec 14:** the `reported_port` kind, the `confirmed` notion,
`run.Noter`.

## Decisions

- **Shodan's ports are a kind of their own**, `reported_port` (key `ip:port`; `ip`, `port`,
  `banner`, `last_seen`), shown by the same port-eligibility rule as `open_port`. Nyx's own
  handshakes stay in `open_port`. Nothing that decides contact reads `reported_port`: the probe's
  detection checks and the egress policy use `open_port` and the configured port list only.
- **`shodan` (netblock search)** also emits `reported_port` for each TCP match, and a
  `shodan_netblock` record (`truncated`) per search. The check key is unchanged, so existing
  engagements gain ports only with `--redo shodan`.
- **`shodan-host`** (`internal/stages/shodan/host.go`) yields, in address order, each
  port-eligible address that is outside every in-scope netblock, or inside one whose
  `shodan_netblock` is truncated and for which no `reported_port` from the `shodan` stage exists.
  It is `Budgeted` by `shodan.max_hosts` (default 500, minimum 1): `Budget` returns the setting,
  and each check is keyed by its address and has `Cost` 1. A 404 completes with nothing.
  TCP services become `reported_port`; UDP is dropped; hostnames under an in-scope root become
  `hostname` and `ip_hostname`, others become a `root` candidate (registrable domain).
- **Candidate evidence.** The check key is the address and carries no setting, so the default
  evidence (the stage name and the check key) is right and the stage needs no `Evidencer`.
  `shodan-host` joins the family table in `internal/candidates` as passive DNS, beside `shodan`
  and `shodan-dns`. A source the table does not list is a family of its own, so without the entry
  Shodan agreeing with Shodan would count as two families and raise a candidate's confidence.
- **Closed versus silent** (decided with the user: one extra handshake). The ports stage records
  the outcome only for ports Shodan reported, as `port_check` (`result`: `closed` or `silent`):
  - a port check that has not run yet carries `reported` in its input and records the outcome
    itself, so no extra handshake is made;
  - a port check that completed before the report existed is redone once under the key
    `<ip>:<port>|reported`, yielded only while there is no current `open_port` and no
    `port_check` for that address and port. This needs `View.Done(key)`, a read of the stage's
    completed set the runner already holds.
  The recheck is only for ports on the configured list at port-eligible addresses.
- **`open-ports.csv`** merges the kinds by key: `source` (`nyx`, `shodan`, `nyx;shodan`),
  `confirmed` (`yes` when nyx completed a handshake), `shodan_last_seen`; nyx's banner wins.
- **A rejected port is hidden by the showing rule, not by the file.** The store's `current` only
  means "has an observation", so the closed set (`port_check` with `closed`) goes into
  `inventory.Data` and `reported_port` is shown while its address is port-eligible and the port is
  not in that set. The counts, the findings, Spec 20 and Spec 21 then agree; `open-ports.csv`
  still lists the row, with `current` false.
- **Findings**: a risky port known only from `reported_port` (and not closed) is the same
  `ports|risky-port|<ip:port>` finding at one severity step lower with `confirmed: no`; when
  `open_port` appears the same key is re-derived at full severity. `deriveFindings` emits a
  `found` event when a current finding's severity rises, which is the new `+` line. (Findings keep
  the runner's own found-line code: `kinds` cannot import `findings`.)
- **Summary**: `open_port`'s category becomes `open ports (confirmed)`; the runner adds
  `open ports (third-party reported)` (reported, shown, not confirmed, not closed) and
  `unconfirmed_risky_ports`, printed as `N risky ports reported by Shodan, unconfirmed`. Stages may
  add summary lines through `run.Noter.Notes(View) []string`; `shodan` uses it for truncated
  searches. Deferred lookups need no code here: the runner's `Deferred to the next run` block
  shows the deferred cost beside `shodan-host`, which is a number of addresses, and the README
  names that unit.

## Changes

- `internal/kinds/reportedport.go` (`reported_port`, `shodan_netblock`, `port_check`).
- `internal/stages/shodan/shodan.go`, `host.go`. `internal/stages/ports/ports.go`: `reported`
  input, recheck key, `port_check`. `internal/run/stage.go`: `View.Done`, `Noter`.
- `internal/run/runner.go`: severity-raise event, summary counts and notes.
- `internal/output/ports.go` (moved from `output.go`). `internal/findings/findings.go`,
  `records.go` (`confirmed` column), `table.go`. `internal/config/config.go`: `shodan.max_hosts`.
- `internal/candidates/candidates.go`: `shodan-host` in the family table, as passive DNS.
- `README.md`: passive-boundary text, columns, the `--redo shodan` and `--redo shodan-host` notes,
  `shodan-host` in the passive DNS list of `sources` values, the unit of the deferred number.

## Tests

`internal/cli/shodan_host_test.go`:

- `--passive` with a key fills `open-ports.csv` and `risk-ports.csv` (low, `confirmed: no`); the
  cap defers the rest in address order and the summary says how many; a 404 completes.
- Addresses a complete netblock search returned are not looked up; those missed by a truncated
  search are, and the summary notes the truncation.
- **Canary tests:** a Shodan port outside the configured list is shown unconfirmed and never
  dialled; a Shodan port does not create a probe check.
- Passive then active: one handshake per port; open raises the finding with a new `+` line and
  `confirmed: yes`; a rejection marks the row not current; silence leaves it unconfirmed.
- Active then Shodan: exactly one extra handshake per reported port without an open record, then
  none on later runs.
- A closed Shodan-only port is absent from the counts and `risk-ports.csv`, and its
  `open-ports.csv` row is not current.
- Banner cut to one line or 256 characters and sanitised; UDP not recorded; out-of-root hostnames
  are candidate roots; the split open-port counts in console and `--json`.
- A candidate root that `shodan` and `shodan-host` both report, and nothing else, has one family
  and is `low`.

## To verify while building

Whether `shodan/host/<ip>` costs query credits under Shodan's current terms (behaviour 8); the
README sentence is written from that answer.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Budget rules (Spec 6).** The first pending check of a run is always sent, and a budget below
  1 counts as 1. A lookup that fails still spends its share of the budget, so a run with many
  failures looks up fewer than `shodan.max_hosts` addresses.
- **A 402 from Shodan is an ordinary failed check (Spec 2).** `httpsrc.Get` aborts a keyed stage
  on a 401, 403 or 429 only. Behaviour 7 keeps that for the netblock search. If the check under
  "To verify while building" finds that host lookups do cost credits, make a 402 from
  `shodan-host` wrap `run.ErrAbortStage`, so one spent balance does not fail every remaining
  address.
- **Truncation (Spec 2).** The `shodan` stage has no truncation warning today: it stops at its
  page constant, or once it has read `total` matches. Set `truncated` by that same test (the page
  cap was reached with fewer than `total` matches read), which is the rule Censys and `shodan-dns`
  use. Do not add another rule.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname under a root the user promotes later was recorded only as that candidate root, so it
  becomes a hostname only after `--redo shodan-host`. Putting the scope in the key would repeat
  every lookup on every scope change. The README's `--redo shodan-host` note says so.
- **`Kind` is not comparable (Spec 3).** It holds `Found`. Compare `Name()`; never compare two
  `kinds.Named` values with `==` or use one as a map key.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates. The
  `shodan` stage uses `input.NormaliseHost` today. Use `CleanName` in the new stage and leave the
  old call alone: the hostname helpers are merged in one change after Specs 4, 10, 13 and 17.
- **Console text (Spec 22).** If Spec 22 has merged, the severity-raise `+` line goes through its
  log formatter and is asserted on stderr. If not, assert it on stdout.

## Out of scope

Shodan vulnerability data; UDP; using Shodan ports to widen the port list.

# Implementation

## Develop

Built as designed. `reported_port`, `shodan_netblock` and `port_check` are in
`internal/kinds/reportedport.go`, with `EncodeBanner` (moved out of the ports stage) and
`ShodanBanner` (first line or 256 characters, then escaped like nyx's own banner). A new kind flag,
`ClosedHides`, makes `Visibility` drop a reported port nyx found closed; the closed set is
`inventory.Data.ClosedPorts`, read from the `port_check` records (`PortCheck` is in `scopeKinds`).
`Visibility.Totals` counts `open ports (confirmed)` and `open ports (third-party reported)` (a
reported port with a current `open_port` of the same key is counted once, as confirmed).
`shodan` emits `reported_port` and `shodan_netblock` (`truncated` by the page-cap rule) and is a
`run.Noter`; `shodan-host` (`host.go`, registered after `dnsroot`) is `Budgeted` by
`shodan.max_hosts`, with `View.KnownAddrs` giving its candidate addresses. The ports stage carries
`reported` in a check's input, records `port_check` when nyx finds a reported port closed or
silent, and yields `<ip:port>|reported` once for a completed check with no `open_port` and no
`port_check` (`View.Done`). `open-ports.csv` merges the kinds by key (`internal/output/ports.go`).
`findings.ports()` derives the one-step-lower finding with `confirmed: no`; `deriveFindings` emits
the `found` event when a finding's severity rises; the summary event carries
`unconfirmed_risky_ports` and `notes`. Changes to existing tests: the open-port category name, the
`open-ports.csv` header, the stage-order tail, the `risk-ports.csv` columns, and the keyed
rejection test now ignores `shodan-host`'s lookups when counting `shodan-dns` requests.

How each behaviour is tested (`internal/cli/shodan_host_test.go` unless named):

1. `TestShodanHost_PassiveShowsOpenAndRiskyPorts`, `_CompleteNetblockSearchNeedsNoLookups`,
   `_TruncatedSearchLooksUpWhatItMissed`, `_NotConfiguredWithoutKey`, `_RefreshedOnlyByRedo`.
2. `_CapDefersInAddressOrder`, `config` `TestPerRunCapSettings`.
3. `_PassiveShows...`, `_ReportedPortsAreNeverDialledOrProbed` (canary listeners),
   `_BannersUDPAndHostnames`, `internal/kinds` `TestEncodeBanner`/`TestFirstLine`.
4. `_BannersUDPAndHostnames`.
5. `_ActiveRunSettlesWhatShodanReported`, `_LateReportCostsOneExtraHandshake`,
   `_ClosedPortIsInNoCountOrFinding`, `internal/findings` `TestRiskyPortsReportedByAThirdParty`.
6. `_ConsoleSummarySplitsOpenPorts`, `internal/report` summary test, `internal/kinds`
   `TestTotalsSplitOpenPorts`.
7. `_UnknownAddressCompletesWithNothing`, `_RejectedKeyAbortsTheStage`.
8. `_ReadmeSaysWhatItDoes`.
Also `_CandidateRootFromBothIsOneFamily` and `candidates` `TestFamily` for the family entry.

Deviations and differences from the plan:

- **The cost of `shodan/host/<ip>` could not be confirmed.** Shodan's credit page and API reference
  do not mention the host lookup (they list credits for filtered searches and for pages past the
  first). The README says it is rate-limited and not listed as credited, and that this was not
  confirmed. No 402 handling was added (the design adds it only if lookups turn out to cost credits).
- **"Absent from `risk-ports.csv`" for a closed Shodan-only port** is implemented as "no current
  row". `shodan-host` stores the port, the finding is derived and printed at once, and the ports
  stage then finds it closed, so the finding is no longer derived and its row stays with
  `current` false, like every other finding that stops being derived.
- **`shodan-host` candidate addresses** are the known addresses of `ips.csv` (`View.KnownAddrs`),
  not every address of an in-scope netblock: a truncated search of a /16 would otherwise queue
  65,536 lookups. An address inside a truncated netblock is asked about only once it is known.
- `shodan_last_seen` holds the date (`YYYY-MM-DD`) of Shodan's timestamp.
- Only `data` entries are read from a host answer, not the `ports` list, because the list does not
  say which ports are UDP.
- No test was marked for a mutation check in `## Tests`. Six were run by hand after simplifying, each
  broken and then restored, and each made a test fail: dropping the `!settled` guard of the recheck
  (`_ActiveRun...`, `_ClosedPort...`, `_LateReport...`); not stepping the severity down
  (`_PassiveShows...`, `_ActiveRun...`); looking up addresses a complete search covered
  (`_CompleteNetblockSearchNeedsNoLookups`); not hiding a closed reported port (three tests);
  leaving `shodan-host` out of the family table (`_CandidateRootFromBothIsOneFamily`); and cutting a
  banner at `\r` only (`TestFirstLine`).

## Known limitations

- Behaviour 1: an engagement whose netblock search completed before ports were recorded has no
  `shodan_netblock` record, so it is treated as complete; its addresses are not looked up until
  `--redo shodan`.
- Behaviour 5: a Shodan-only risky port that nyx then finds closed in the same run is printed as a
  `+` low finding before the handshake, and its row stays in `risk-ports.csv` as not current.
- Behaviour 5: the recheck under `<ip:port>|reported` is made once. A port nyx found silent twice
  (the first check and the recheck) stays unconfirmed and is not checked again until `--redo ports`.
- Behaviour 4: a hostname under a root promoted later becomes a hostname only after
  `--redo shodan-host`, as the design says.
- Behaviour 2: a lookup that fails still spends budget, so a run with failures looks up fewer than
  `shodan.max_hosts` addresses.
- `open-ports.csv` `source` names who has ever reported the port, including a record that is no
  longer current.

## Simplify

Fixed:
- One `kinds.ParsePortKey` (parse and unmap a port key) replaces seven copies in `output`,
  `findings`, `ports`, `run` (`OpenPorts`, the closed-port read) and `shodan-host`.
- `open-ports.csv`: rows keyed by `netip.AddrPort` with no separate order slice (the file is sorted
  on render), each key parsed once, and a reported row's `current` taken from `Visibility.Shown`
  rather than restating the closed-port rule.
- `shodan` package: one `truncated` helper for the truncated in-scope netblocks, used by
  `shodan-host`'s checks and the summary note; one `isTCP`, so `shodan-host` now also reads `TCP`
  in any case for hostnames, as the reported-port rule already did.
- `View.KnownAddrs` uses a new `Inventory.KnownAddrs` instead of building and sorting every
  address's hostname list and throwing it away.
- The `ClosedHides` doc now says it also stops `Totals` counting a port nyx opened twice.
- Smaller: a redundant length guard in the console summary, one `portRow` test helper behind
  `openRow`/`riskPortRow`, `strings.Repeat` in the banner test, and a zero `hostnames: nil`.

Skipped:
- Moving `kinds.PortCheck` out of `scopeKinds` so a port_check write doesn't re-rank candidates:
  the list is shared on purpose so the two can't drift, and the cost is a few re-ranks per run.
- Feeding `unconfirmed_risky_ports` in as a note, and storing a `Source` on reported ports: the
  summary field is in the README and the design, and a second reporting source is speculative.
- One merged per-port view (open, reported, closed) for output, findings and `Totals`: a redesign
  larger than this change.
- Unifying `input.NormaliseHost` (shodan) and `httpsrc.CleanName` (shodan-host) for Shodan
  hostnames: it would change which names each stage accepts.
- Moving `ShodanBanner` into the shodan package: it defines the stored attribute's format.
- Counting unconfirmed findings in `Headline`'s loop, and making the reported-port findings test
  table-driven: negligible gain.

# Verification

## Result

The goal is met, with B8 resting on an unconfirmed fact about Shodan's credits (Follow-ups).
`make test` passes when the user's own config file is kept out of the way
(`XDG_CONFIG_HOME` pointed at an empty directory); with it, `internal/config`
`TestDefaults` fails on `output_dir`, as on `main`. `golangci-lint run ./...` reports five issues,
all in test files this change did not add (`sources_keyed_test.go`, `sanitize_test.go`,
`providerranges_test.go`); the two in `sources_keyed_test.go` are on lines this change does not touch.

- **Goal: met.** Under `--passive` with a key, `shodan` and `shodan-host` fill `open-ports.csv`
  and `risk-ports.csv` for the port-eligible addresses, capped per run; nothing that decides contact
  reads `reported_port` (only output, findings, the ports stage's `reported` flag and
  `shodan-host`'s own skip list read it), and the ports stage yields only the configured ports on
  eligible addresses, so a Shodan port never widens what nyx connects to (canary test).
- **B1: met** (one gap fixed, below). The netblock search records `reported_port` for each TCP
  match and a `shodan_netblock` record whose `truncated` uses the page-cap rule of the other paged
  sources; its check key is unchanged, and the README says ports arrive only after `--redo shodan`.
  `shodan-host` runs under `--passive`, is `not-configured (no key)` without `keys.shodan`, and
  yields each port-eligible known address outside every in-scope netblock, or inside a truncated one
  that the search did not return. The summary carries a note per truncated in-scope search (console
  and `--json` `notes`). The candidate addresses are those of `ips.csv`, not every address of a
  truncated block, as `# Implementation` says; B1 asks only about addresses `ips.csv` marks, so
  this is the behaviour. An engagement whose search ran before this change has no
  `shodan_netblock` and is treated as complete until `--redo shodan` (known limitation; B1 already
  says such engagements need the redo).
- **B2: met.** `shodan.max_hosts` (default 500, minimum 1, `--shodan-max-hosts`, `NYX_SHODAN_MAX_HOSTS`)
  is the stage's `Budget`, each check costs 1 and the checks are in address order
  (`netip.Addr.Compare`, tested against text order). Deferred checks are not failures, the stage
  shows `done`, and the summary's `Deferred to the next run` block gives the number of addresses.
  The check key is the address alone, so only `--redo shodan-host` refreshes it.
- **B3: met.** `open-ports.csv` merges `open_port` and `reported_port` by address and port, with
  `source`, `confirmed` and `shodan_last_seen` (the date of Shodan's timestamp; empty on rows only
  nyx saw); nyx's banner wins when it has one. Shodan's banner is cut to its first line (`\r` or
  `\n`) or 256 characters before it is escaped like nyx's own. A Shodan port off the configured list
  is shown unconfirmed and never dialled or probed. UDP services (and their hostnames) are dropped.
- **B4: met.** A hostname under an in-scope root becomes `hostname` and `ip_hostname`; any other
  gives its registrable domain as a `root` candidate. `shodan-host` is in the candidate family table
  as passive DNS, so `shodan` and `shodan-host` agreeing is one family (tested). A name under a root
  promoted later needs `--redo shodan-host`, as the design and README say.
- **B5: met**, within the known limitations. A port check that has not run carries `reported` and
  records `port_check` (`closed` or `silent`) itself; one that completed before the report is
  rechecked once under `<ip:port>|reported`. A rejected port hides the reported record through the
  showing rule (row not current, out of the counts and findings); a silent one stays unconfirmed. A
  Shodan-only risky port is the `ports|risky-port` finding one step lower with `confirmed: no`; when
  `open_port` appears the same row is re-derived at full severity with `confirmed: yes` and the
  runner prints a new `+` line for the raised severity. The known limitations (a low `+` line
  printed before the same run finds the port closed; the single recheck) are outside what B5 asks.
- **B6: met.** `open ports (confirmed)` and `open ports (third-party reported)` are separate
  counts (a port both know is counted once, as confirmed); the console prints
  `N risky ports reported by Shodan, unconfirmed` only when N > 0, and the `--json` summary carries
  `unconfirmed_risky_ports`.
- **B7: met.** A 404 completes the check with nothing; a 401, 403 or 429 aborts the stage, as for
  the other keyed sources.
- **B8: met as written, not confirmed.** The passive-boundary section says Shodan is queried per
  dedicated in-scope address up to `shodan.max_hosts`, that host lookups are rate-limited rather
  than credited as far as Shodan's documentation says, that this was not confirmed against Shodan's
  current terms, and that netblock search pages past the first still cost credits.

Changed during verification:

- **The README's `Console and JSON` section had been deleted (no behaviour of this spec; a
  regression of the README contract).** The new `Shodan per address` section had replaced it
  rather than following it, leaving the link at the top of the README dangling and the log,
  summary, `--quiet`, `--debug`, colour and `--json` rules undocumented. The section is restored
  unchanged in its old place, before `Shodan per address`, and the per-run limits paragraph now
  names the unit of `shodan-host`'s deferred number (addresses) beside the other two.
- **B1: an address a truncated search returned with only a UDP service was looked up again.**
  `shodan-host` decided "returned" from the `reported_port` records of the `shodan` stage, which a
  UDP-only match does not create. It now reads the `ip` records the search writes for every match.
  `TestShodanHost_TruncatedSearchReturnedUDPOnly` pins it (it fails without the change).
- `shodan_host_test.go`: `http.StatusUnauthorized` instead of `401`, which the lint hook flagged.

## Code review

`/code-review high --fix` made eight findings and applied five fixes; `make test` passes after
them (with the user's config kept out of the way, as above). None changes a behaviour the spec
pins, and no test was edited.

- **Fixed (B6, console summary).** The count column was 16 characters wide, so the new
  `open ports (confirmed)` and `open ports (third-party reported)` pushed their numbers out of line.
  The column is now at least 16 wide and as wide as the longest category.
- **Fixed (B6, counts).** `Totals` matched `open_port` to `reported_port` by the raw key, while the
  findings and `open-ports.csv` match on the parsed, unmapped address and port. It now uses
  `ParsePortKey` too, so a port both know cannot be counted twice.
- **Fixed (B1, summary note).** Under `--skip shodan-host` the truncation note said `shodan-host`
  looks up the missed addresses; it now says the stage is skipped and addresses may be missing.
- **Fixed (no behaviour; conventions).** `Settings.Shodan`, `rawSettings.Shodan` and
  `Inventory.closed` are appended at the end of their structs, and `shodan_netblock` and
  `port_check` each have their own file (`internal/kinds/shodannetblock.go`,
  `internal/kinds/portcheck.go`), as the build-order plan asks.

Left unfixed:

- **An excluded hostname Shodan names gives its registrable domain as a candidate root (B4).** B4
  says any name not under an in-scope root becomes a candidate root, so dropping excluded names
  would change the behaviour as written. A decision for the user (Follow-ups).
- **The ports check key does not carry the `reported` flag.** The design keeps the bare key on
  purpose and settles a late report with the one `|reported` recheck; putting the flag in the key
  would repeat every reported port's handshake.
- **A `port_check` write re-ranks the candidates.** `PortCheck` is in `scopeKinds`, which the rank
  deriver also reads. Splitting the list is the change `## Simplify` already declined; the cost is a
  few re-ranks per run.
- **The "nyx's handshake beats Shodan's report" rule is written in three places** (`Totals`,
  `findings.ports`, `openPortRows`). Merging them is the redesign `## Simplify` declined.

# Follow-ups

1. Check whether `GET https://api.shodan.io/shodan/host/<ip>` costs query credits on your plan
   (Shodan's API plan page, or compare `GET https://api.shodan.io/api-info?key=<key>` before and
   after one lookup). Then adjust the credit sentence in README `## Passive boundary`. If lookups
   are credited, make a 402 from `shodan-host` wrap `run.ErrAbortStage` in `Host.Run`
   (`internal/stages/shodan/host.go`) so one spent balance does not fail every remaining address.
2. Run it once against Shodan for real, on a target you are authorised for, to confirm the
   live answer has the `data[].port`, `transport`, `data` and `timestamp` fields the stage reads:
   `NYX_KEYS_SHODAN=<key> ./nyx --passive --output-dir /tmp/nyx-out <domain>`, then look at
   `/tmp/nyx-out/<domain>/open-ports.csv` and `risk-ports.csv`.
3. Decide whether a hostname Shodan names that you have excluded should still give its
   registrable domain as a candidate root (the `else if` branch in `Host.Run`,
   `internal/stages/shodan/host.go`).
4. Decide what to do with the working-tree changes this verification did not commit because they
   are not part of this spec: the notes added to `docs/todo.md` and the deletion of
   `docs/plans/2026-11-osint-improvements.md` (`git diff docs/todo.md`, `git status`).
5. Make `internal/config` `TestDefaults` independent of your own config file, which sets
   `output_dir` (`internal/config/config_test.go`). Until then, run the suite with
   `XDG_CONFIG_HOME=$(mktemp -d) make test`.
6. Fix the flaky `cli` suite: the test world's "closed" loopback port is freed and can be taken by
   another listener, so `TestPorts_*` and some web tests fail now and then. Reserve a port that is
   never bound, or hold the listener and reset each connection (`internal/cli/ports_test.go`,
   `internal/cli/harness_test.go`).
