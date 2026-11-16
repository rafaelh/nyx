# Spec 19: service records and well-known hostnames

## Goal

Mail, identity, voice, collaboration and game infrastructure advertised through SRV records and
well-known hostnames is discovered for each in-scope root, without widening what nyx connects to.

## Behaviours

1. The `dnsroot` stage (Spec 3) also queries, as its own check per root, a fixed SRV list:
   `_sip._tls`, `_sip._tcp`, `_sipfederationtls._tcp`, `_autodiscover._tcp`, `_ldap._tcp`,
   `_kerberos._tcp`, `_xmpp-server._tcp`, `_xmpp-client._tcp`, `_caldav._tcp`, `_carddav._tcp`,
   `_imaps._tcp`, `_submission._tcp`, `_matrix._tcp`, `_minecraft._tcp`. Adding SRV to an
   existing engagement runs the new check once; nothing already recorded is re-queried.
2. Each SRV answer is a row in `resolutions.csv` with type `SRV`, the service name as the name and
   `priority weight port target` as the value. SRV service names are not hostnames and are not
   tested as wildcard zones. A target of `.` records nothing. An in-scope target is recorded as a
   hostname; any other target is a row in `third-parties.csv` with mechanism `srv` and the
   target's registrable domain, not a candidate.
3. SRV ports are reported, never connected to: `ips.csv` gains an `srv_ports` column listing the
   ports SRV records advertise for the address's hostnames. The `ports` stage keeps to the
   configured port list and the README boundary text is unchanged.
4. The permutations stage always tries `autodiscover`, `lyncdiscover`, `enterpriseenrollment`,
   `enterpriseregistration` and `mta-sts` under each root, even when the wordlist lacks them,
   and only when permutations are enabled. These fixed labels are part of the permutation check
   like any wordlist change.

# Design

**Status:** ready to build (wave 2). Specs 3 and 6 have merged, and the design was re-checked
against them on 2026-11-14: `dnsroot` and the permutations stage are described below as built.
**Depends on:** Spec 3 (the `dnsroot` stage, `third_party`) and Spec 6 (it reordered and budgeted
the permutations stage this spec also edits).

## Decisions

- **SRV is one more check per root in `dnsroot`**, keyed `<root>|SRV|<hash of the service list>`.
  The existing type checks keep their keys, so nothing recorded is re-queried, and editing the
  list later re-runs only this check. A SERVFAIL or timeout on any service fails the check. As
  built, `dnsroot` yields one check per in-scope input root and per row of its `rootTypes` table
  (NS, SOA, TXT, CAA), keyed `<root>|<TYPE>`. SRV is not a row of that table, because its check
  makes one query per service name; it is yielded beside them.
- **Egress** gains `TypeSRV` with the value `priority weight port target`.
- **Rows** are `resolution` records with the service name (`_sip._tls.example.com`) as the name
  and type `SRV`. The inventory reads only `A`, `AAAA` and `CNAME` rows and the wildcard stage
  derives zones from hostnames, so service names are never treated as hostnames or wildcard
  zones; a test pins both.
- **Targets**: `.` records nothing; an in-scope target is a `hostname` observation; any other is a
  `third_party` observation with mechanism `srv` and the target's registrable domain. The row
  uses the kind as built: key `<root>|srv|<domain>`, depth 0 (the root's own records), `provider`
  from `provider.DomainOwner` as for `ns` rows. `srv` becomes a mechanism constant beside
  `MechanismNS`, and `kinds.ThirdPartyOf` gains it in its key fallback (the key's last part is
  the domain), so a row that is no longer current still shows its root, mechanism and domain.
- **`srv_ports` is derived on read** in the inventory: for each current SRV row whose target is an
  in-scope hostname, the port is attached to that hostname's addresses, and `ips.csv` lists them
  `;`-joined. Nothing reads the column back: the ports stage and the egress policy keep to the
  configured list.
- **Fixed labels** are a constant in the permutations stage, appended to the root check's words
  after the wordlist (deduplicated). The root check's key hashes the wordlist and the fixed
  labels together, so adding them repeats the root checks once, as a wordlist change does. As
  built, the root key is `root|<root>|wl=<hash>` and the seed key
  `seed|<seed>|wl=<hash>|max=<n>`, from the same hash. Only the root key changes: seed checks do
  not use the fixed labels and must not be repeated. A root check's `Cost` is the number of names
  it queries, so it counts the fixed labels too. A root that is a known wildcard zone gets no
  root check, as today, so the labels are not tried under it: every name under it exists.

## Changes

- `internal/egress/dns.go`, `egresstest/dns.go`: SRV.
- `internal/stages/dns/dnsroot.go`: the SRV check. `permutations.go`: fixed labels and key.
- `internal/kinds/thirdparty.go`: the `srv` mechanism constant and the `ThirdPartyOf` fallback.
- `internal/inventory/inventory.go`: `IPRow.SRVPorts`. `internal/output/output.go`: the column.
- `README.md`: the service list, `srv_ports`, the fixed labels, and `srv` among the mechanisms in
  the `third-parties.csv` row.

## Tests

`internal/cli/srv_test.go`, with `egresstest`:

- Each answer is a `resolutions.csv` row with the stated value; `.` records nothing; an in-scope
  target becomes a hostname; another is a `third-parties.csv` row and not a candidate.
- An existing engagement runs only the new check; NS, SOA, TXT and CAA are not re-queried.
- `ips.csv` shows `srv_ports`; **canary:** an SRV port outside the configured list is never
  connected to; no wildcard check is made for a service name.
- The five fixed labels are tried with a custom wordlist that lacks them, and not at all with
  `--no-permutations`. Adding them to an existing engagement repeats the root checks once and no
  seed check.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **The repeat spends the per-run budget (Spec 6).** The permutations stage is `Budgeted` by
  `permutations.max_names` (default 200,000), and a root check costs its whole word count, about
  4,900 with the built-in list. Repeating every root check once therefore fits about 40 roots in
  one run; the rest are deferred and shown under `Deferred to the next run`. The README's note
  on the fixed labels says so.
- **The `dnsroot` check key does not carry the scope (Spec 3).** An SRV target that a root added
  later brings into scope becomes a hostname only after `--redo dnsroot`. Its `third-parties.csv`
  row hides itself at once, because the showing rule is evaluated on read.
- **`resolution` rows cost a scope rebuild (Spec 3, follow-up 3).** The scope build reads the
  `resolution` kind, so a pass that writes SRV rows rebuilds the scope and inventory although
  they cannot change it, as NS, SOA, TXT and CAA rows already do. That is accepted here.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).**
  `splitResolutionKey` already reads `name|TYPE|value` for such a `resolutions.csv` row, and an
  SRV value holds spaces, not bars, so it needs no change.
- **Column order.** `srv_ports` is the last column of `ips.csv`, after the three Spec 8 adds.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Connecting to SRV ports; SRV lookups under subdomains.

# Implementation

## Develop

SRV is one more check per root in `dnsroot`, keyed `<root>|SRV|<hash of the service list>`
(`srvServices`, `srvKeyToken` in `internal/stages/dns/dnsroot.go`), yielded beside the `rootTypes`
checks, so their keys and the records already held are untouched. `egress` gained `TypeSRV` and the
`priority weight port target` value (`.` for a null target), and `egresstest.DNS` gained `SRV`. Each
answer is a `resolution` row named by the service name; an in-scope target is a `hostname`, any other
is a `third_party` row with the new `kinds.MechanismSRV`, the registrable domain and
`provider.DomainOwner`. The inventory reads an SRV row only for its port: `Inventory.srv` maps a
target to its ports and `IPRow.SRVPorts` lists those of an address's in-scope hostnames, written
`;`-joined as the last column of `ips.csv`. A SERVFAIL or timeout on any service fails the check.
`ThirdPartyOf` needed no new case: its default branch already takes the key's last part as the
domain, so the spec's "gains it in its fallback" is the comment and a test (`srv` is covered by the
not-current row test).

The permutations stage has `wellKnownLabels`, appended (deduplicated) to the root check's words. The
root key is `root|<root>|wl=<wordlist hash>|wk=<token of the labels>` (`wellKnownToken`); the seed key
has no `wk=`, so only root checks repeat. A root check's `Cost` is its name count, so it
includes the labels.

Tests (`internal/cli/srv_test.go`, with `egresstest`):

| Behaviour | Tests |
|---|---|
| 1 (list, own check, existing engagement) | `TestSRV_AnswersAreRows` (14 names asked once, one check), `TestSRV_FailureFailsOnlyTheSRVCheck` (SERVFAIL and timeout), `TestSRV_ExistingEngagementRunsOnlyTheNewCheck`, `TestDNSRoot_ChecksAndPassive` (updated) |
| 2 (rows, `.`, targets, no wildcard check) | `TestSRV_AnswersAreRows`, `TestSRV_Targets`, `TestSRV_NoWildcardCheckForServiceNames`, `TestSRV_ThirdPartyAnnouncedAndKeptWhenNotCurrent` |
| 3 (`srv_ports`, never connected) | `TestSRV_PortsReportedNeverConnected` (canary on every SRV port; only the configured port is checked) |
| 4 (fixed labels) | `TestSRV_WellKnownLabelsAreAlwaysTried` (custom list, deduplicated, `--no-permutations`, wildcard zone), `TestSRV_WellKnownLabelsAreCosted`, `TestSRV_WellKnownLabelsRepeatRootChecksOnce` |

Existing tests changed because the behaviour changed: the `ips.csv` header in two tests, the
`dnsroot` check list, the permutation tests whose cap arithmetic assumed a root costs only its
wordlist (cap 30 became 35, `rootNames` 9), and `TestEmailMTASTS_ExistingEngagementRerunsOnce`, which
now runs with `--no-permutations` because the permutations stage legitimately resolves
`mta-sts.<root>` (the test is about the email stage never doing so).

Interpretations and deviations:

- "A target of `.` records nothing" is read as: the answer records nothing at all, so there is no
  `resolutions.csv` row for it either, as well as no hostname or third party.
- The root key is `root|<root>|wl=<hash>|wk=<token of the labels>` rather than one hash of both (the
  design's wording): same effect, and `wl=` means the same in root and seed keys.
- An SRV port of 0 is not listed in `srv_ports` (it is "not offered", like a null target).
- The spec's wildcard test is pinned by feeding SRV rows from a fake stage (as the NS, SOA, TXT and CAA
  test does) and by checking the real run makes no wildcard check and no A, AAAA or CNAME query for a
  service name.

No external fact differed from `## External facts` (the spec has none).

Mutation checks (each broken by hand, the named test failed, then undone by hand): the canary on
SRV ports (the `ports` stage and the egress policy both made to allow port 5061:
`TestSRV_PortsReportedNeverConnected` failed; the stage change alone does not, because the egress
policy refuses the port too); `srv_ports` for a name outside the scope (the in-scope guard removed:
same test failed); a SERVFAIL no longer failing the SRV check (`TestSRV_FailureFailsOnlyTheSRVCheck`);
a null target recorded (`TestSRV_AnswersAreRows`, `TestSRV_Targets`); the labels left out of the root
key (`TestSRV_WellKnownLabelsRepeatRootChecksOnce`); the labels added to the seed key (the first
version of that test passed, so it now also asserts no seed key carries the labels); the labels left
out of a root check's cost (`TestSRV_WellKnownLabelsAreCosted`); the labels not deduplicated against
the wordlist (`TestSRV_WellKnownLabelsAreAlwaysTried`).

## Known limitations

- Behaviour 1: the service list is a constant, so a later release that removes a service leaves that
  service's rows current (the stage is not `Retiring`); only `--redo dnsroot` retires them.
- Behaviour 2: an SRV target a root added later brings into scope becomes a hostname only after
  `--redo dnsroot`, as for name servers (the `third-parties.csv` row hides itself at once).
- Behaviour 4: repeating every root check once spends the per-run permutation budget (about 40 roots
  a run at the default cap); the rest are deferred. The README says so.

## Simplify

Fixed:
- `srvTargetObs` was a copy of `nameServer`; both are now `dependency(in, mechanism, host)` in
  `dnsroot.go` (an empty mechanism, for an SOA primary, adds nothing outside the scope). The SRV check
  uses `rootInput` with `srvType` instead of its own `srvInput`, so `Run` has one input type.
- The SRV value was parsed twice (`srvTarget` in the stage, `parseSRV` in the inventory) with different
  rules; both now use `dnsname.SRV`. The inventory alone drops port 0, as before, and no longer
  re-normalises a target egress already normalised.
- The root permutation key no longer hashes the wordlist hash with the labels: it is
  `root|<root>|wl=<hash>|wk=<token>`, with the token computed once, so `wl=` means the same in root and
  seed keys and the upgrade test strips `|wk=` instead of recovering the hash from a seed key.
- Tests: `TestDNSRoot_ChecksAndPassive` compares with `slices.Equal` again (the SRV hash is cut off);
  `TestSRV_AnswersAreRows` checks each service name's queries in one loop.
- README: the five well-known labels are listed once, under the built-in lists.

Skipped:
- One check per SRV service as rows of `rootTypes`: the spec asks for one SRV check per root that any
  SERVFAIL or timeout fails, so this would change the behaviour.
- Moving the service list to `config` beside the DKIM selectors, and a shared short-hash helper: the
  list belongs to the stage, and the helper would touch code outside this change. The tests keep their
  own copies of the two lists on purpose, as a pin of the specified names.
- `--no-permutations` on only some runs of `TestEmailMTASTS_ExistingEngagementRerunsOnce`: its
  "never resolves `mta-sts.<root>`" count covers every run, so every run needs it.
- Running the 14 SRV lookups concurrently, and the remaining overlap between SRV tests: the efficiency
  review found nothing that matters (a check runs once per engagement, beside the other root checks),
  and the overlapping assertions each pin a different behaviour.

# Verification

## Result

`make test` (cross-target `go vet`, then `go test -race ./...`) passes.

- **Goal: met.** Each in-scope root's SRV records and the five well-known names are discovered, and
  nothing new is connected to: SRV ports are only reported, out-of-scope targets are third parties
  and never resolved, and the README's passive-boundary text is unchanged.
- **Behaviour 1: met.** `dnsroot` yields `<root>|SRV|<hash of the list>` beside the four type checks
  for every in-scope input root and asks exactly the 14 listed names, each once
  (`TestSRV_AnswersAreRows`). An engagement that already holds NS, SOA, TXT and CAA runs only the
  new check, and a further run repeats nothing (`TestSRV_ExistingEngagementRunsOnlyTheNewCheck`).
  A SERVFAIL or timeout fails only the SRV check, which the next run retries. The known limitation
  (a service a later release drops stays current until `--redo dnsroot`) is about a future change
  to the list, not about this behaviour.
- **Behaviour 2: met, with the carried exception.** Each answer is a `resolutions.csv` row of type
  `SRV`, named by the service name, valued `priority weight port target`. A `.` target records
  nothing (read, as the Develop notes say, to mean no `resolutions.csv` row either). Service names
  never reach the inventory as hosts and are never wildcard-checked or resolved (only A, AAAA and
  CNAME rows are read by the inventory, the wildcard stage and the storage finding). An in-scope
  target is a hostname, resolved and probed; any other is a `third-parties.csv` row with mechanism
  `srv`, the registrable domain, `provider.DomainOwner` and depth 0, and is not a candidate. The
  exception, listed under Known limitations and in "Carried from built specs" but not under
  `## Out of scope`: a target that a root added later brings into scope becomes a hostname only
  after `--redo dnsroot`, because the check key does not carry the scope (its third-party row does
  hide at once).
- **Behaviour 3: met.** `ips.csv` gains `srv_ports` as its last column, derived on read from the
  current SRV rows whose target is an in-scope hostname of the address, sorted, distinct and
  `;`-joined. The ports stage and the egress policy keep to the configured list; the canary test
  puts every SRV port on every address and none is dialled. Port 0 is left out (an interpretation:
  it is "not offered", like a null target).
- **Behaviour 4: met.** The five labels are appended, deduplicated, to the root check's words only
  (seed checks use the plain wordlist), only while the stage is configured (so not under
  `--no-permutations`), and not under a known wildcard zone. The root key gains `|wk=<token>`, so
  adding the labels repeats each root check once and no seed check; a root check's `Cost` counts
  the labels. The budget deferral of that repeat is the same as for any wordlist change, which the
  behaviour asks for.

Changed during verification:

- `README.md`: the well-known-labels note said a root check is "4865 with the built-in list". The
  built-in wordlist already holds all five labels, which are deduplicated, so a root check stays at
  4860 names. The note now says so.

## Code review

`/code-review high --fix` found six issues and fixed one; `make test` passes afterwards.

Fixed:

- `srvKeyToken` and `wellKnownToken` were two copies of the same sha256-of-the-list code. Both now
  call `listToken` in `internal/stages/dns/dns.go`. The tokens are byte-for-byte the same, so no
  check key changes (behaviours 1 and 4 untouched).

Left unfixed:

- **An edited service list leaves the old SRV check's rows current** (`DNSRoot` is not `Retiring`).
  Already a known limitation; making the stage `Retiring` would also retire the NS, SOA, TXT and
  CAA checks of a root that leaves the inputs, which no behaviour asks for.
- **An internal SRV target is reported as a third party.** `_ldap`/`_kerberos` records often name
  internal hosts (`dc01.corp.local`, or a single label), which become a `srv` row for `corp.local`.
  Behaviour 2 says any target outside the scope is a third-party row by registrable domain, so
  changing this is a decision for the user.
- **Port 0 is treated two ways.** `srv_ports` leaves a port-0 record out, but the stage still
  records its target as a hostname or third party. The spec only defines `.` as "records nothing",
  so either half is a defensible reading; the user should pick one.
- **One timeout or SERVFAIL discards the whole SRV check.** This is what the design and README
  specify.
- **SRV rides through `rootInput` as a pseudo `rootType`.** A style choice; documented and tested.

# Follow-ups

1. Run the linter with a golangci-lint built with Go 1.27.3 or later (the installed one is built
   with Go 1.26 and refuses the module):
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest && golangci-lint run ./...`.
2. Live check against a domain you are authorised to test that publishes SRV records (for example a
   Microsoft 365 tenant's `_sip._tls` and `_sipfederationtls._tcp`):
   `make build && ./nyx --passive --output-dir /tmp/nyx-srv <domain>`, then confirm the `SRV` rows
   in `/tmp/nyx-srv/<engagement>/resolutions.csv`, the `srv` rows in `third-parties.csv` and, after
   an active run, the `srv_ports` column of `ips.csv`.
3. Decide whether the well-known labels should repeat root checks for engagements on the built-in
   wordlist. It already holds all five labels, so the repeat re-queries exactly the same ~4860 names
   per root and spends the per-run cap (about 40 roots a run). The alternative is to key the root
   check on the effective word list (`root|<root>|wl=<hash>|wk=<token>` in
   `internal/stages/dns/permutations.go`, `Checks`).
4. Decide how an SRV target outside the scope that is an internal name (`dc01.corp.local`, a
   single label) should be shown; today it is a `srv` third party (`dependency` in
   `internal/stages/dns/dnsroot.go`).
5. Decide what an SRV port of 0 means and apply it in one place (`dnsname.SRV` in
   `internal/dnsname/dnsname.go`): today `srv_ports` drops it but the target is still recorded.
6. Decide whether an edited SRV service list should retire the old check's rows (`DNSRoot` would
   need `run.Retiring` in `internal/stages/dns/dnsroot.go`); until then `nyx --redo dnsroot -e
   <engagement>` retires them.
7. An SRV target that a root added later brings into scope becomes a hostname only after
   `nyx --redo dnsroot -e <engagement>`; decide whether the `dnsroot` check key should carry the
   scope.
