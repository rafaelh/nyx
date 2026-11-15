# Spec 10: reverse lookups from in-scope addresses

## Goal

Every dedicated address nyx has recorded is asked which other hostnames point at it, so sibling
sites and related domains hosted on the organisation's own servers are found.

## Behaviours

1. A `reverseip` stage, available under `--passive`, performs one check per recorded address
   that is inside an in-scope netblock or port-eligible, is not excluded, has a known owner and is
   not shared provider infrastructure. It never enumerates every address of a netblock. It asks
   HackerTarget's reverse IP lookup (unkeyed, IPv4 only) and, when `keys.securitytrails` is set,
   SecurityTrails' list of domains whose current A or AAAA record is the address.
2. A returned name under an in-scope root is recorded as a hostname. Any other name contributes
   its registrable domain as a candidate root in `candidates.csv` (the hostname itself is not
   kept). An excluded name is recorded as excluded. No names, or HackerTarget's "no records"
   reply, completes the check with nothing.
3. If one address returns more than `reverseip.max_domains` distinct registrable domains (default
   100), none are recorded and a `--verbose` warning names the address: it is treated as
   unrecognised shared hosting.
4. HackerTarget's quota behaviour is as in Spec 1 behaviour 5. Hostnames already obtained from
   Shodan (Spec 4) are not fetched again here.
5. A candidate root found on two or more distinct addresses contributes the reverse-IP signal
   defined in Spec 15.
6. Each address is queried once per engagement; new results arrive only with `--redo reverseip`.
   The README's passive-boundary section names HackerTarget.

# Design

**Status:** ready to build (wave 2). Specs 1 and 15 have merged, and on 2026-11-14 the evidence
source was corrected to the name the family table holds (`reverseip`, not `reverse-ip`).
**Depends on:** Spec 1 (`ErrQuota`, `Warnf`, `CleanName`) and Spec 15 (candidate evidence).
Independent of Spec 4: behaviour 4's second sentence is read as "this stage
never calls Shodan" (confirm that reading; the alternative is to skip addresses `shodan-host` has
already answered, which would make this spec wait for Spec 4).

## Decisions

- **One stage, `reverseip`**, in `internal/stages/reverseip`, always configured, with sources
  `api.hackertarget.com` and `api.securitytrails.com`.
- **Checks** come from `View.IPs`, keeping an address that is in an in-scope netblock or
  port-eligible, not excluded, with a known owner and not shared. It never iterates
  `Scope.IPv4Addrs()`. Key: `<addr>|max=<n>`. An IPv6 address is yielded only when the
  SecurityTrails key is set, since HackerTarget cannot answer it; it gets its check when a key is
  added. As for Cert Spotter in Spec 1, a key added later applies to checks not yet done.
- **`Run`** asks HackerTarget (`reverseiplookup/?q=<addr>`, IPv4) and, when keyed, SecurityTrails'
  domain search filtered by the address, and merges the names through `httpsrc.CleanName`.
  HackerTarget's quota body or a 429 is `ErrQuota`: the 429 through `httpsrc.GetQuota`, and the
  quota body, which arrives with a 200, by the reply rules the `hackertarget` subdomain stage
  already has (`hackertargetNames` in `internal/stages/subdomains`). Move that function to
  `httpsrc` and call it from both stages; do not write the rules twice.
- **Recording**: a name the scope classifies in scope or excluded is a `hostname` observation
  (scope then lists it as a subdomain or as excluded); any other name contributes its registrable
  domain as a `root` observation and the hostname is dropped. The check input carries the scope.
- **The shared-hosting guard counts distinct registrable domains**; above
  `reverseip.max_domains` (default 100, minimum 1) nothing is recorded and `run.Warnf` names the
  address. The cap is in the key, so changing it re-asks.
- **Evidence**: `Evidencer` returns (`reverseip`, the address). `reverseip` is the stage's own
  name and the reverse IP entry of the family table as built; any other spelling would be a
  family of its own and the medium rule would never fire. The item leaves out the key's `max=`,
  so changing the cap does not count an address twice. A root seen on two addresses has two pairs
  and meets Spec 15's medium rule with no extra code.

## Changes

- `internal/stages/reverseip/`. `internal/cli/cli.go`: registered after `shodan-host`'s place.
- `internal/config/config.go`: `reverseip.max_domains`.
- `internal/candidates`: nothing. `reverseip` is in the family table.
- `internal/stages/httpsrc/httpsrc.go`: HackerTarget's reply rules, moved from `subdomains`.
- `README.md`: HackerTarget in the passive-boundary list, the stage, the setting, the
  `--redo reverseip` note, and `reverseip` moved out of the sentence that lists the reserved
  source names.

## Tests

`internal/cli/reverseip_test.go`:

- Only dedicated, known-owner, non-excluded addresses are asked; a netblock's unrecorded addresses
  are not; shared and unknown-owner addresses are not.
- In-scope names become hostnames, others become candidate roots without the hostname, excluded
  names land in `excluded.csv`; "no records" completes with nothing.
- More than the cap records nothing and warns; changing the cap re-asks.
- HackerTarget quota stops the stage and retries next run; with a SecurityTrails key both are
  asked and IPv6 is covered; the key never appears in output.
- A root on two addresses is `medium` in `candidates.csv` with `reverseip` in `sources`, and stays
  at two pairs after the cap is changed and both addresses are asked again; once per engagement
  until `--redo reverseip`; **canary:** no candidate root is resolved or contacted.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Family table (Spec 15, follow-up 2).** `reverseip` was reserved in the table for this stage.
  Take it out of the README sentence that lists the reserved names.
- **Keyed aborts.** `httpsrc.Get` aborts a keyed stage on a 401, 403 or 429. A rejected
  SecurityTrails key therefore stops the whole stage, HackerTarget lookups included, until the
  key is fixed or removed. Say so in the README beside the key.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname under a root the user promotes later was dropped when its address was asked, so it
  is recorded only after `--redo reverseip`. Putting the scope in the key would ask every address
  again on every scope change, against a small unkeyed quota. The README's `--redo reverseip`
  note says so.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates, so a
  wildcard name gives its parent. The hostname helpers are merged in one change after Specs 4,
  10, 13 and 17.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warning of behaviour 3 is a
  WARN line, shown without a flag.

## Out of scope

Shodan as a reverse source (Spec 4 covers it); enumerating netblocks.

# Implementation

## Develop

Built as designed, with the design's reading of behaviour 4: the stage never calls Shodan. Spec 4 has
merged (`shodan-host` is in the family table as passive DNS), so the alternative reading, skipping
addresses `shodan-host` has answered, was possible, and was not taken. The user has not confirmed
the reading: it is cheap to change, since `Checks` would only need to drop the addresses with a
completed `shodan-host` check.

- `internal/stages/reverseip` is the stage. `Checks` takes `View.IPs` filtered by
  `View.PortEligible` (which already means in an in-scope netblock, or dedicated, known owner, not
  shared, and never excluded), plus the IPv6 rule: an IPv6 address is yielded only when
  `keys.securitytrails` is set. The key is `<addr>|max=<n>`, and `Evidence` returns (`reverseip`,
  the address). `Run` asks HackerTarget (IPv4) and SecurityTrails (when keyed), merges the names
  through `httpsrc.CleanName`, counts distinct registrable domains for the guard, then records a
  `hostname` for an in-scope or excluded name and a `root` for any other.
- `httpsrc.HackerTargetLines` holds HackerTarget's reply rules (empty and "nothing found" replies
  are no lines, the spent-quota text is `run.ErrQuota`). The design said to move `hackertargetNames`;
  that function reads `host,address` lines, which only hostsearch has, so the rules moved and the
  `host,address` cut stayed in `subdomains`. Both stages call it.
- `reverseip.max_domains` (`--reverseip-max-domains`, default 100, minimum 1) is in `config`, with a
  case in `TestPerRunCapSettings`.
- Behaviour tests are in `internal/cli/reverseip_test.go`, one for each line of `## Tests`: the
  address set (including IPv6 waiting for the key), names by scope, each "no records" reply, an
  unreadable reply, the guard at exactly the cap and one over, a changed cap, both quota forms,
  SecurityTrails merged with HackerTarget and the key never in output, a rejected key stopping the
  stage, medium confidence on two addresses (and unchanged after the cap changes), once per
  engagement and `--redo reverseip`, the canary, registry order and help, and the README.
- Existing tests that changed: `TestRiskStageRegistry` lists `reverseip`; the unkeyed quota test
  skips `reverseip`, and the rerun test counts only `/hostsearch/` requests, because the two stages
  share `api.hackertarget.com`.

Mutation checks: `## Tests` marks none, so these were spot-checks of the riskiest guards, each broken by
hand, run, and undone by hand. Dropping `PortEligible` from `Checks` fails
`TestReverseIP_AsksOnlyDedicatedKnownOwnerAddresses`. Dropping the IPv6 key gate fails
`TestReverseIP_IPv6WaitsForTheKey`. Putting the cap in the evidence item (the whole check key, not the
address) fails `TestReverseIP_RootOnTwoAddressesIsMedium`. Changing the guard's `>` to `>=` fails
`TestReverseIP_SharedHostingGuard`.

Deviations and facts that differ from the design:

- A 404 from either source is "no names", as for the subdomain sources. HackerTarget does not 404
  a reverse lookup, so this only keeps the fake world's default answer from failing every check.
- A HackerTarget line containing a space, comma or angle bracket makes the reply unreadable (an
  error, retried), so an HTML error page is never recorded as "no names".
- The "no records" reply of the reverse lookup is written from memory of HackerTarget as
  `No DNS A records found for <address>`. The rules accept that as well as the two hostsearch
  replies. Neither it nor the SecurityTrails request was checked against the live service.

## Known limitations

- **Behaviour 1 (SecurityTrails):** the request is `POST /v1/domains/list` with
  `{"filter":{"ipv4"|"ipv6": <address>}}`, read for `records[].hostname` and `pages`. It was written
  from memory of SecurityTrails' documentation, whose pages could not be fetched here, so the
  request shape and the response field names are untested against the real API. Its page size is
  assumed to be 100.
- **Behaviour 1:** SecurityTrails is read for at most 10 pages per address (one query credit each),
  and stops once the guard's cap is passed; an address that needs more has the rest dropped, with a
  WARN line, and the check completes.
- **Behaviour 2 and 6:** the check key carries no scope, so a name under a root promoted later is
  recorded only after `--redo reverseip` (as designed; the README says so).
- **Behaviour 3:** the guard counts registrable domains across both sources together, after
  cleaning; a name with no registrable domain is not counted.

## Simplify

Fixed:

- `reverseip` gathers names into one running set of cleaned names and their registrable domains.
  The shared-hosting guard and SecurityTrails' early stop now both read that set, instead of two
  separate counting loops that re-cleaned every name on every page. Each name is now cleaned and
  its registrable domain looked up once. The source errors are wrapped in one place.
- SecurityTrails is not asked about an address that HackerTarget alone already shows to be shared
  hosting. The result is the same (nothing recorded, one WARN line), and it saves 1 to 10 credits
  per such address.
- `httpsrc.GetNames` (GetQuota, where a 404 is no names, then parse) replaces the copy in
  `reverseip`. `subdomains.fetchNames` wraps it.
- `httpsrc.HackerTargetLines` lowercases only the first 40 bytes of the reply to match the short
  replies, not the whole body.
- Tests: `slices.Sorted(maps.Keys(...))` replaces `keysOf`. `candidate(value)`/`candidates()` use
  `find`, and the never-varied `typ` parameter and `candidate0` are gone. A named `stQuery` type is
  shared by the SecurityTrails fake and `stAsked`. The README test uses `readmeSection`. The
  hostsearch count uses `source.count`. The duplicate registry-order assertion is dropped, since
  `TestRiskStageRegistry` pins it. So is the second run in each "no records" subtest, since
  `TestReverseIP_OncePerEngagementUntilRedo` covers it.

Skipped:

- Stopping every stage that shares a source host (here `hackertarget` and `reverseip`) when one
  hits the HackerTarget quota. This is a runner change well outside this diff.
- Splitting `reverseip` into one stage per source. The design chose one stage, so that the guard
  counts across both sources.
- A shared "name found on an address → hostname or candidate root" helper with `shodan-host`. The
  two treat excluded names differently, and the build order defers merging those helpers.
- Moving the space/comma/angle-bracket line rejection into `HackerTargetLines`. Hostsearch lines
  are `host,address`, so a comma is valid there.
- Checking `View.Done` before `PortEligible` in `Checks`. The saving is small, and it would differ
  from `shodan-host`.
- A test helper for the repeated dedicated-address setup (`host` plus `owner`). It is optional.

# Verification

## Result

Checked against the code on 2026-11-15. `make test` passes (vet for the four targets, then
`go test -race ./...`). `golangci-lint` could not run: the installed binary is v1.64.8, built with
Go 1.26, and `.golangci.yml` is a v2 config.

- **Goal: met.** Every port-eligible recorded address (an in-scope netblock address, or one an
  in-scope hostname resolves to whose owner is known and not shared, never excluded) is asked of
  HackerTarget and, with a key, SecurityTrails. In-scope names become hostnames and other names
  give their registrable domain as a candidate root.
- **B1: met, with one reading.** `Checks` takes `View.IPs` filtered by `View.PortEligible` (the same
  decision `shodan-host` and the port sweep use) and never iterates a netblock
  (`TestReverseIP_AsksOnlyDedicatedKnownOwnerAddresses`). HackerTarget is asked for IPv4 only, and
  SecurityTrails' domain search by `ipv4`/`ipv6` filter only with `keys.securitytrails`; an IPv6
  address gets its check once a key is set. The reading: an address inside an in-scope netblock is
  asked even when the provider table or a provider CNAME calls it shared, because
  `scope.PortEligible` treats in-scope netblocks as the user's own. Read literally, B1's "is not
  shared provider infrastructure" would also drop those (see Follow-ups). The SecurityTrails
  request shape is untested against the live API (known limitation).
- **B2: met.** `Run` cleans every name through `httpsrc.CleanName` (which drops addresses, single
  labels and public suffixes, and turns `*.x` into `x`), records a `hostname` for a name the scope
  classifies in scope or excluded (so it lands in `subdomains.txt` or `excluded.csv`), and a `root`
  for the registrable domain of any other name, once per root. An empty reply, HackerTarget's
  "No records found", "No DNS A records found …" and "error check your search parameter" complete
  the check with nothing; a reply that is not a list of names (an HTML page) fails the check, so it
  is retried rather than recorded as empty.
- **B3: met.** Distinct registrable domains from both sources are counted together; more than
  `reverseip.max_domains` records nothing and a WARN line (Spec 22 has merged) names the address and
  the setting. The cap is in the key (`<addr>|max=<n>`), so changing it re-asks every address. The
  setting has a flag, a config key and an env variable, default 100, minimum 1. When the cap is
  lowered, the earlier check under the higher cap is not retired, so roots it recorded stay
  current even if the address is now over the cap (the stage is not `Retiring`; see Follow-ups).
- **B4: met.** HackerTarget's 429 (through `httpsrc.GetQuota`) and its "API count exceeded" reply
  with a 200 (through `httpsrc.HackerTargetLines`, now shared with the `hackertarget` stage) are
  `run.ErrQuota`: the stage alone stops with one WARN line and the remaining checks are retried
  next run. The stage never calls Shodan; `## Out of scope` ("Shodan as a reverse source") supports
  that reading of the second sentence.
- **B5: met.** `Evidence` returns (`reverseip`, the address), the name the family table holds, and
  leaves out the cap; a root on two addresses is `medium` with `reverseip` in `sources`, and stays
  at two pairs after a cap change (`TestReverseIP_RootOnTwoAddressesIsMedium`).
- **B6: met.** Completed checks are not repeated; `--redo reverseip` asks again. The README's
  passive-boundary section names HackerTarget's reverse lookup, and the new `## Reverse IP` section
  covers the stage, setting, quota, key, IPv6 and refresh rules. `reverseip` left the reserved-names
  sentence. The canary test confirms no candidate root is resolved or contacted.

Changed while verifying:

- **README:** the candidate families sentence was missing the comma before "registrant" and ran
  long; it is re-flowed, keeping "The names" and "are reserved for stages that are not built yet"
  each unbroken, since `TestReverseIP_ReadmeSaysWhatItDoes` searches for both. The passive-boundary sentence
  now also says SecurityTrails receives the addresses when its key is set.

## Code review

`/code-review high --fix` reported seven issues and fixed two (with one extra README note). I kept
all of them after checking them against the spec. `make test` passes afterwards.

Fixed:

- **SecurityTrails' page count (B1, B3).** The stage read only a top-level `pages`. It now takes
  the larger of `pages` and `meta.total_pages`, where the domain search is believed to report it, so
  a shared address on SecurityTrails can still pass the cap. The field name is from memory and
  untested against the live API, like the rest of the request (known limitation).
- **README wording on SecurityTrails errors (B1).** Only a rejected key (401 or 403) stops the stage
  until the key is fixed; a 429 stops it for the run.
- **README note on a key added later (B1, B6).** The Refresh bullet says a SecurityTrails key
  added later reaches IPv4 addresses HackerTarget already answered only after `--redo reverseip`,
  as the design chose.

Left unfixed:

- **The check key leaves out whether SecurityTrails was keyed.** The design chose this ("a key
  added later applies to checks not yet done"), and `TestReverseIP_IPv6WaitsForTheKey` pins it.
- **Lowering `reverseip.max_domains` leaves the old check's roots current.** Making the stage
  `Retiring` would also retire the checks of addresses that are no longer port-eligible, which the
  spec does not ask for. It is a decision for the user (see Follow-ups).
- **`hackertarget` and `reverseip` each hit HackerTarget's spent quota separately**, so each logs
  its own WARN. Stopping every stage that shares a source needs a runner change outside this spec.
- **A failed SecurityTrails request re-asks HackerTarget on the retry.** The design keeps both
  sources in one check so the guard counts across them.
- **No `ip_hostname` link from an in-scope name to the address it was found on.** B2 asks only for
  the hostname, and the build order defers merging the hostname helpers this would share with
  `shodan-host`.

# Follow-ups

1. Confirm the reading of B4's second sentence: the stage never calls Shodan (built). The
   alternative, skipping addresses `shodan-host` has already answered, would drop the addresses
   with a completed `shodan-host` check in `Checks` in `internal/stages/reverseip/reverseip.go`.
2. Decide whether an address inside an in-scope netblock that the provider table or a provider
   CNAME calls shared should be asked. Built: it is, because `View.PortEligible` treats in-scope
   netblocks as the user's own. To drop it, add a shared check to the filter in `Checks` in
   `internal/stages/reverseip/reverseip.go` (`View` has no `Shared` method yet; it would go in
   `internal/run/stage.go`).
3. Decide whether lowering `reverseip.max_domains` should retire the roots recorded under the old
   cap. Today they stay current. Implementing `run.Retiring` on the stage would do it, but would
   also retire the checks of addresses that are no longer port-eligible.
4. Check the SecurityTrails request against the live API with a real key: run
   `curl -s -X POST -H "APIKEY: $NYX_KEYS_SECURITYTRAILS" -H 'Content-Type: application/json' -d '{"filter":{"ipv4":"<a known address>"}}' 'https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=false&page=1'`
   and confirm the endpoint, `records[].hostname`, the page size and where the page count is
   (`pages` or `meta.total_pages`). Adjust `securityTrails` in
   `internal/stages/reverseip/reverseip.go` if any differ.
5. Check HackerTarget's "no records" reply for the reverse lookup: run
   `curl -s 'https://api.hackertarget.com/reverseiplookup/?q=192.0.2.1'` and confirm the text
   matches a case in `httpsrc.HackerTargetLines` (`internal/stages/httpsrc/httpsrc.go`).
6. Run the stage live once: `nyx --passive --output-dir /tmp/nyx-out <a domain you are authorised
   for>`, then check `candidates.csv` for `reverseip` rows and the console for shared-hosting WARN
   lines.
7. Rebuild golangci-lint with the module's Go version (`go install
   github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`), then run
   `golangci-lint run --new-from-rev=main ./...`. It could not run during verification.
