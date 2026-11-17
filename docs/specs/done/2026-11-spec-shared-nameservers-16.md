# Spec 16: shared name servers and mail hosts as a relatedness signal

## Goal

Root domains that share an organisation's own name servers or mail hosts are found and offered as
candidates, because self-hosted DNS and mail are strong signs of common ownership, without ever
resolving a candidate.

## Behaviours

1. A name server or mail host is **self-hosted** only if it is in scope, or its address is inside
   an in-scope netblock or is a port-eligible dedicated address. Name servers and mail hosts on
   known providers, or whose address is shared infrastructure or of unknown owner, are never a
   signal and nothing is fetched for them. `resolutions.csv` NS rows and `email-posture.csv` MX
   entries gain a `self_hosted` marker.
2. An `nsreverse` stage, keyed on `keys.securitytrails` and available under `--passive`, fetches
   the domains hosted on each self-hosted name server and the domains whose MX is each
   self-hosted mail host, and records each as a candidate root with source `shared-ns` or
   `shared-mx`. Candidate roots are never resolved; this lookup is the only discovery path.
3. If a server has more than `nsreverse.max_domains` domains (default 1,000), none are recorded,
   the server is treated as not self-hosted for this purpose, and a `--verbose` warning names it.
   Changing the setting re-fetches. Quota exhaustion stops the stage as for other keyed sources.
4. A candidate found this way is at least `medium` confidence (Spec 15). Excluded roots stay
   excluded.
5. Without the key, the stage is `not-configured (no key)` and only the `self_hosted` marker is
   produced.

# Design

**Status: built.** (Was: review before building, wave 3.) Specs 3 and 15 have merged, and the items that
waited on them were settled against the code on 2026-11-14. Spec 9 has not merged: after it
does, re-read the one item still marked *Review*. The open point below still needs the user's
answer. **Depends on:** Spec 3 (NS rows from `dnsroot`), Spec 9 (the email check it edits),
Spec 15 (the family table and the medium rule).

## Open point to settle at review

A name server or mail host outside scope has no address on record, because `resolve` looks up
only in-scope and excluded names. Deciding whether such a host is self-hosted "by address" needs
its A and AAAA records. This design proposes that `dnsroot` and `email` look those up through the
public resolvers and store them in a kind nothing else reads. That is a DNS lookup of a name that
is not in scope: allowed by the passive boundary (a public resolver is asked, the host is not
contacted), but new for nyx. The alternative is to treat only in-scope hosts as self-hosted and
drop the address clauses of behaviour 1. Confirm before building.

**Settled 2026-11-17 (user):** yes, `dnsroot` and `email` look up the addresses of out-of-scope name
servers and mail hosts. A lookup that fails (SERVFAIL or a timeout) is best-effort: it gives the
host no address and never fails or retires the check that found it, so the NS and email checks keep
their existing failure rules.

## Decisions

- **Server addresses are their own kind**, `server_address` (key `host|addr`; `host`, `addr`,
  `role` `ns` or `mx`), written by `dnsroot` for NS targets and by the email check for MX hosts.
  The inventory, scope and egress policy do not read it, so a looked-up server never becomes
  resolved, probed or port-checked because of it.
- **Self-hosted is derived on read**: `inventory.SelfHosted(host, sc)` is true when the host is in
  scope, or any `server_address` of it is inside an in-scope netblock or is port-eligible, and
  false when the host's domain is a known provider (`provider.DomainOwner`) or its address is
  shared or of unknown owner. As built, `provider.Default().DomainOwner(name)` matches the
  `domains:` list by suffix. Route 53 name servers (`ns-123.awsdns-45.com`) match no entry,
  because the number is inside the label, so they are not ruled out by name: they are ruled out
  by address (shared), which costs their address lookups if the open point is answered that way.
- **Markers**: `resolutions.csv` gains `self_hosted` (`yes`/`no` on NS rows, blank otherwise);
  `email-posture.csv` gains `mx_self_hosted` (the self-hosted MX hosts, `;`-joined). Both are
  computed when the file is written. The build-order plan gives the order: `self_hosted` follows
  `source` in `resolutions.csv` and comes before Spec 7's two date columns, and `mx_self_hosted`
  follows Spec 9's `mta_sts` in `email-posture.csv`.
- **`nsreverse`** (`internal/stages/nsreverse`, keyed on `securitytrails`, third-party) yields one
  check per self-hosted name server (`ns|<host>|max=<n>`) and mail host (`mx|<host>|max=<n>`).
  `Run` asks SecurityTrails' domain search filtered by that server, reads the total first, and if
  it is above `nsreverse.max_domains` (default 1,000) records nothing and warns; otherwise it
  records each domain's registrable domain as a `root` observation. A 401, 403 or 429 already
  aborts a keyed stage in `httpsrc.Get`, which is the quota rule of behaviour 3; the stage adds
  no quota code.
- **Evidence**: `Evidencer` returns (`shared-ns` or `shared-mx`, the server), which is what puts
  those two names in the `sources` column (behaviour 2), and leaves the key's `max=` out of the
  item. As built, the family table holds this stage under its stage name, `nsreverse`, and looks
  a source up by exact name, so `shared-ns` and `shared-mx` would each be a family of its own:
  the shared-infrastructure medium rule would never fire, and a root both found would count as
  two families. This spec replaces the `nsreverse` entry with `shared-ns` and `shared-mx`, both
  shared infrastructure. One such pair is then `medium` by the rule as built.
- **Candidate roots are never resolved**: the stage emits only `root` observations, which
  `resolve` does not look up. Excluded roots stay excluded by the scope's existing rule.

## Changes

- `internal/kinds/serveraddress.go`. `internal/stages/dns/dnsroot.go` and
  `internal/stages/risk/email.go`: the address lookups (*Review:* both files as built).
- `internal/inventory/inventory.go`: `SelfHosted`; `inventory.Data` gains the server addresses.
- `internal/stages/nsreverse/`; registered after `email`.
- `internal/candidates/candidates.go`: `shared-ns` and `shared-mx` in place of `nsreverse` in the
  family table.
- `internal/output/output.go`, `evidence.go`: the two columns.
- `internal/config/config.go`: `nsreverse.max_domains`. `README.md`: the stage, the setting, the
  two columns, the `--redo` notes, and `shared-ns` and `shared-mx` as `sources` values in place of
  the reserved `nsreverse`.

## Tests

- `internal/inventory`: `SelfHosted` for an in-scope host, an address in a netblock, a
  port-eligible address, a provider-hosted server, a shared address and an unknown owner.
- `internal/cli/nsreverse_test.go`: markers in both files with and without the key; nothing is
  fetched for provider-hosted servers; candidates carry `shared-ns` or `shared-mx` and are `medium`;
  a root found by both is still one family; above the cap nothing is recorded, a warning names the
  server, and changing the cap re-fetches; quota stops the stage; without the key the stage is
  `not-configured (no key)`; **canary:** no candidate root is resolved and no looked-up server
  address is contacted.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Family table (Spec 15, follow-up 2).** `nsreverse` was reserved in the table for this stage.
  The entry changes as the Evidence decision says; update the README sentence that lists the
  reserved names.
- **`Score` already assumes this stage reports only self-hosted servers (Spec 15).** Its medium
  rule fires on any shared-infrastructure evidence. The stage must never emit a root for a server
  that is not self-hosted, or that is above the cap.
- **The `dnsroot` check key does not carry the scope (Spec 3).** A name server that a root added
  later brings into scope becomes a hostname only after `--redo dnsroot`. Its `self_hosted`
  marker is computed on read, so it is right at once; its `nsreverse` check appears once it is
  self-hosted by either test.
- **`dnsroot` checks are per root and type (Spec 3)**, keyed `<root>|<TYPE>`. The NS address
  lookups of the open point join the `NS` check, so adding them to an existing engagement needs
  a token on that key, or they arrive only with `--redo dnsroot`. Decide which with the open
  point. *Review:* the same question for the email check, whose key Spec 9 changes.
- **Kinds the scope build reads (Spec 3, follow-up 3).** `inventory.Data` gains the server
  addresses, so `server_address` joins the kinds the scope build reads (`scopeKinds` in
  `runner.go`, or `run.BuildScope` once Spec 21 has merged). A pass that writes one then rebuilds
  the scope and inventory, as a pass that writes `resolution` rows already does. Nothing that
  decides contact may read it, and the canary test pins that.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The `self_hosted`
  marker is blank on a not-current `resolutions.csv` row.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warning of behaviour 3 is a
  WARN line, shown without a flag.

## Out of scope

Comparing NS sets across roots already on record; SOA mailbox pivots.

# Implementation

## Develop

Built as designed, with the open point settled as the design proposed (see above), and the failure
rule for the new lookups that the user chose: best-effort, for the name servers as well as the mail
hosts. The steps below were done in the order of the design's `## Changes`.

- `kinds.ServerAddress` (`internal/kinds/serveraddress.go`): key `host|addr`, attributes `host` and
  `addr` (the designed `role` was dropped at simplify: nothing read it). It is read only by `run.BuildScope`, which turns it into
  `inventory.Data.ServerAddresses`, and it is in `scopeKinds`, so a pass that writes one rebuilds the
  scope and re-ranks the candidates, as a pass that writes `resolution` rows already does.
- `inventory.SelfHosted(host, sc)` and `View.SelfHosted`: true for an in-scope host, or when any
  looked-up address is `PortEligible` (inside an in-scope netblock, or dedicated, of known owner, and
  used by an in-scope host); false for an excluded host, and for a host on a known provider's domain
  (`provider.DomainOwner`) whatever its addresses. Shared and unknown-owner addresses are not port
  eligible, so they never count. A server that is in scope needs no address.
- `internal/stages/serveraddr` is the one lookup, used by both stages: A and AAAA of a host that is
  not in scope, not excluded, not on a provider's domain and not an address. It is best-effort (a
  SERVFAIL or a timeout gives no addresses); only a cancelled context is an error. It lives in its own
  package because `dns` and `risk` are siblings and both need it.
- `dnsroot`: the NS check looks up each distinct name server and appends the observations. Its key is
  `<root>|NS|addrs`, so an engagement from before asks its NS records once more. The SOA primary is
  not looked up (an SOA primary is not a name server of the root's delegation).
- `email`: the check looks up each distinct MX host after the posture is built. Its key ends
  `|mta-sts|addrs`. The check's input is now a small struct holding the root and the scope.
- `nsreverse` (`internal/stages/nsreverse`, registered after `email`): one check per self-hosted
  name server and mail host of an in-scope root, keyed `ns|<host>|max=<n>` and `mx|<host>|max=<n>`,
  read from the current `NS` resolution rows and the `email_posture` MX lists. `Run` POSTs
  `/v1/domains/list` with `{"filter":{"ns"|"mx": <host>}}`, reads the total (`record_count`, or the
  records on the page if larger) from the first page and records nothing above the cap, else records
  each domain's registrable domain as a `root`. `Evidence` returns `shared-ns` or `shared-mx` and the
  host, leaving the cap out. A 401, 403 or 429 aborts the stage in `httpsrc.Get`; the stage has no
  quota code of its own.
- The family table has `shared-ns` and `shared-mx` in place of `nsreverse`, both shared
  infrastructure. `candidates.Score` is unchanged: its medium rule already fires on that family.
- `resolutions.csv` has `self_hosted` after `source`, and `email-posture.csv` has `mx_self_hosted`
  after `mta_sts`, both computed when the file is written. `nsreverse.max_domains`
  (`--nsreverse-max-domains`, default 1000, minimum 1) is in `config`. The README has the section,
  the setting, the two columns, the `--redo` notes and the two new `sources` values.

How each behaviour is tested (`internal/cli/nsreverse_test.go` unless stated):

1. *Self-hosted and the markers:* `internal/inventory/selfhosted_test.go` has a case for an in-scope
   host, a netblock address, a port-eligible address, a provider-hosted server (inside a netblock, to
   show the name wins), a shared address, an unknown owner, an excluded address and host, and one
   good address among bad ones; `TestServerAddressesChangeNothing` shows the addresses change nothing
   the inventory reports. `TestNSReverse_MarkersInBothFiles` checks the two columns and their
   positions, and `TestNSReverse_AddressLookupsAreBestEffort` checks that a provider's server is not
   looked up, an unknown server is asked for A and AAAA once, and a SERVFAIL fails neither check.
2. *The stage and the sources:* `TestNSReverse_AsksOnlySelfHostedServers` (five servers asked, the
   provider, shared and unknown ones not, with the check keys) and
   `TestNSReverse_CandidatesAreSharedAndMedium` (sources `shared-ns`, `shared-mx` or both, evidence
   counts, `medium`, no candidate for the engagement's own root).
   `TestNSReverse_NothingFoundIsContacted` is the canary: a full authorised run, with the looked-up
   addresses mapped to listeners on 25, 53, 80 and 443 that must see nothing, no candidate root
   queried for any type, and no server resolved, probed or in `ips.csv`.
3. *The cap and quota:* `TestNSReverse_CapRecordsNothingAndWarns` (exactly the cap is recorded; a
   server whose total is over it records nothing although its page is short, is asked once, and is
   named in one warning; raising the cap records it), `TestNSReverse_ChangingTheCapAsksAgainWithoutCountingTwice`,
   `TestNSReverse_QuotaStopsTheStage`.
4. *At least `medium`, excluded stay excluded:* the candidates test and
   `TestNSReverse_ExcludedRootStaysExcluded`; `internal/candidates` has the family cases (a shared
   name server and mail host are one family, so with one more family they are two, not three).
5. *Without the key:* `TestNSReverse_WithoutKeyOnlyTheMarkers` (`not-configured (no key)`, no
   SecurityTrails search, markers still present, no candidates).
- Check keys: `TestNSReverse_ExistingEngagementLooksUpAddressesOnce`; the setting is a case in
  `TestPerRunCapSettings`.

Mutation checks: `## Tests` marks none, so these were spot-checks of the riskiest guards, each
broken by hand, run, and undone by hand (the last three through a saved copy of the file). Dropping the
provider-domain rule from `AddressDecides` fails `TestSelfHosted`; loosening the port-eligible test
to "owner known" fails `TestSelfHosted`; the cap's `>` as `>=` fails
`TestNSReverse_CapRecordsNothingAndWarns`; leaving the cap in the evidence item fails
`TestNSReverse_ChangingTheCapAsksAgainWithoutCountingTwice`; removing `shared-mx` from the family
table fails `TestFamily` and `TestScore`; a SERVFAIL on a server address failing the check fails
`TestNSReverse_AddressLookupsAreBestEffort`; the marker on a non-NS row fails
`TestNSReverse_MarkersInBothFiles`; and making a server address a resolution fails the canary
`TestNSReverse_NothingFoundIsContacted`. Each failed at least one test, and none needed a new one.

Existing tests that changed because the design changes what they pin: the `dnsroot` tests that
assert the key `<root>|NS` and that an out-of-scope name server is never queried (a provider's still
is not; an unknown one now has its address asked, and still has no resolution row or hostname), the
email key suffix in the MTA-STS test, the column headers in four tests, the stage order in
`TestRiskStageRegistry`, and the candidate cases that named `nsreverse`.

## Known limitations

- **Behaviour 2 (SecurityTrails):** the request is `POST /v1/domains/list` with
  `{"filter":{"ns"|"mx": <host>}}`, read for `records[].hostname`, `record_count` and `pages` or
  `meta.total_pages`. It was written from memory of SecurityTrails' domain search (its documentation
  pages could not be fetched here), so the filter names and the response field names are untested
  against the real API. If `record_count` is not the total of matching domains, the cap is applied
  to the first page's length instead, which is a weaker guard. Its page size is assumed to be 100.
- **Behaviour 1:** an address lookup that fails is not retried until `--redo dnsroot` or
  `--redo email`, because the check completes. A server whose address was missed is not self-hosted
  until then, and its `self_hosted` marker is `no`.
- **Behaviour 1:** an address is only known for a server outside the scope if `dnsroot` or `email`
  looked it up. Its owner is known only if another record gave it (an in-scope host on the same
  address, or a provider range): `ipowner` does not ask about server addresses, as they are not `ip`
  records. A dedicated address that nothing in scope uses is therefore never self-hosted, which is
  the cautious reading.
- **Behaviour 3:** the cap decides the fetch only. The `self_hosted` marker does not change when a
  server is over the cap, since it is a statement about the address. Lowering the cap does not
  retire the roots recorded under a higher one (the same limit as `reverseip.max_domains`).
- **Behaviour 2:** the check key carries no scope or self-hosted result. A server that becomes
  self-hosted later is asked then, but one that stops being self-hosted keeps the roots it gave until
  `--redo nsreverse` (no `Retiring`).
- A server found only through an SOA primary is not looked up, and MX hosts are looked up only for
  roots the email check covers (in-scope input roots).

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) read the change.

Fixed:

- The SecurityTrails domain search was written twice, in `nsreverse` and `reverseip`. Both now call
  `httpsrc.SecurityTrailsDomains`. It takes the filter, a page cap and a callback per page that
  returns whether to stop. Each stage keeps only its own cap rule.
- The `role` attribute of `server_address`, and the `kinds.ServerRoleNS`/`ServerRoleMX` constants,
  were written but never read. They were also wrong for a host that is both a name server and a
  mail host, because the key has no role. All of them are removed, as is `serveraddr.Observations`'
  `role` parameter. `nsreverse` keeps its own `ns`/`mx`, which are filter names and key prefixes.
- The rule "could this host's addresses make it self-hosted" was written in both `serveraddr` and
  `inventory.SelfHosted`. It is now `inventory.AddressDecides`, and both call it.
- `dns.addrsOf` is now `egress.DNSResult.Addrs`, which `resolve`, `wildcard` and `serveraddr` use.
  `serveraddr` uses `input.IPLiteral` for the address test.
- The `|addrs` key token was defined in both `dnsroot` and `email`. It is now
  `serveraddr.KeyToken`.
- `scopebuild` no longer unmaps server addresses, because `inventory.New` already does. The
  repeated `dnsroot` doc paragraph is cut, and the long line in `email`'s `Run` doc is wrapped.
- Tests: the `stShared` fake is folded into `stReverse` (`reverseip_test.go`), which now also
  answers searches by `ns` and `mx`. `x.stServers()` reads the harness's request log in place of a
  second log of its own.

Skipped:

- Moving the address lookups into their own stage, one check per host. The altitude and efficiency
  reviewers both raised it. It would give a retry per host, no key tokens on `dnsroot` and `email`,
  and one lookup per shared server instead of one per root. Skipped because it reverses the design
  the user settled (the open point above). It is the better answer to Follow-up 2 if lost lookups
  matter.
- Running the A and AAAA lookups, or the MX address lookups, concurrently. The DNS rate limit
  applies anyway, and few hosts get past `AddressDecides`.
- A separate list of kinds read only by the inventory, so that a `server_address` write would not
  re-rank candidates. That would be a special case in the runner for a cost seen only with many
  candidates.
- Checking the resolution key in `nsreverse.Checks` before decoding it. Decoding is cheap and
  `wildcard` does the same.
- Shortening the `nsreverse` `Stage` and `SelfHosted` doc comments beyond the cuts above. Removing
  the address assertions in `TestNSReverse_AddressLookupsAreBestEffort` that `TestDNSRoot_NameServers`
  also makes. Both are minor.

# Verification

## Result

The goal is met, with the limits below. Roots that share a self-hosted name server or mail host
are found through SecurityTrails and offered as candidates, and no candidate root is ever resolved
(the canary test queries none of them, for any type, in a full authorised run).

1. **Met, with one limit.** `inventory.SelfHosted` is in scope, or an address inside an in-scope
   netblock or port-eligible (dedicated, of known owner, used by an in-scope host); a known
   provider's domain, a shared address and an unknown owner never count, and an excluded host never
   counts. Nothing is fetched from SecurityTrails for those servers, and a provider-domain server
   is not even looked up. `resolutions.csv` has `self_hosted` after `source` (`yes`/`no` on current
   NS rows from nyx's own lookup) and `email-posture.csv` has `mx_self_hosted` after `mta_sts`, both
   computed on read. Partly met: a failed address lookup is not retried until `--redo dnsroot` or
   `--redo email` (Known limitations), so such a server reads `no` until then. A Shodan-only NS row
   (a record nyx's own lookup did not return) has a blank marker, consistent with "records only
   Shodan reports decide nothing". Out-of-scope servers are looked up through the public resolvers
   as the user settled, which includes a server whose name falls under a candidate root; the
   candidate root itself is never queried.
2. **Met, with one limit.** `nsreverse` is keyed on `securitytrails`, third-party (runs under
   `--passive`), registered after `email`, and asks only for self-hosted servers of in-scope roots,
   recording registrable domains as `root` observations with evidence `shared-ns`/`shared-mx`.
   Partly met: the check key carries no scope, and the stage does not retire, so a server that
   stops being self-hosted keeps giving its roots until `--redo nsreverse` (Known limitations). The
   SecurityTrails request and response field names are untested against the live API.
3. **Met, after a fix.** A server over `nsreverse.max_domains` (default 1000, flag
   `--nsreverse-max-domains`) records nothing and logs a WARN line naming it and the setting; the cap
   is in the key, so changing it re-fetches, and the evidence item leaves it out. A 401, 403 or 429
   aborts the stage through `httpsrc.Get`. **Fixed:** the cap was checked only against the first
   page (`record_count` or that page's length). If `record_count` were missing or short, later pages
   were never counted, so a server with up to 10,000 domains could be recorded whatever the cap. The
   stage now counts the domains listed across pages and, once the count passes the cap, drops
   everything it gathered and warns. The SecurityTrails test fake (`stReverse` in
   `internal/cli/reverseip_test.go`) gained an optional page size, and
   `TestNSReverse_CapCountsPagesWithoutATotal` pins the fix (it fails on the old code).
4. **Met.** `shared-ns` and `shared-mx` replace `nsreverse` in the family table as shared
   infrastructure, so one such pair is `medium` and a root found by both is one family. Excluded
   roots stay excluded.
5. **Met.** Without the key the stage is `not-configured (no key)`, nothing is asked of
   SecurityTrails for a server, and both markers are still written.

`README.md` documents the stage, the setting, the two columns, the `--redo` notes and the two new
`sources` values. `make test` passes.

## Code review

`/code-review high --fix` reported seven findings and applied two, both kept:

- **Mail-host address lookups ran one after another** after the email check's concurrent batch. They
  now run in that batch (`internal/stages/risk/email.go`), still best-effort, with the same results
  in the same order. Behaviour 1 (the addresses behind `mx_self_hosted`); no behaviour changes.
- **The README said every NS row carries `yes` or `no`**, but an NS row only Shodan reports is
  blank (nsreverse reads only nyx's own NS rows). The README now says the marker is on the NS rows of
  nyx's own lookup. Behaviour 1; documentation only.

Left unfixed:

- The old `<root>|NS` dnsroot check of an engagement from before is not retired when the
  `<root>|NS|addrs` check runs, so its NS rows stay current alongside the new ones until
  `--redo dnsroot`. dnsroot retires no checks; those rows would have stayed current without the
  token too, so nothing is worse than before. Changing dnsroot's retirement is outside this spec.
- A server with one port-eligible address and another inside an excluded CIDR counts as
  self-hosted. The spec does not say; it is a decision for the user (Follow-up 4).
- Lowering `nsreverse.max_domains` does not retire the roots recorded under a higher cap, and a
  server that stops being self-hosted keeps its roots (Known limitations; Follow-up 3).
- The cap counts listed hostnames, while `reverseip.max_domains` counts distinct registrable
  domains. The spec says "domains" and the README describes the count, so it was left.
- `nsreverse.Checks` reads every `resolution` record to find the NS rows. Minor cost; a narrower
  read needs a store change.

golangci-lint could not run here (the installed build uses Go 1.26, older than the module's Go
1.27.3); `go vet` for all four targets is clean.

# Follow-ups

1. Run one real `nsreverse` lookup with a SecurityTrails key and check the filter names (`ns`,
   `mx`), that `record_count` is the total of matching domains, and the page size, for example
   `NYX_KEYS_SECURITYTRAILS=<key> ./nyx <a domain with its own name servers> --passive
   --output-dir /tmp/nyx-out`, then read `candidates.csv` for `shared-ns` rows. If a name is wrong
   the fix is in `httpsrc.SecurityTrailsDomains` (`internal/stages/httpsrc/securitytrails.go`),
   which `reverseip` shares.
2. A failed server-address lookup is not retried until `--redo dnsroot` or `--redo email` (Known
   limitations). If that proves to lose real signals, decide whether to fail the NS check on a
   SERVFAIL (weighed against a broken name-server domain failing the whole NS check every run), or
   to move the lookups into a stage of their own, one check per host (the simplify reviewers'
   suggestion). Either is a change to `internal/stages/serveraddr/serveraddr.go` and its callers.
3. Decide whether `nsreverse` should retire checks it no longer yields (`run.Retiring`, as `email`
   does), so that a server that stops being self-hosted, or a lowered `nsreverse.max_domains`,
   stops its roots being current without `--redo nsreverse`. The cost is re-asking SecurityTrails
   (credits) whenever a server's self-hosted result flips back. The place is
   `internal/stages/nsreverse/nsreverse.go`.
4. Decide whether a server with any address inside an excluded CIDR should never be self-hosted
   (today one port-eligible address is enough). The place is `inventory.SelfHosted` in
   `internal/inventory/inventory.go`.
5. Run `golangci-lint run ./...` with a golangci-lint built on Go 1.27.3 or later; the hook's
   installed build could not load the config for this change.
