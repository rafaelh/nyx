# Spec 1 of 4: Names learned from found names

## Goal

Series context: nyx was compared with bbot, whose recursive approach finds hostnames and addresses
nyx misses today. The comparison found that bbot's extra results come from building on its own
finds (learned names, parent names, the records of every name, names anywhere in a response, and
names served from target netblocks), not from asking third-party sources again. The four specs of
this series close the gaps the user chose, within nyx's passive boundary.

This spec: nyx builds on the names it has already found. A label seen under one in-scope zone is
tried under the others, the names any procedure finds meanwhile are learned from in turn, and the
parents of found names are resolved, so that deeper levels and sibling zones are discovered without
a larger wordlist.

Depends on: nothing.

Done when:

- with `staging.a.example.com` and `api.b.example.com` known, a run finds `staging.b.example.com`
  and `api.a.example.com` where they exist;
- a name found from a tried name (a variant `permutations` makes of it, say) is learned from in the
  same run;
- `b.example.com` is listed when `a.b.example.com` was found and `b.example.com` resolves.

## Behaviours

- **B1 Learning.** nyx learns every label, below its nearest input root, of each in-scope hostname
  under an input root that has an address or a CNAME, is not wildcard-only, and sits in a zone
  whose wildcard check has completed. A label with hyphens also gives its hyphen-separated parts
  (`api-dev2` gives `api-dev2`, `api` and `dev2`); a label that begins `xn--` is not split. A label
  or part of digits only is not learned. (amended by D6)
- **B2 Populated zones.** A populated zone is an input root, or an in-scope name between such a
  hostname (B1) and its nearest input root. (amended by D19)
- **B3 Trying.** Each learned label is tried, as one more label, under every populated zone. A
  tried name exists when it has a CNAME or an A address; one that exists becomes a hostname and is
  resolved like any other. `permutations` applies the same rule to the names it tries, in place of
  today's (anything but NXDOMAIN or SERVFAIL). A name that has only an IPv6 address, or only other
  records, is not found by trying. (amended by D1)
- **B4 Once.** Learning tries each name at most once per engagement, whatever the answer, until it
  is redone. It does not try a name already known, a parent name (B9, which `resolve` asks), or a
  wordlist label directly under an input root while `permutations` is on (the wordlist job asks
  it, whether or not that job has run yet). With `--skip permutations` learning tries those
  labels, and a later run with `permutations` on asks them again. A name `permutations` tried only
  as a variant may be asked once more by learning. A second run with no new finds and nothing
  deferred sends no learning lookups. (amended by D2)
- **B5 Rounds.** Names any procedure finds during the run, including names found by trying, are
  learned from and tried in the same run. This stops when a round adds no new label or populated
  zone, or the cap (B6) is spent.
- **B6 Cap.** Learned names have their own per-run cap, `learned_names.max_names`
  (`--learned-names-max-names`, default 50,000, at least 1), separate from
  `permutations.max_names`; neither delays the other. When a round has more names than the cap
  has left, labels are ranked by the number of populated zones that have a found name with an
  address or a CNAME whose first label it is, most first, then alphabetically, and a label's names are tried under its zones in
  alphabetical order. Names over the cap are deferred, not failed: they are tried on a later run,
  and the summary counts them under `Deferred to the next run` on their own line.
  (amended by D3, D5, D18)
- **B7 Wildcards.** Nothing is tried under a zone until its wildcard check has completed and found
  no wildcard.
- **B8 Exclusions.** An excluded name is not tried, and nothing is tried under one.
- **B9 Parent names.** Every name between a found in-scope hostname and its input root is resolved
  (`a.b.example.com` gives `b.example.com`). One that resolves is a hostname like any other. One
  that does not resolve, and that no other source found, is listed in no file, `unresolved.txt`
  included, except as the name of its own records (Spec 2); it still counts as a populated zone
  when B2 makes it one. An excluded parent is treated as any excluded name is. A parent whose
  answer only its zone's wildcard gives is treated as one that does not resolve, and a parent is
  not asked until its zone's wildcard check has completed, when that zone is checked. (amended by
  D16)
- **B10 Under input roots only.** Learning and parent names apply only to hostnames under an input
  root. A name in scope by its address (Spec 4) gives no label, is never a populated zone, and its
  parents are not resolved.
- **B11 Passive.** Learning sends only DNS lookups through the public resolvers, so it runs under
  `--passive` and needs no `--authorised`.
- **B12 Procedure and switch.** Learning is reported in the summary, skipped with `--skip` and
  redone with `--redo` under its own procedure name, `learned-names`, separately from
  `permutations`. `--skip` of either procedure leaves the other running. `permutations.enabled:
  false` (or `--no-permutations`) turns both off. Parent names (B9) are resolved even when
  learning is skipped or turned off, and are reported under `resolve`. (amended by D3)
- **B13 Documented.** `docs/sources.md` describes name guessing (the wordlist, variants, learning
  and parent names), and `docs/configuration.md` lists the permutations settings and the new cap.

## Out of scope

- Trying the wordlist under deeper zones (bbot's `dnsbrute` under every populated zone). Declined:
  the user chose learned names only.
- Sharing `permutations.max_names` with the wordlist jobs. Declined: one root's wordlist job costs
  about 103,000 names, so learning would wait a run or more on an engagement with several roots.
- Learning as part of the `permutations` procedure. Declined: it has its own procedure name.
- Asking third-party sources again about deeper names. bbot does not do this either: each source is
  asked once per root, as in nyx.
- New third-party sources, zone transfers and NSEC walking. Not recursion, and zone transfers are
  outside the passive boundary.
- Engagements created before this change. The user will start fresh engagements, so no job key is
  versioned and nothing is migrated.
- Finding, by guessing, a name that has only an IPv6 address or only records other than A and
  CNAME (D1). Declined: asking AAAA as well doubles the lookups on Cloudflare-style zones.
- Skipping names that `permutations` tried as variants (D2). Declined: it costs more to work out
  than the occasional repeated lookup.
- Recording an in-scope CNAME target as a hostname. Moved to Spec 2 (its B4).

# Design

## External facts

- **Cloudflare-hosted zones answer NOERROR with no records for a name that does not exist**
  (`example.com`, `cloudflare.com`), and a conventional zone answers NXDOMAIN (`iana.org`).
  *Confirmed live* on 2026-11-26 against nyx's three default resolvers (1.1.1.1, 8.8.8.8 and
  9.9.9.9). Check again with:

  ```sh
  for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
    for n in zz-nx-probe-7f3a91.example.com zz-nx-probe-7f3a91.iana.org; do
      printf '%s @%s: ' "$n" "$r"; dig +noall +comments "$n" A @"$r" | grep -o 'status: [A-Z]*'
    done
  done
  ```

  Consequence: today's rule in `permutations.go` (`len(res.CNAMEs) > 0 || res.RCode !=
  RCodeNXDomain && res.RCode != RCodeServFail`) counts every tried name under such a zone as
  existing, and the wildcard check does not catch it because no record is answered. D1 rests on
  this.
- **A name that exists only as the parent of other names (an empty non-terminal) answers NOERROR
  with no records** (RFC 8020). *From docs*, not probed. Nothing rests on it: a parent that has no
  address and no CNAME records nothing either way (D9).

## Decisions

Decided by the user:

- **D1 Existence rule.** A guessed name exists when its A lookup returns a CNAME or an A address.
  AAAA is never asked when guessing. One helper in package `dns` serves `learned-names` and the
  existing `permutations` jobs, replacing `permutations.go`'s rule. A job's cost stays its number
  of lookups. Why: the external fact above; asking AAAA on every no-records answer would double a
  root's wordlist job on Cloudflare-style zones (about 103,000 to 206,000 lookups). Names lost:
  those with only AAAA, MX or TXT records and empty non-terminals. No finding depends on them
  (takeover needs a CNAME plus NXDOMAIN; `email` and `dnsroot` look only at roots).
- **D2 Wordlist names.** `learned-names` never yields `<label>.<input root>` when the label is in
  the root job's word set (the valid wordlist words plus `wellKnownLabels`), unless `permutations`
  is in `Settings.Skip`. It does not consult whether the root job has run. Why: with two or more
  roots the second root's job is deferred (103,186 names against a 200,000 budget), so a
  "skip once done" rule would ask each such name twice. Variants are not considered.
- **D3 Names.** Procedure `learned-names`; setting `learned_names.max_names`; flag
  `--learned-names-max-names`; default 50,000; minimum 1; Go field `Settings.LearnedNames.MaxNames`.
- **D6 Learn guard.** A hostname is learned from only when the wildcard job of its parent zone has
  completed (whatever it found) and the name is not wildcard-only. Why: wildcard-only marking needs
  a wildcard record, so a zone whose check failed would feed junk labels into every zone. Names
  with their own answers under a real wildcard zone are still learned from.

Decided from the code:

- **D4 One job per tried name.** New procedure `LearnedNames` in
  `internal/recon/procedures/dns/learn.go` (embeds `base`: `ThirdParty`, no sources). Job key = the
  tried name, cost 1. `Run` does one A lookup and returns `kinds.Hostname.Obs(name,
  kinds.HostnameAttrs{})` when D1 holds, else nothing; a timeout is an error (that name's job
  fails and is retried next run). Why: B4 then holds by the runner's completed-job rule with no new
  persisted state, `--redo learned-names` works unchanged, and the runner's `Budgeted` deferral
  (`withinBudget` in `internal/recon/run/procedurerun.go`) gives B6's cap and an exact deferred
  count, because `spent` carries across the passes of one run. Rejected: batch jobs keyed by a hash
  of a zone's labels (a grown label set changes the key and retries every label) and a new "tried"
  record kind. `resolve` already runs one job per hostname, and a completion with no observations
  bumps no kind version, so the store copes.
- **D5 Enumeration and order.** `Jobs` recomputes labels (B1, D6) and populated zones (B2) from the
  view on every pass, ranks the labels as B6 says, and yields label-major with zones in
  alphabetical order. Per zone it checks once, before building any name: the zone is in scope
  (B8), its wildcard job is done and it is not a wildcard zone (B7, D7). Per name it leaves out:
  a name that is not in scope (B8), a known name and a parent name (D8), a wordlist name (D2), and
  a name too long to be a DNS name. It yields the whole backlog and lets the runner defer what is
  over the cap. The budget is spent pass by pass, so B6's order holds within each round, not across
  the run. Cost accepted for now: on a very large engagement (thousands of labels times hundreds of
  zones) a pass yields millions of jobs and fills `procedureRun.all`. Add a benchmark (5,000 labels
  by 500 zones) for the pure planning function, and a `docs/todo.md` entry for stopping
  enumeration at the cap, which needs a runner change.
- **D7 Reading the wildcard job's completion.** New `View.DoneBy(procedure, key string) bool` in
  `internal/recon/run/procedure.go`: loads that procedure's completed keys with
  `Store.Completed` on first use in a pass, keeps them in the pass's `recordCache` (`View` is
  passed by value), and on a store error warns once and answers false. `learned-names` asks
  `v.DoneBy("wildcard", zone)`. A wildcard job that finds no wildcard completes with no record
  (`wildcard.go`, the `if !answered` return), so there is nothing else to read. It is sound because
  `wildcard` runs before `learned-names` in each pass and the runner flushes after a procedure's
  work before the next view is built; say so in the `defaultProcedures` comment. Both procedures
  are in package `dns`, so no code outside a procedure names one. Rejected: making the wildcard job
  always write a record, because inventory treats every wildcard record as a wildcard zone and
  `scopebuild` and an analysis read the kind.
- **D8 Names another path owns.** `learned-names` does not yield: a name that has a `hostname`
  record with a producer other than `learned-names` (known); or any ancestor of an in-scope
  hostname under an input root (a parent name, which `resolve` asks under D9, whether or not that
  job has run). A name only `learned-names` found is still yielded, so the runner sees its
  completed job and `--redo learned-names` lists it again (`FinishRedo` sweeps jobs that are not
  listed). Without the parent rule every parent with no records would be asked by both procedures,
  because every parent of a resolving name is also a learned label under a populated zone.
- **D9 Parent names in `resolve`.**
  - A new inventory method, exposed on `View` and taking the generator's name as `Seeds` does,
    returns the parent names: every ancestor (`dnsname.Parents`) of a current in-scope `hostname`
    record under an input root, kept when it is under an input root (`Scope.RootOf` is not empty)
    and is not itself an input root, and left out when it has a `hostname` record with a producer
    other than the generator.
  - `View.ResolvableHostnames` leaves out a name whose only `hostname` producer is the generator
    (safe today: `resolve` writes no `hostname` records), so a parent that resolved is not asked a
    second time under a bare key.
  - `Resolve.Jobs` yields the normal jobs, then one job per parent name keyed `parent|<name>`.
    `Resolve.Run` takes the name from the job's input, not its key.
  - A parent job does the same A and AAAA lookups. When the name has an address or a CNAME it
    returns what a normal job returns plus `kinds.Hostname.Obs(name, …)`. When it has neither it
    returns nothing, so no `unresolved` record exists and B9's "listed in no file" holds
    (`unresolved.txt` lists every current `unresolved` record; `subdomains.txt` every in-scope
    `hostname` record).
  - The separate key means a parent that a real source later finds gets a normal job, and then
    appears in `unresolved.txt` if it does not resolve.
  - An excluded parent is asked like any excluded name; if it resolves, its `hostname` record puts
    it in `excluded.csv`.
  - Nothing else reads a `resolve` job key as a hostname (candidate evidence, the change baseline,
    redo and export were checked).
  - Rejected: one key plus a visibility rule on the `unresolved` kind, which touches output,
    counts, `changes.csv` and export for one edge.
  - Accepted: a parent whose label is in the wordlist is also asked by its root's wordlist job
    (one extra lookup per such zone).
- **D10 Seeds unchanged.** `inventory.Seeds` keeps excluding only the names `permutations` alone
  found. So names `learned-names` or a parent job finds become `permutations` seeds, and names
  `permutations` finds are learned from. This is what chains finds inside one run (B5 and the
  second done-when). A run always ends: a pass counts as work only when it runs a job that is not
  done, both caps only decrease within a run, and the names are finite. On a large engagement
  expect both caps to be spent every run.
- **D11 Switches.** `LearnedNames.Configured` returns `false, "disabled"` when
  `Settings.Permutations.Enabled` is false. It implements `Budgeted` with
  `Settings.LearnedNames.MaxNames`. It is not `Required`. The `--no-permutations` flag help says it
  turns off learned names too.
- **D12 Registry.** Added to `defaultProcedures()` in `internal/cli/cli.go` directly after
  `dns.NewPermutations()`. A `procedureHelps` entry in `internal/cli/procedures_topic.go`
  (`"learned-names": {"", "Labels of found names tried under the other zones that have names"}`),
  which `TestSetupProceduresLeaveOutTheUnskippable` requires.
- **D13 Setting.** The places an integer setting needs in `internal/config/config.go`: the
  `LearnedNames` struct and field on `Settings`, `Defaults()`, `settingTable`
  (`{"learned-names-max-names", "learned_names.max_names"}`), `RegisterFlags` (`intFlag`, help
  "Maximum learned names tried per run; the rest are deferred to later runs"), `rawSettings`,
  `setDefaults`, and `numbers()` with minimum 1. It is not a `nyx setup` setting.
- **D14 Labels.** A pure helper in `internal/knowledge/dnsname` gives a label's learnable forms:
  the label and, unless it begins `xn--`, its hyphen-separated parts, dropping empty, digits-only
  and invalid (`ValidLabel`) ones. Labels are taken below `Scope.RootOf(name)`, the most specific
  input root.
- **D15 Docs.** A new `## Name guessing` section in `docs/sources.md`: the wordlist under each
  root, variants of found labels, learned names (what is learned, where it is tried, the cap and
  its order, the wildcard and exclusion rules, `--skip` and `--no-permutations`), parent names, and
  that a guessed name counts only with a CNAME or an A address (so IPv6-only names and names with
  only other records are not found by guessing). A bullet in `docs/configuration.md` listing
  `permutations.enabled` (`--no-permutations`), `permutations.max_per_seed`
  (`--permutations-max`), `permutations.max_names` (`--permutations-max-names`) and
  `learned_names.max_names` (`--learned-names-max-names`) with defaults and minimums. Do not touch
  the sample `config.yaml` block there (a test copies it).

Settled after verification (by the user):

- **D16 Wildcard-answered parents.** A parent job records nothing when its answer matches its
  zone's wildcard record (an answered address among the wildcard's addresses, or the wildcard's
  CNAME target in its chain: inventory's rule), so nyx does not list a name only the wildcard
  answered. Because `resolve` runs before `wildcard` in each pass, a parent job is not yielded
  until its zone's wildcard job has completed, when the `wildcard` procedure checks that zone
  (its zone list is shared, not copied); a zone it does not check holds no parent back. Why: a
  stale crt.sh name under a wildcard zone otherwise makes its parent a wildcard-only hostname no
  source found. A real empty non-terminal is never answered by a wildcard.
- **D17 `permutations` waits for wildcard checks.** A root job, and a seed's variants, are not
  yielded until the zone's wildcard job has completed, when the `wildcard` procedure checks that
  zone, as learning does (D6, B7). Not yielding is neither a failure nor a deferral. Why: when a
  zone's check failed, every wildcard-answered guess was recorded.
- **D18 Rank by found names that resolve.** B6's rank counts found names with an address or a
  CNAME (the learnable names of B1), as the code does; B6 and `docs/sources.md` say so. Why: a
  name that resolves is the stronger signal, and the planning input stays one list.
- **D19 Zones up to the nearest root.** B2's populated zones are the names between a learnable
  hostname and its nearest input root, as the code does. Parent names (D9) still run up to any
  input root. Why: nested roots with a gap are rare, and both readings hold.

## Files

New:

- `internal/recon/procedures/dns/learn.go`: `LearnedNames` (Jobs, Run, Configured, Budget) and the
  pure planning function (labels, zones, rank, ordered names).
- `internal/recon/procedures/dns/learn_test.go`: unit tests and the benchmark for the planning
  function.
- `internal/cli/learned_names_test.go`: the behaviour tests below.

Changed:

- `internal/recon/procedures/dns/permutations.go`: use the shared existence helper (D1); expose
  the root job's word set for D2.
- `internal/recon/procedures/dns/dns.go`: the existence helper.
- `internal/recon/procedures/dns/resolve.go`: parent jobs (D9).
- `internal/recon/run/procedure.go`: `View.DoneBy`, the parent-names and learnable-hostnames
  methods, the `ResolvableHostnames` filter; `recordCache` gains the completed-keys cache.
- `internal/recon/inventory/inventory.go` and `inventory_test.go`: the methods behind them
  (parent names; hostnames with their producers, addresses, CNAMEs and wildcard-only state).
- `internal/knowledge/dnsname/dnsname.go` and its test: the label helper (D14).
- `internal/config/config.go`, `internal/config/config_test.go` (`TestIntSettings` row).
- `internal/cli/cli.go` (registry and its ordering comment), `internal/cli/procedures_topic.go`.
- `internal/cli/testdata/plain/help-recon.txt`: regenerate with
  `go test ./internal/cli/ -run 'TestPlain_' -update-plain`.
- `docs/sources.md`, `docs/configuration.md`, `docs/todo.md` (D5's entry).
- Existing tests in `internal/cli` (see Tests).

## Tests

Behaviour tests drive `cli.Execute` through the harness and the fake DNS server (`w.dns`: `A`,
`CNAME`, `Wildcard`, `Rcode`, `Drop`, `Count`, `Queried`, `Total`; unknown names answer NXDOMAIN).
Use `--passive --concurrency 1` and a small `--wordlist` for a fixed query order, as `permRun`
does. Mutation checks in `/spec-develop`: **B3/D1** (existence rule), **B6** (cap), **B7** (wildcard
guard) and **B8** (exclusions), since a bug in any of them floods the output or sends lookups the
user ruled out.

- **B1, B2, B3.**
  - `staging.a` and `api.b` known: `staging.b` and `api.a` are asked, and recorded when they exist.
  - `api-dev2.a` known: `api-dev2`, `api` and `dev2` are asked under `b`; a digits-only label and a
    digits-only part are not; an `xn--` label is asked whole and not split.
  - A hostname with no address and no CNAME gives no label and makes no zone.
  - A wildcard-only name gives no label; a name with its own answer under a wildcard zone does.
  - `api.dev.example.com` known makes `dev.example.com` a zone that labels are tried under.
  - Nested roots: labels are taken below the most specific root.
- **B1, D6.** A name under a zone whose wildcard probes fail (SERVFAIL) gives no label; after a
  run in which the check succeeds, it does.
- **B3, D1** (also for a `permutations` root job and a seed job).
  - A name answered NOERROR with no records is not recorded: a fake zone that answers no-records
    for everything records no hostname.
  - A name with only an AAAA record is not recorded, and no AAAA query is sent when guessing.
  - A CNAME with an NXDOMAIN target counts as existing.
  - SERVFAIL on a tried name records nothing and completes the job.
- **B4.**
  - A second run with nothing new sends zero learning lookups (compare `w.dns.Total()`).
  - A name answered NXDOMAIN is not asked on the next run; `--redo learned-names` asks it again.
  - A known name is never asked by learning.
  - A wordlist label is not asked by learning under an input root, in a world with two roots and
    `--permutations-max-names` small enough to defer the second root's job; each such name is
    asked exactly once over two runs.
  - With `--skip permutations`, learning asks the wordlist label under the root.
  - The parent of a resolving name that has no records itself is asked once for A in the run
    (by its parent job), not again by learning.
- **B5.** One invocation: a tried name is found, `permutations` finds a variant of it, and the
  variant's label is asked under another zone.
- **B5, D10 termination.** In a world where every name that learning and `permutations` try exists
  (the fake answers each with an address but answers NXDOMAIN to the wildcard probes' labels, so no
  wildcard is detected), the run ends, and the names asked by each procedure do not exceed its cap.
- **B6.**
  - Cap N: exactly N names are asked, in rank order (a label under more zones first, ties
    alphabetical, zones alphabetical); `deferred` has the rest under `learned-names` in the console
    block and the JSON envelope; the next run asks the rest and repeats none.
  - A `permutations` deferral does not defer learning, and the reverse.
  - `--learned-names-max-names 0` exits 2 with no DNS query.
- **B7.** Nothing is asked under a wildcard zone. Nothing is asked under a zone whose wildcard job
  failed; the names are asked in the run after it succeeds.
- **B8.** An excluded name is never asked by learning; nothing is asked under an excluded name.
- **B9, B12.**
  - `b.example.com` is in `subdomains.txt` when `a.b.example.com` was found and `b` has an address;
    it is asked once across passes (the `ResolvableHostnames` filter).
  - A parent with no records is in no file; once crt.sh also returns it, it is in `unresolved.txt`.
  - Parents are resolved with `--skip learned-names` and with `--no-permutations`.
  - An excluded parent that resolves is in `excluded.csv`.
  - No parent of a candidate (a name under no input root) is ever queried (B10).
- **B11, B12.** Learning runs under `--passive` without `--authorised`. `--skip learned-names`
  leaves `permutations` running and the reverse. `--no-permutations` shows `not-configured
  (disabled)` for both.
- **B13.** A docs test like `TestShodanHost_DocsSayWhatItDoes`: `docsSection(t, "## Name guessing")`
  names learned names, parent names and the existence rule, and `docsText` has
  `learned_names.max_names`, `--learned-names-max-names`, `permutations.max_names` and
  `permutations.max_per_seed`.
- **Failure and re-run cases.**
  - External dependency: a dropped (timed-out) tried name fails only that job; the other names are
    recorded; the run exits 7; the next run asks just that name.
  - One item failing in a batch: covered by the case above (jobs are per name).
  - Interrupt part-way: an interrupted run (as in `partial_test.go`) keeps the names already
    completed, and the re-run asks only the remainder. No secret is involved: the procedure has no
    key.
  - Re-run after success: the B4 zero-lookup test. Re-run after a partial failure: the timeout
    case. Order: a parent resolved in pass N is learned from in the same run (B5 test).
  - `DoneBy` when the store errors cannot be reached from a behaviour test; cover its false-and-warn
    path with a unit test in `internal/recon/run`.
- **Unit.** The `dnsname` label helper; the inventory methods (parent names with producers,
  nested roots, excluded and candidate ancestors); the planning function's order.
- **Existing tests to update.** The new procedure runs in every world-based test
  (`newWorldWith` in `internal/cli/world_test.go`), so tests that assert on every A query
  (`TestPermutations_ApexIsNotSeed`, `TestListsPermutations_NoNamesUnderWildcardZone` and others in
  `lists_test.go`, `discovery_test.go` and `srv_test.go`) need their expectations updated or
  `--skip learned-names`. Tests that pin today's existence rule for `permutations` change to D1.
  Parent jobs add `resolve` queries for the parents of deeper names in any world.

## Conventions

- `CLAUDE.md`: the hard invariants (only `internal/egress` does network I/O; the procedure gets
  `egress.Clients`), the procedure rules (a job key encodes every input that changes the work;
  negative results complete a job; code outside a procedure never names a procedure), the testing
  rules (`t.Parallel()` first, harness environment only, behaviour tests in `internal/cli`), and
  Australian English in docs, comments and messages.
- Targeted tests without `-race` while iterating; `make test` and `make lint` before finishing.
- Doc tests read `README.md` and `docs/*.md`; a sentence a test names must stay in its `## `
  section.
- Commit messages use conventional prefixes (`feat:`, `fix:`, `docs:`).

## Handed to later specs

- **Spec 2.** Recording an in-scope CNAME target as a hostname (its B4). Asking a parent name that
  does not resolve for its NS, MX and TXT records (its B1): the parent-names method from D9 is the
  list to use, since such a parent has no `hostname` record.
- **Spec 4.** A name in scope by its address must give no label, make no zone and have no parent
  resolved (B10). This spec keys all three on `Scope.RootOf`, so they hold as long as Spec 4 does
  not make such a name answer to an input root.

# Implementation

## Develop

Base commit: c3cfabf1e3c8e4852a643bcd2a5be14cae6d87b4

Frozen test files (staged before the code was written): `internal/cli/learned_names_test.go`,
`internal/cli/parent_names_test.go`, `internal/cli/guess_existence_test.go`,
`internal/cli/name_guessing_docs_test.go`, `internal/config/config_test.go` (the `TestIntSettings`
row), `internal/knowledge/dnsname/dnsname_test.go`, `internal/recon/inventory/inventory_test.go`,
`internal/recon/procedures/dns/learn_test.go`, `internal/recon/run/doneby_test.go`, and the fake
DNS `internal/egress/egresstest/dns.go`, which gained `NoDataSuffix` (a zone answering NOERROR with
no records, as Cloudflare does) and `AnySuffix` (every name at any depth exists, except those a
predicate refuses) for the existence and termination tests.

How it was built:

- **Existence (B3, D1).** `guessExists` in `dns.go` (a CNAME or an A address) replaces the rule in
  `permutations.go` and serves `learned-names`. Pinned for learning, a root job and a seed job by
  `guess_existence_test.go` (no-records zone, AAAA-only name with no AAAA asked, dangling CNAME,
  SERVFAIL).
- **Learning (B1–B8, D4–D8).** `LearnedNames` in `learn.go`: `Jobs` reads `View.Learnable`
  (inventory: in scope, under a root, address or CNAME, not wildcard-only), keeps a host only when
  `View.DoneBy("wildcard", <its zone>)` (D6), and passes the pure `learnNames` a zone filter (in
  scope, wildcard job done, not a wildcard zone) and a name filter (known by another producer, a
  parent name, out of scope, or a wordlist word under a root unless `permutations` is skipped).
  `learnNames` takes labels below `Scope.RootOf` through `dnsname.LearnableForms`, ranks them by
  the populated zones that hold a host starting with them (zones a filter refuses still count, as
  B2 makes them populated zones), and yields label-major, zones alphabetical, names over 253
  characters left out. One job per name, cost 1; the runner's budget gives the cap. Behaviour tests
  in `learned_names_test.go`; order, zones, nested roots and forms in `learn_test.go` and
  `dnsname_test.go`; `BenchmarkLearnNames` runs 5,000 labels by 500 zones (2.5 million names) in
  about 88 ms.
- **`View.DoneBy` (D7)** caches each procedure's completed keys in the pass's `recordCache` and
  warns once (the runner's warning dedup) on a store error. Unit tests in `doneby_test.go` close
  the store to make it fail.
- **Parent names (B9, B10, D9).** `Inventory.ParentNames` and `View.ParentNames(generator)`;
  `Resolve.Jobs` yields `parent|<name>` jobs after the normal ones, and a parent job returns the
  normal observations plus a `hostname` record only when a resolution (address or CNAME) was
  observed. `View.ResolvableHostnames` now takes the generator's name (deviation: the design
  didn't give it a parameter, but code outside a procedure may not name one), and leaves out a
  name only that generator produced. Tests in `parent_names_test.go` and `inventory_test.go`.
- **Settings and switches (B6, B11, B12, D3, D11–D13).** `learned_names.max_names` in every place
  an integer setting needs; the flag sits after `--permutations-max-names` in the help;
  `--no-permutations`'s help names learned names; the registry entry and its ordering comment in
  `cli.go`; the `procedureHelps` entry. `help-recon.txt` regenerated (`go test ./internal/cli/
  -run Plain -update-plain`): the two flag lines changed, nothing else.
- **Docs (B13, D15).** `## Name guessing` in `docs/sources.md`; a "Name guessing" bullet in
  `docs/configuration.md` (the sample `config.yaml` untouched); D5's entry in `docs/todo.md`.

Deviations from the plan:

- **No existing test needed changing.** `## Tests` expected updates to tests that assert on every A
  query; with the full suite run, none failed because of the new lookups, and the existence writer
  found no test pinning today's `permutations` rule.
- `ResolvableHostnames` takes the generator name, as above.
- **D9's "the name from the job's input, not its key".** After `/simplify`, `Resolve.Run` takes
  the name from the key, cutting the `parent|` prefix. It is the same name, since `|` cannot occur
  in a hostname.

Mutation checks (each made by hand, run with `-count=1`, then undone by hand):

- **B3/D1** (`guessExists` back to "anything but NXDOMAIN or SERVFAIL"): fails
  `TestGuessExistence_NoRecordsZoneRecordsNoHostname` and
  `TestGuessExistence_AAAAOnlyIsNotANameAndAAAAIsNotAsked`.
- **B6** (`Budget` times 1,000): fails the two `Cap…` tests, `EveryNameExistingStillEnds`,
  `InvalidCapExits2` and `CapsAreSeparate`. Inverting the rank fails
  `CapTriesTheHighestRankedAndDefersTheRest`, `TestLearnNames_Order` and `TestLearnNames_Skip`.
- **B7** (the zone filter without its wildcard checks): fails `NothingUnderAWildcardZone`,
  `WildcardOnlyNameGivesNoLabel` and `NothingUnderAZoneWhoseWildcardCheckFailed`.
- **D6** (hosts learned from without their zone's check): fails
  `NoLabelUntilTheZonesWildcardCheckCompletes`.
- **B8** (the zone scope check removed, the name scope check removed, each alone and both
  together): each fails `TestLearnedNames_Exclusions`.

Tests failing on the base too (not this change's): `TestSetup_FailedSaveKeepsTheEdits` and
`iplookup`'s `TestActive_EndToEnd`, both already in `docs/todo.md` as failing every time on macOS.

After verification (D16–D19):

- **D16 and D17** were tested first: `internal/cli/wildcard_guard_test.go` was written and frozen
  (a wildcard-answered parent records nothing; a parent with its own answer is listed; a parent
  waits for its zone's check; a root job and a seed's variants wait for their zone's check). Then
  `wildcard.go` gained `wildcardZones` (the zone list `Wildcard.Jobs` already built, now shared)
  and `wildcardPending` (a check is due and not done). `Permutations.Jobs` skips a root or seed
  whose zone is pending; `Resolve.Jobs` skips a parent whose zone is pending and passes its zone's
  wildcard record as the job's input; `Resolve.Run` records nothing for a parent whose answer
  `answer.matches` that wildcard (inventory's rule: an address among the wildcard's, or the
  wildcard's CNAME target). Mutation checks: making the match never apply fails
  `WildcardAnsweredParentIsInNoFile`; dropping the parent's wait fails it and
  `ParentWaitsForItsZonesWildcardCheck`; dropping `permutations`' waits fails
  `RootJobWaitsForTheRootsWildcardCheck` and `SeedVariantsWaitForTheirZonesWildcardCheck`.
- **D18 and D19** reword B6 and B2 (and `docs/sources.md`) to what the code does.
- **Comment-only edits to frozen test files.** The test writers' comments cited behaviour and
  decision numbers and the spec's name (`learned_names_test.go`, `parent_names_test.go`,
  `guess_existence_test.go`, `name_guessing_docs_test.go`, `wildcard_guard_test.go`,
  `learn_test.go`); they were reworded to name the behaviour instead, as the project's rule asks.
  No test code changed (checked by diffing the non-comment lines).

## Known limitations

- **B6 order across rounds.** The rank order holds within one pass, not across the run (D5): names
  learned in a later pass come after the budget spent earlier, whatever their rank.
- **B6 enumeration cost.** `Jobs` yields the whole backlog every pass (D5); `docs/todo.md` has the
  entry for stopping at the cap.
- **B9 and nested roots.** `ParentNames` follows D9: an ancestor between two nested input roots
  (`corp.example.com` for `x.dev.corp.example.com` with roots `example.com` and
  `dev.corp.example.com`) is resolved as a parent, although it is above the host's nearest root
  and, under D19, not a populated zone.
- **D16/D17 and failing checks.** A parent name, a root's wordlist job or a seed's variants in a
  zone whose wildcard check keeps failing are never asked, as learning's names are not (D6).
- **B9 "listed in no file"** is tested on the engagement's files outside `.nyx/`, not on stdout,
  stderr or the event stream.
- **B5 interrupt test timing.** `TestLearnedNames_InterruptKeepsCompletedNames` cancels the run
  once three slow (100 ms) learning lookups have been asked; it asserts only that some, not all,
  names were kept, but it still depends on timing (in `docs/todo.md`).

## Simplify

`/simplify` ran four reviewers (reuse, simplification, efficiency, altitude) over the change.

Fixed:

- **One producer rule.** `inventory.FoundByOther(producers, generator)` replaces the inline
  "a producer other than the generator" check in `Seeds`, `ParentNames` and
  `View.ResolvableHostnames`. `LearnedNames.Jobs` builds its known names from
  `View.ResolvableHostnames(l.Name())` instead of its own loop over the hostname records. That set
  also holds the input roots, so a learned name that is a nested input root (which resolve asks)
  is no longer tried a second time.
- **The wildcard key in one place.** `wildcardChecked(v, zone)` in `wildcard.go`, next to the job
  key's definition, replaces the two `v.DoneBy("wildcard", zone)` literals in `learn.go`.
- **One switch.** `LearnedNames.Configured` returns `Permutations.Configured`'s answer instead of
  a copy of it, since the two must turn off together.
- **Resolve.** The `parent|` key already marks a parent job, so `resolveInput` is gone and `Run`
  reads the name with `strings.CutPrefix(c.Key, parentPrefix)`. `resolve` returns whether it found
  an address or a CNAME, rather than `Run` scanning the observations for a `resolution` kind.
- **`learnNames`.** Ranks are counted once before the sort (they were recounted inside the
  comparator); the host's parent zone is computed once; `Jobs` no longer sorts the roots it passes.
- **Wordlist.** `rootWords` takes the lower-cased words, so `permutations` lower-cases the wordlist
  once per `Jobs` call again (it had been doing it twice).
- **`DoneBy`'s cache** is made with the rest of the `recordCache`, not lazily.

Skipped:

- **Frozen test files and the fake DNS.** Every test finding is left alone, because those files
  were frozen before the code was written. The findings were: the probe regexp defined three times
  (`randomLabel` exists); `learnRun`/`guessRun` beside `permRun`; `guessHostnames` and
  `learnFoundBy` beside `hostnameKeys` and `observedBy`; the overlapping world builders and
  tests; the slow re-run in the interrupt test; and `NoDataSuffix` as a special case of
  `AnySuffix(suffix, nil)` in `egresstest/dns.go`.
- **Yielding `learnNames` lazily** instead of building the slice: its frozen unit tests take a
  `[]string`. The real fix, stopping at the cap, is already in `docs/todo.md`.
- **Caching the wordlist set across passes, and memoising `ParentNames`/`Learnable` per scope**:
  a few milliseconds a pass, for extra state (`ParentNames` is keyed by generator, which
  `perScope` doesn't fit, and `Learnable`'s frozen test fixes its return type).
- **Dropping `zones[z]` from the rank and the `Under` guard in `learnNames`**: they hold only for
  the inputs `Jobs` gives. The pure function keeps them for any input.
- **Merging `View.Done` into `DoneBy`**, and dropping the host `RootOf` check in `ParentNames`:
  outside this change, or an early exit worth keeping.
- **`guessExists` parsing every address**: negligible next to the lookup.

# Verification

## Result

Read against the base `c3cfabf`; the full suite (`go test ./... -count=1`) passes apart from the
two macOS failures that also fail on the base (`TestSetup_FailedSaveKeepsTheEdits`, `iplookup`'s
`TestActive_EndToEnd`, both in `docs/todo.md`), and `make lint` reports 0 issues. The frozen test
files are unchanged against the index. No external fact needed probing: `## External facts` has
none marked *assumed*, and `## Known limitations` none marked *unconfirmed*.

- **Goal.** Met. Each done-when is pinned by a passing behaviour test:
  `LabelsAreTriedUnderTheOtherZones` (staging/api across zones), `FindsAreLearnedFromInTheSameRun`
  (a permutations variant of a tried name is learned from in the same run) and
  `ResolvingParentIsListedAndAskedOnce` (`b.example.com` listed).
- **B1 Learning.** Met. `Inventory.Learnable` (in scope, under a root, address or CNAME, not
  wildcard-only) plus `wildcardChecked` on the host's parent zone (D6); labels below
  `Scope.RootOf` through `dnsname.LearnableForms` (hyphen parts, `xn--` whole, digits-only
  dropped).
- **B2 Populated zones.** Met, except one nested-root case: with roots `example.com` and
  `dev.corp.example.com`, `corp.example.com` has a B1 hostname beneath it and is under an input
  root, so B2 makes it a populated zone, but `learnNames` only takes zones between a host and its
  nearest root. See Follow-ups.
- **B3 Trying.** Met. `guessExists` (a CNAME or an A address) serves `learned-names` and both
  `permutations` job types; only A is asked.
- **B4 Once.** Met. One job per tried name; known names (`ResolvableHostnames(learned-names)`),
  parent names and wordlist words under a root (unless `permutations` is skipped) are left out.
- **B5 Rounds.** Met. `Jobs` replans from the view every pass; the runner passes until no work.
- **B6 Cap.** Met within each round (a pass), as B6 words it; the order does not hold across
  rounds (Known limitations, accepted in D5). The rank counts the zones holding a *learnable* host
  (B1) that starts with the label, not any known name: a known name with no address or CNAME does
  not raise a label's rank. A narrow reading of "known name"; see Follow-ups.
- **B7 Wildcards, B8 Exclusions.** Met. The zone filter requires the zone in scope, its wildcard
  job done and no wildcard record; the name filter requires the name in scope.
- **B9 Parent names.** Met. `parent|<name>` jobs in `resolve`; a parent with no address or CNAME
  records nothing, so it is in no file (and, since nothing is recorded, in no console line either);
  `ResolvableHostnames` leaves out a resolved parent so it is not asked twice. The nested-root
  limitation listed above (an ancestor between two nested roots is resolved) is consistent with
  B2's literal wording, which makes such a name a populated zone; it is the same follow-up as B2's.
- **B10 Under input roots only, B11 Passive, B12 Procedure and switch.** Met. Everything keys on
  `Scope.RootOf`; the procedure is `ThirdParty` with no sources; `Configured` follows
  `permutations`; parent jobs run under `resolve`, which is `Required`.
- **B13 Documented.** Met. `## Name guessing` in `docs/sources.md` and the "Name guessing" bullet
  in `docs/configuration.md` agree with the code (defaults 200, 200,000 and 50,000; the built-in
  wordlist has 103,181 lines, matching "about 103,000").

Nothing was changed by this verification before the code review.

## Code review

`/code-review high --fix` found no important bugs, and four minor ones.

Fixed:

- **`AnySuffix`'s comment** in `internal/egress/egresstest/dns.go` (the fake DNS, a frozen file):
  an excepted name answers as though no `AnySuffix` covered it (NXDOMAIN, or no records under a
  `NoDataSuffix`), and `except` runs with the server's lock held. Comment only; it touches the
  test fake behind the termination test (B5, D10), and no test's behaviour changed, so it is kept.

Undone by hand:

- **D9's wording.** The review rewrote D9 to say `Resolve.Run` takes the name from the key. That
  rewrites the design rather than the code, and `## Develop` already records the deviation, so D9
  is back to its original wording.

Left unfixed, as each changes behaviour the spec asks for:

- **Wildcard-answered parent names (B9).** A parent under a wildcard zone that only the wildcard
  answers (a stale `a.b.example.com` from crt.sh, with `*.example.com`) is recorded as a hostname
  by its parent job and then listed as wildcard-only, though no source found it. B9 says a parent
  that resolves is a hostname like any other. See Follow-ups.
- **Rank by known names (B6).** As in `## Result`: the rank counts learnable hosts only. See
  Follow-ups.

The tests pass after the review, apart from the two failures that also fail on the base.

# Follow-ups

- **Nested roots (B2, B9):** B2 reworded to the nearest root; code unchanged (D19).
- **Rank by known names (B6):** B6 and the docs reworded to names with an address or a CNAME (D18).
- **Wildcard-answered parent names (B9):** recorded as nothing, and parents wait for their zone's
  wildcard check (D16).
- **`permutations` and wildcard checks:** root jobs and seed variants wait for their zone's check
  (D17).
- **Stopping `learned-names` enumeration at the cap, and the rank order across passes:** in
  `docs/todo.md` under Design changes.
- **The two macOS test failures** that also fail on the base: already in `docs/todo.md`.
- **The interrupt test's timing:** in `docs/todo.md` under CI improvements.

**Manual steps:**

1. **Old engagements on Cloudflare-style zones** may hold guessed names that never existed (D1's
   external fact). For any engagement kept from before this change, run
   `nyx recon --redo permutations <roots>` in that engagement after upgrading.
2. **A live run** against a real multi-zone domain you are authorised to test, to see learned
   names and parent names in practice: `nyx recon --passive --output-dir /tmp/nyx-live <root>`,
   then check `subdomains.txt` and the `learned-names` line of the summary.
