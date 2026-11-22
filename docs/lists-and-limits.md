# Built-in lists and per-run limits

Two stages work from lists built into the binary. `--wordlist` and `--sensitive-paths` each replace
the list they name; neither adds to it.

**Permutation wordlist.** The built-in list has 4860 lower-case labels, most common first. It is
derived from `Discovery/DNS/subdomains-top1million-5000.txt` in
[SecLists](https://github.com/danielmiessler/SecLists) (Daniel Miessler and contributors, MIT
licence); the licence text is in the header of `internal/config/builtin/wordlist.txt`. Permutations
stay on under `--passive`, because they send only DNS lookups to public resolvers.

- **Volume.** The list costs 4860 lookups per root (one `A` query per word). Each seed (a
  name another stage found) costs at most `permutations.max_per_seed` lookups (default 200, taken
  from the front of the list). At the default `--rate-dns` of 50 queries a second, a root takes
  about 97 seconds.
- **Per-run cap.** `permutations.max_names` (`--permutations-max-names`, default 200000) caps the
  names generated in one run. Roots are taken first, then seeds, each in name order. A root's or
  seed's names are never split across runs: the first one that would pass the cap, and every one
  after it, waits for the next run, though the first of a run is always taken even if it alone is
  over the cap. A zone already known to be a wildcard is not permuted.
- **Well-known labels.** Each root also tries `autodiscover`, `lyncdiscover`,
  `enterpriseenrollment`, `enterpriseregistration` and `mta-sts`, even when the wordlist lacks them
  and only when permutations are on, so a root check is the list plus up to five names (the built-in
  list already holds all five, so it stays at 4860). Seeds do not use them, and neither does a root
  already known to be a wildcard zone.
- **After an upgrade.** A changed list repeats every permutation check once, on the first run
  that uses it. Adding the well-known labels repeats each root's check once and no seed check, and
  that repeat spends the per-run cap: at the default cap about 40 roots' repeats fit in one run, and
  the rest are deferred to the next.

**Sensitive paths.** The built-in list has 268 entries. Each one has a body signature or byte prefix
and a severity (`high`, `medium` or `low`), so a site that answers 200 to everything is not flagged.
Entries that were in earlier releases are unchanged, so their earlier results stay current and only
new entries are requested on the first run after an upgrade.

- **Volume.** Each path is requested once per live web service that is not served by a third-party
  SaaS platform, so a run sends services × entries requests: 268 per service. At the default
  `--rate-per-host` of 5 requests a second to an address, one service takes about 54 seconds. Services
  on different addresses are checked in parallel, up to `--concurrency`; 100 services take about
  9 minutes if each answers in 200 ms.
- **Per-run cap.** `sensitive_path_max_requests` (`--sensitive-path-max-requests`, default 50000,
  at least 1; a top-level setting, not part of `sensitive_paths`) caps the requests in one run.
  Requests go entry by entry in severity order, then by service, so every service gets its
  highest-severity paths first. The rest wait for later runs, and a hit from an earlier run stays
  current while its neighbours wait.

A cap that defers work is not a failure: the stage shows `done`, and the summary gives the amount
deferred for each stage (names for permutations, requests for sensitive paths, addresses for `shodan-host`, searches for `identifier-pivot`, hostnames for `dnshistory`) under `Deferred to
the next run`, and as the envelope's `deferred` list under `--json`. A run that only deferred work
exits 0. Run the same command again to do the rest.
