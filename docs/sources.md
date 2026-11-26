# Third-party sources

## RDAP netblocks and registrants

The `rdap` procedure runs under `--passive`. It contacts only `data.iana.org` and the RDAP servers of
the five regional registries: `rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`,
`rdap.lacnic.net` and `rdap.afrinic.net`. Nothing it finds enters scope on its own.

- **Netblocks and ASNs of an organisation.** For each `--org` input it searches every registry that
  returns an organisation's networks and autonomous systems: ARIN and APNIC. RIPE, LACNIC and
  AFRINIC's RDAP servers return the organisation but not its networks, so those jobs complete
  with no results and a WARN line saying so (`org-asn` covers RIPE through RIPEstat). A registry's
  organisations are kept only when the name contains every word of the `--org` input, ignoring
  legal suffixes (the rule `org-asn` applies), and at most 50 netblocks and autonomous systems per
  registry are kept, with a WARN line when more were returned. Each netblock is a `netblock`
  candidate in `candidates.csv` (a range that is not one CIDR is split into CIDRs), and each
  autonomous system is an `asn` candidate. Pass one as `--cidr` or `--asn` to bring it into scope.
- **Registrants of addresses.** Each address in `ips.csv` that is port-eligible, is not shared
  provider infrastructure and is not inside an input or ASN-expanded netblock is looked up once, at
  the registry the IANA bootstrap file names. The registered netblock, its registrant and the
  registry fill the `registrant`, `registrant_netblock` and `registry` columns of `ips.csv`;
  `owner` still says who announces the address. Another address inside a registered netblock reuses
  the answer. A referral to another of the five registries is followed, up to three times; a
  referral to any other server completes the lookup with no data and a WARN line naming the address.
- **Organisation candidates.** A registrant that holds three or more registered netblocks among the
  addresses, none of whose recorded addresses is shared provider infrastructure, and whose name does
  not match an `--org` input, is an `organisation` candidate in `candidates.csv`. Its
  `evidence_count` is the number of netblocks. Pass it as `--org` to search the registries for its
  own netblocks.
- **Quota and refresh.** A 429 from any server stops the procedure for the run, with one WARN line; the
  jobs that remain are retried on the next run. Each lookup is made once per engagement and
  refreshed only by `--redo rdap`. The bootstrap file is fetched once per run. The jobs are keyed
  by address and organisation, not by the scope, so an address that becomes eligible later is looked
  up then.

## Shodan per address

With `keys.shodan`, the `shodan-host` procedure (it runs under `--passive`, and is `not-configured (no
key)` without the key) looks up each address that `ips.csv` marks port-eligible and that is either
outside every in-scope netblock, or inside one whose `shodan` search stopped at its page cap
without returning it. It records Shodan's TCP ports and banners, and its hostnames: one under an
in-scope root becomes a hostname, and any other becomes a candidate root in `candidates.csv`. UDP
services are not recorded. A 404 is an address Shodan does not know: the job completes with
nothing. The `shodan` netblock search also records the ports it returns, so the addresses it
returned need no lookup. An engagement that ran `shodan` before it recorded ports gets them only
after `--redo shodan`, and the summary says when a netblock search was truncated.

- **Cap.** At most `shodan.max_hosts` addresses (default 500) are looked up per run, in address
  order. The rest are deferred, which is not a failure: the procedure shows `done`, and the number of
  addresses deferred is under `Deferred to the next run` (the unit of that number is addresses).
- **Refresh.** Shodan's data for an address is refreshed only by `--redo shodan-host`. The job is
  keyed by the address and not by the scope, so a hostname under a root you promote later was
  recorded only as a candidate root, and becomes a hostname after `--redo shodan-host`.
- **Banners.** Shodan's banner is cut to its first line or 256 characters, whichever is shorter,
  and escaped like nyx's own. When both have a banner, nyx's is shown.
- **Never connected to.** A TCP port Shodan reports outside the configured `--ports` list is shown
  as unconfirmed and nyx never connects to it. Nothing Shodan says makes nyx probe or connect
  anywhere.
- **nyx decides.** Its own handshake takes precedence, whichever came first. A port nyx finds
  closed (the connection is rejected) is no longer current in `open-ports.csv` and drops out of the
  counts and findings; a port that does not answer within the connect timeout stays unconfirmed. A
  port that was checked before Shodan reported it, and that nyx did not find open, is checked once
  more; later runs do not.
- **Findings.** A risky port only Shodan reports is the same finding in `risk-ports.csv` one severity
  step lower (low, not medium) with `confirmed` `no`. When the `ports` procedure opens it, the row becomes
  the full severity with `confirmed` `yes`, and a new `+` line is printed at the raised severity.
- **Counts.** The open-port count is split into `open ports (confirmed)` (nyx completed a
  handshake) and `open ports (third-party reported)` (all others that are shown). The summary has a
  line `N risky ports reported by Shodan, unconfirmed` when N is above zero, and the `--json`
  envelope carries it as `data.unconfirmed_risky_ports` (a number, 0 when there are none), with the
  procedures' lines as `data.notes`.

## Reverse IP

The `reverseip` procedure runs under `--passive` and needs no key. For each recorded address that may be
port-checked, so one that is in an in-scope netblock, or is dedicated to the organisation (its owner
is known and it is not shared provider infrastructure) and is not excluded, it asks HackerTarget's
reverse IP lookup (IPv4 only) which hostnames point at it, and, with `keys.securitytrails`,
SecurityTrails for the domains whose current A or AAAA record is the address. It never walks a
netblock: only an address another procedure recorded is asked. Nothing it finds enters scope on its own.

- **Names.** A name under an in-scope root is a hostname, and an excluded name is recorded as
  excluded. Any other name gives its registrable domain as a candidate root in `candidates.csv`, and
  the hostname itself is not kept. Having no names, or HackerTarget's "no records" reply, completes
  the job with nothing. No candidate root is resolved or contacted.
- **Shared hosting.** An address that returns more than `reverseip.max_domains` distinct
  registrable domains (default 100) is treated as unrecognised shared hosting: nothing is recorded
  for it, and a WARN line names the address. The cap is part of the job, so changing it asks
  every address again.
- **Quota.** HackerTarget's spent quota (a 429, or its text reply with a 200) stops the procedure for
  the run with one WARN line, and the jobs that remain are retried on the next run. A rejected
  SecurityTrails key also stops the procedure, HackerTarget lookups included.
- **IPv6.** HackerTarget cannot answer an IPv6 address, so one is asked only with
  `keys.securitytrails`, and gets its job when the key is added.
- **Refresh.** Each address is asked once per engagement, and new results arrive only with
  `--redo reverseip`. The job is keyed by the address and the cap, not by the scope, so a hostname
  under a root you promote later was recorded only as a candidate root, and becomes a hostname after
  `--redo reverseip`. A SecurityTrails key added later is used only for the addresses not yet
  asked, so an IPv4 address HackerTarget already answered reaches SecurityTrails only after
  `--redo reverseip`.
- **Candidates.** A candidate root found on two or more addresses is `medium` in `candidates.csv`,
  with `reverseip` in `sources`. It never calls Shodan: Shodan's hostnames for an address come from
  `shodan-host`.

## GitHub code search

The `github` procedure runs under `--passive` and needs `keys.github`, a GitHub personal access token
(it needs no scopes: GitHub's code search refuses requests that carry no token). For each in-scope
input root it searches GitHub's public code for the quoted root domain, reading results up to
`github.max_results` (default 500; GitHub serves at most 1,000 for a search). The procedure queries
GitHub about the domain, not the target: the target is never contacted, and GitHub receives only the
root's name.

- **What is recorded.** Each match is a row in `code-mentions.csv` with its `repository`, file `path`
  and `url` on GitHub, and the `hostnames` that the returned fragment names under an in-scope root.
  Those hostnames are also recorded as hostnames, so a forgotten internal name can be resolved like
  any other. The root itself is not listed, since every match mentions it. The procedure records only
  locations: no fragment text is written to a file or the engagement database, and repository, path
  and URL are sanitised like any text from outside. Personal-account repositories are recorded like
  any other. A name found in a fragment that is under no in-scope root is ignored.
- **What is not.** Nothing is inferred about secrets, credentials or tokens, the files are never
  cloned or read, and no finding is produced. Whether a match is worth opening is for you to judge.
- **Limits.** GitHub's code search allows few requests a minute. When it answers that the limit is
  reached and lifts it within 60 seconds (`Retry-After`, or `X-RateLimit-Reset` with none left), the
  procedure waits and asks the same page again, up to five times in a row for one page; an interrupt
  during the wait ends the run promptly, with the roots already searched kept. A reset further away, a
  sixth refusal of the same page, a 401, and any other 403 or 429 stop the procedure for the run, with
  the roots not yet searched retried on the next. Reading stops after GitHub's tenth page of 100
  results, the last it serves.
- **Refresh.** A root's search completes once. New mentions appear only after `--redo github`, or when
  `github.max_results` changes, which searches again. A root added to scope later is searched in the
  next run. The job is keyed by the root and the cap, not by the scope, so a hostname under a root
  you add later was ignored and is recorded only after `--redo github`. After a redo, a match that is
  gone is marked not current, and its row keeps only its URL (which names the repository and the path).
  A file that mentions two roots is one row, from the root searched last.

## Name guessing

Besides the names third-party sources return, nyx guesses names and keeps those that exist. Every
guess is one A lookup through the public resolvers, so guessing runs under `--passive` and needs no
`--authorised`; nothing is sent to the target's own servers but DNS lookups.

- **What counts as found.** A guessed name counts only when its A lookup answers with a CNAME or an
  A address. A CNAME counts even when its target does not exist (a dangling CNAME is how a takeover
  starts). An answer with no records, SERVFAIL or NXDOMAIN is not a find, and AAAA is never asked
  when guessing, so a name that has only an IPv6 address, or only other records (MX or TXT, say),
  is not found by guessing. Many hosted zones (Cloudflare's among them) answer "no records" rather
  than NXDOMAIN for a name that does not exist, which is why such an answer is not a find. A found
  name is then resolved like any other.
- **The wordlist under each root.** The `permutations` procedure tries each word of the wordlist
  (`wordlist`; the built-in list by default), plus a few well-known labels such as `autodiscover`,
  directly under each input root. A root's list is one job of about 103,000 lookups with the
  built-in list.
- **Variants of found labels.** It also tries variants of the first label of each name another
  procedure found (digits changed, wordlist words joined with a hyphen, a dot or nothing), up to
  `permutations.max_per_seed` per name. Names it found itself are not varied again. Together the
  wordlist and the variants are capped at `permutations.max_names` lookups a run; the rest are
  deferred to the next run. Neither is tried in a zone until its wildcard check has completed, so
  a zone whose check keeps failing gets no guessed names, and nothing is guessed directly under a
  wildcard zone.
- **Learned names.** The `learned-names` procedure learns the labels of the names already found and
  tries each under the other zones that have names. A name gives its labels below its input root
  (`staging.a.example.com` under `example.com` gives `staging` and `a`) when it is in scope, has
  an address or a CNAME, is not wildcard-only, and its zone's wildcard check has completed. A label
  with hyphens also gives its parts (`api-dev2` gives `api-dev2`, `api` and `dev2`), except one that
  begins `xn--`; a label of digits only is not learned. The zones it tries labels under are the
  input roots and every in-scope name between a found name and its nearest input root
  (`dev.example.com` for `api.dev.example.com`). So with `staging.a.example.com` and `api.b.example.com` found, it tries
  `staging.b.example.com` and `api.a.example.com`. Names found meanwhile, by any procedure, are
  learned from in the same run, until a round adds nothing new or the cap is spent.
  - **Once.** Each name is tried once per engagement, whatever the answer; `--redo learned-names`
    tries them again. A name already known is not tried, nor a parent name (below), nor a wordlist
    word directly under an input root while `permutations` is on (its wordlist job asks it). With
    `--skip permutations` learning tries those words too.
  - **Cap and order.** `learned_names.max_names` (`--learned-names-max-names`, default 50,000)
    caps the names tried in one run, separately from `permutations.max_names`. When a round has
    more, the labels that start found names (with an address or a CNAME) in the most zones go
    first, then alphabetically, and a label's zones go in alphabetical order. The rest are deferred to the next run and counted under
    `Deferred to the next run` in the summary.
  - **Wildcards and exclusions.** Nothing is tried under a zone until its wildcard check has
    completed and found no wildcard, so a zone whose check keeps failing gets no learned names. An
    excluded name is never tried, and nothing is tried under one.
  - **Turning it off.** `--skip learned-names` skips learning and leaves `permutations` running, and
    `--skip permutations` the reverse. `permutations.enabled: false` (`--no-permutations`) turns
    both off, and both show `not-configured (disabled)`.
- **Parent names.** Every name between a found name and its input root is resolved, so
  `b.example.com` is listed when `a.b.example.com` was found and `b.example.com` has an address or
  a CNAME. A parent that does not resolve, and that no source found, is listed in no file
  (`unresolved.txt` included), though learning still tries labels under it. A parent is asked once
  its zone's wildcard check has completed, and one that only the wildcard answers counts as not
  resolving. Parent names are resolved even when learning is skipped or turned off, and they are
  reported under `resolve`.
- **Only under input roots.** Learning and parent names apply only to names under an input root: a
  candidate's labels are not learned and its parents are never asked.
