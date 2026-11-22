# Third-party sources

## RDAP netblocks and registrants

The `rdap` stage runs under `--passive`. It contacts only `data.iana.org` and the RDAP servers of
the five regional registries: `rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`,
`rdap.lacnic.net` and `rdap.afrinic.net`. Nothing it finds enters scope on its own.

- **Netblocks and ASNs of an organisation.** For each `--org` input it searches every registry that
  returns an organisation's networks and autonomous systems: ARIN and APNIC. RIPE, LACNIC and
  AFRINIC's RDAP servers return the organisation but not its networks, so those checks complete
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
- **Quota and refresh.** A 429 from any server stops the stage for the run, with one WARN line; the
  checks that remain are retried on the next run. Each lookup is made once per engagement and
  refreshed only by `--redo rdap`. The bootstrap file is fetched once per run. The checks are keyed
  by address and organisation, not by the scope, so an address that becomes eligible later is looked
  up then.

## Shodan per address

With `keys.shodan`, the `shodan-host` stage (it runs under `--passive`, and is `not-configured (no
key)` without the key) looks up each address that `ips.csv` marks port-eligible and that is either
outside every in-scope netblock, or inside one whose `shodan` search stopped at its page cap
without returning it. It records Shodan's TCP ports and banners, and its hostnames: one under an
in-scope root becomes a hostname, and any other becomes a candidate root in `candidates.csv`. UDP
services are not recorded. A 404 is an address Shodan does not know: the check completes with
nothing. The `shodan` netblock search also records the ports it returns, so the addresses it
returned need no lookup. An engagement that ran `shodan` before it recorded ports gets them only
after `--redo shodan`, and the summary says when a netblock search was truncated.

- **Cap.** At most `shodan.max_hosts` addresses (default 500) are looked up per run, in address
  order. The rest are deferred, which is not a failure: the stage shows `done`, and the number of
  addresses deferred is under `Deferred to the next run` (the unit of that number is addresses).
- **Refresh.** Shodan's data for an address is refreshed only by `--redo shodan-host`. The check is
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
  step lower (low, not medium) with `confirmed` `no`. When the `ports` stage opens it, the row becomes
  the full severity with `confirmed` `yes`, and a new `+` line is printed at the raised severity.
- **Counts.** The open-port count is split into `open ports (confirmed)` (nyx completed a
  handshake) and `open ports (third-party reported)` (all others that are shown). The summary has a
  line `N risky ports reported by Shodan, unconfirmed` when N is above zero, and the `--json`
  envelope carries it as `data.unconfirmed_risky_ports` (a number, 0 when there are none), with the
  stages' lines as `data.notes`.

## Reverse IP

The `reverseip` stage runs under `--passive` and needs no key. For each recorded address that may be
port-checked, so one that is in an in-scope netblock, or is dedicated to the organisation (its owner
is known and it is not shared provider infrastructure) and is not excluded, it asks HackerTarget's
reverse IP lookup (IPv4 only) which hostnames point at it, and, with `keys.securitytrails`,
SecurityTrails for the domains whose current A or AAAA record is the address. It never walks a
netblock: only an address another stage recorded is asked. Nothing it finds enters scope on its own.

- **Names.** A name under an in-scope root is a hostname, and an excluded name is recorded as
  excluded. Any other name gives its registrable domain as a candidate root in `candidates.csv`, and
  the hostname itself is not kept. Having no names, or HackerTarget's "no records" reply, completes
  the check with nothing. No candidate root is resolved or contacted.
- **Shared hosting.** An address that returns more than `reverseip.max_domains` distinct
  registrable domains (default 100) is treated as unrecognised shared hosting: nothing is recorded
  for it, and a WARN line names the address. The cap is part of the check, so changing it asks
  every address again.
- **Quota.** HackerTarget's spent quota (a 429, or its text reply with a 200) stops the stage for
  the run with one WARN line, and the checks that remain are retried on the next run. A rejected
  SecurityTrails key also stops the stage, HackerTarget lookups included.
- **IPv6.** HackerTarget cannot answer an IPv6 address, so one is asked only with
  `keys.securitytrails`, and gets its check when the key is added.
- **Refresh.** Each address is asked once per engagement, and new results arrive only with
  `--redo reverseip`. The check is keyed by the address and the cap, not by the scope, so a hostname
  under a root you promote later was recorded only as a candidate root, and becomes a hostname after
  `--redo reverseip`. A SecurityTrails key added later is used only for the addresses not yet
  asked, so an IPv4 address HackerTarget already answered reaches SecurityTrails only after
  `--redo reverseip`.
- **Candidates.** A candidate root found on two or more addresses is `medium` in `candidates.csv`,
  with `reverseip` in `sources`. It never calls Shodan: Shodan's hostnames for an address come from
  `shodan-host`.

## GitHub code search

The `github` stage runs under `--passive` and needs `keys.github`, a GitHub personal access token
(it needs no scopes: GitHub's code search refuses requests that carry no token). For each in-scope
input root it searches GitHub's public code for the quoted root domain, reading results up to
`github.max_results` (default 500; GitHub serves at most 1,000 for a search). The stage queries
GitHub about the domain, not the target: the target is never contacted, and GitHub receives only the
root's name.

- **What is recorded.** Each match is a row in `code-mentions.csv` with its `repository`, file `path`
  and `url` on GitHub, and the `hostnames` that the returned fragment names under an in-scope root.
  Those hostnames are also recorded as hostnames, so a forgotten internal name can be resolved like
  any other. The root itself is not listed, since every match mentions it. The stage records only
  locations: no fragment text is written to a file or the engagement database, and repository, path
  and URL are sanitised like any text from outside. Personal-account repositories are recorded like
  any other. A name found in a fragment that is under no in-scope root is ignored.
- **What is not.** Nothing is inferred about secrets, credentials or tokens, the files are never
  cloned or read, and no finding is produced. Whether a match is worth opening is for you to judge.
- **Limits.** GitHub's code search allows few requests a minute. When it answers that the limit is
  reached and lifts it within 60 seconds (`Retry-After`, or `X-RateLimit-Reset` with none left), the
  stage waits and asks the same page again, up to five times in a row for one page; an interrupt
  during the wait ends the run promptly, with the roots already searched kept. A reset further away, a
  sixth refusal of the same page, a 401, and any other 403 or 429 stop the stage for the run, with
  the roots not yet searched retried on the next. Reading stops after GitHub's tenth page of 100
  results, the last it serves.
- **Refresh.** A root's search completes once. New mentions appear only after `--redo github`, or when
  `github.max_results` changes, which searches again. A root added to scope later is searched in the
  next run. The check is keyed by the root and the cap, not by the scope, so a hostname under a root
  you add later was ignored and is recorded only after `--redo github`. After a redo, a match that is
  gone is marked not current, and its row keeps only its URL (which names the repository and the path).
  A file that mentions two roots is one row, from the root searched last.
