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
in-scope root becomes a hostname, and any other becomes a candidate root in `candidates.csv`,
with two exceptions. A name that holds the address it was listed for
(`ec2-203-0-113-7.compute.amazonaws.com`) is the reverse name its network gave the address, and
its domain is the network's. And when every in-scope name on the address is one
[a third party serves](output.md#names-a-third-party-serves), the other names there are that
party's other customers. Neither gives a candidate. UDP
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
netblock: only an address another procedure recorded is asked. A name it finds enters scope only by
its address (see [Names on in-scope addresses](#names-on-in-scope-addresses)).

- **Names.** A name under an in-scope root is a hostname, and an excluded name is recorded as
  excluded. Any other name gives its registrable domain as a candidate root in `candidates.csv`. For
  an address inside an in-scope netblock the name itself is kept too, as a candidate hostname; for
  any other address it is not. Having no names, or HackerTarget's "no records" reply, completes
  the job with nothing. A candidate is never contacted: with a netblock in scope it is looked up
  through the public resolvers, and without one it is not looked up at all.
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
  `--redo reverseip`. The job is keyed by the address, the cap and whether the address is inside an
  in-scope netblock, so an address asked before its netblock came into scope is asked once more
  after, to keep the names it hosts. The rest of the scope is not in the key, so a hostname under a
  root you promote later was recorded only as a candidate root, and becomes a hostname after
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
  (`unresolved.txt` included), apart from rows of its own records in `resolutions.csv`, though learning still tries labels under it. A parent is asked once
  its zone's wildcard check has completed, and one that only the wildcard answers counts as not
  resolving. Parent names are resolved even when learning is skipped or turned off, and they are
  reported under `resolve`.
- **Only under input roots.** Learning and parent names apply only to names under an input root: a
  candidate's labels are not learned and its parents are never asked, and the same holds for a
  name in scope by its address (see [Names on in-scope addresses](#names-on-in-scope-addresses)).

## Names on in-scope addresses

The `in-netblock` procedure runs under `--passive` and needs no key. While the engagement has an
in-scope netblock (a `--cidr` input, or a netblock of an `--asn` input), it looks up the A and AAAA
records of each current candidate hostname and candidate root in `candidates.csv`, in the file's
order, through the public resolvers. A candidate is never contacted. A hostname whose lookup gives
an address inside an in-scope netblock enters scope on its own, as bbot does, so the other names
an organisation serves from its netblocks are probed and reported without promoting each one.

- **Which names.** A candidate is looked up when a source other than `in-netblock` found it. Up to
  `in_netblock.max_lookups` are asked in one run (default 1,000); the rest are deferred to the next
  run and counted under `Deferred to the next run`. A candidate is asked once per engagement, and
  again after `--redo in-netblock` (which also asks again each name in scope by its address) or
  once it has stopped being a candidate and is found again. A candidate looked up before a
  netblock came into scope is judged against it without being asked again.
- **The rule.** A name enters scope when an address of its lookup is inside an in-scope netblock,
  unless the name is excluded, an address of its lookup is in an excluded CIDR, or it is generic: a
  name that holds the four numbers of an IPv4 address it resolves to, forwards or backwards,
  joined by `.` or `-` (`203-0-113-5.static.example.net`, `5.113.0.203.example.net`), never enters
  scope this way. An address more than `in_netblock.max_names_per_address` looked-up names point at
  (default 100) is treated as shared hosting: none of its names enters scope by it, a WARN line
  names the address, and the names it had brought in leave scope. A candidate root whose own name
  meets the rule enters scope as one hostname and stays a candidate root, since passing it as a
  domain is still how its subdomains are found.
- **In scope.** Such a name is listed in `scope.csv` with the address and netblock that brought it
  in, and in `subdomains.txt`. Its rows in `resolutions.csv` and `ips.csv` come from its lookup,
  which `resolve` does not repeat. It is probed, crawled, port-checked and checked for findings like
  any in-scope hostname, except that it gets no origin check, and identifiers seen only on its
  pages are not searched for. It is contacted only at its addresses inside the in-scope netblocks:
  an address of its outside them is listed in `ips.csv` but never dialled for it. Without
  `--authorised`, or under `--passive`, it is listed and resolved but not contacted.
- **Only the name.** Its registrable domain does not become a root: no source is asked about it, no
  name is guessed or learned under or beside it, its parents are not resolved, its NS, MX and TXT
  records are not asked for, it gives no `third-parties.csv` row, and names under its registrable
  domain in the text of its responses are ignored. The registrable domain is a candidate root with
  the source `in-netblock`, and is not looked up on that evidence alone. A wildcard of a zone that
  is itself in scope by its address is detected as for any zone in scope.
- **Leaving.** A name stays in scope only while the rule holds. When its lookup, asked again after
  `--redo in-netblock`, no longer gives an address inside an in-scope netblock, or the name is
  excluded, or no source but `in-netblock` finds it any more, it is a candidate (or excluded, or
  gone) again, and `changes.csv` reports it. A name found only by probing a name in scope by its
  address (in its certificate or redirects, say) does not count as found by another source, so two
  such names cannot keep each other in scope.
- **Turning it off.** `in_netblock.enabled: false` (`--no-in-netblock`) turns the lookups off, and
  the names that had entered scope this way are candidates again. The lookups already made are
  kept, unless `--redo in-netblock` is given while it is off, which discards them.
- **Reported.** The summary says `N hosts in scope by address` (`1 host` for one) when there are any, and the `--json`
  envelope carries the number as `data.hosts_in_scope_by_address` (0 when there are none).

## Records of every name

The `dnsroot` procedure asks each input root for its NS, SOA, TXT, CAA and MX records and a list of
SRV service names. The `dnsrecords` procedure asks the names below the roots, through the public
resolvers, so it runs under `--passive` and needs no `--authorised`.

- **Which names.** Every in-scope hostname below an input root that resolve did not answer
  NXDOMAIN, that is not wildcard-only and that is not an alias (a name with a CNAME, which can own
  no other record), once its zone's wildcard check has completed. A parent name that does not
  resolve is asked too. A candidate, an excluded name or a name in scope by its address is never
  asked.
- **What is asked.** Each name's NS, MX and TXT records, one lookup each. A name with NS records of
  its own is a delegated zone and also gets the SOA and CAA lookups and the SRV service list a root
  gets (16 more lookups); it gets no mail posture. An in-scope domain that an SPF record includes
  or redirects to is asked for its TXT records only. Only records a name owns are kept: an alias's
  target's records are not the alias's, for roots too.
- **What it finds.** The records are rows of `resolutions.csv`. An in-scope target of an NS, MX or
  SRV record, the in-scope target of an in-scope name's CNAME, and an in-scope name written in a
  TXT value become hostnames, are resolved, and are asked for their own records in the same run; a
  name with a label that starts with `_` is not a hostname. A target outside scope, a verification
  TXT and the domains an SPF record names are rows of `third-parties.csv` under the name's input
  root (a root's own `mx` and `spf` rows come from `email`). An SPF record's addresses are
  [candidates](candidates.md). A subdomain's name servers and mail hosts are never searched for
  shared infrastructure.
- **Failures.** A timeout fails only that name's lookup of that type, which is asked again on the
  next run. SERVFAIL, NXDOMAIN and an empty answer are results, so a broken delegated zone never
  keeps a run partial.
- **Cost.** About 3 lookups for each name below a root that is not an alias, and 16 more for each
  delegated zone, once per engagement; there is no cap. `--skip dnsrecords` turns it off and leaves
  the roots' lookups, and `--redo dnsrecords` asks every name again.

## Hostnames in responses

nyx takes an in-scope hostname from anywhere in the responses it already receives, not only from
links: page text and comments, JSON, scripts and header values (a `Content-Security-Policy` entry
written `*.cdn.example.com` gives `cdn.example.com`). Reading a response sends nothing, and a name
found this way is resolved, probed and crawled like any other in-scope hostname.

- **What is read.** Every response that `httpprobe` (each redirect hop, the first included),
  `crawl` (pages of any type and status, same-origin redirect hops, `/robots.txt`, `/sitemap.xml`
  and sitemap indexes), `jsparse` (every answer to a script URL, a redirect, an error page or
  markup included) and `origincheck` receive, headers and body, and every banner `ports` reads
  from an open port, whichever hostnames its address serves. Only the part nyx already reads is
  searched: a body past its size limit (1 MiB, or 4 MiB for a script) is not, and a name that runs
  up to the point a limit cut, or to the end of a banner that filled the 1,024-byte read, is left
  out.
- **How a name is read.** A name written with escapes is read through them: percent-encoding
  (`https%3A%2F%2Fapi.example.com`), backslash-escaped slashes (`https:\/\/api.example.com`), JSON
  and script escapes (`\u002F`, `\x2F`) and HTML character references (`&#x2F;`). Upper case is
  read as lower case. A name is read whole, so `www.example.com.evil.net` gives nothing.
- **What is left out.** A name under no input root (it is not a candidate and not a third party;
  names from links, redirects and certificates still give candidates), an input root itself, the
  responding host's own name, and a name with an underscore in it (`_dmarc.example.com`). A name
  written with non-ASCII letters is not read, and a Latin, Greek or Cyrillic letter touching a name
  leaves it out. The responses to the sensitive-path list and the favicon are not searched, nor the banners
  only Shodan reports. An excluded name is listed as excluded and never contacted.
- **The cap.** At most 1,000 distinct names are taken from the responses of one web service over
  the engagement: its probe, its crawl and the scripts it serves together, a script counting
  against the origin that serves it. `crawl` and `jsparse` take hostnames only this way, so the
  hosts of links count too (their URLs are still recorded). Every name read from a service uses a
  place, one nyx already knew from another source included, and a name once taken keeps its
  place. A redirect target and a certificate name that `httpprobe` records do not use one. A run
  that leaves names out ends with one warning per service, giving the number of distinct names
  left out in that run, or "more than 10,000". An `origincheck` response has a cap of 1,000 of its
  own, and a banner is too short to reach it.
- **Kept as records.** Each name taken from a web service is kept as a `text_hostname` record of
  the service, which `nyx recon export --kind text_hostname` shows; it has no output file.
- **Authorisation.** All five procedures contact the target, so the reading needs `--authorised`
  and is off under `--passive`.
- **A root added later.** A response already read is not read again for a new root: that takes
  `--redo` of the procedure (`--redo crawl`, say), and `--redo ports` connects to every port
  again.
