# recon

Passive-first reconnaissance for an authorised engagement. Give it domains, organisations, ASNs or
netblocks and it records the hosts, IPs, web services, URLs and open ports it can find, plus a
severity-ranked list of obvious exposures (dangling CNAMEs, public cloud storage, weak email
policy, risky open ports, sensitive paths, expiring certificates). It is a single Go binary for
macOS and Linux, with no external tools to install.

## Install

```sh
go install github.com/rafaelh/recon/cmd/recon@latest
```

Go 1.21 or later is enough when `GOTOOLCHAIN=auto`, the upstream default: it fetches the toolchain
named in `go.mod`. Some Linux distributions' Go packages set `GOTOOLCHAIN=local`; check with
`go env GOTOOLCHAIN`, and if it says `local`, run `GOTOOLCHAIN=auto go install ...` instead. Set
`CGO_ENABLED=0` for a fully static Linux binary.

From a clone:

```sh
make build   # ./recon for this machine
make dist    # dist/recon-{darwin,linux}-{amd64,arm64}
make test    # vet, race tests, and a cross-target vet for all four platforms
```

`recon --version` prints the build's version (`devel` when there is none). Windows is not supported.

## Quick start

`output_dir` defaults to `.`, so run from a working directory outside this repository, or pass
`--output-dir`.

```sh
recon example.com                  # all stages; asks you to confirm authorisation on a terminal
recon example.com --passive        # third-party sources only; nothing at the target is contacted
recon example.com --authorised     # confirm authorisation up front (needed with --json or no terminal)
recon -e example-com               # re-run or resume an existing engagement by name
```

Results are written to `<output-dir>/<engagement>/`. The log goes to stderr and the summary to stdout
(see [Console and JSON](#console-and-json)).

## Inputs and engagements

- **Inputs:** positional domains, `-d <file>` (one root domain per line, `#` comments allowed),
  `--org <name>`, `--asn <AS123|123>`, `--cidr <netblock>`. The last three are repeatable. An ASN's
  announced netblocks become in scope.
- **Exclusions:** `-x <hostname|*.wildcard|CIDR>` (repeatable) and `--exclude-file <file>`. An
  excluded host, or any host that resolves into an excluded CIDR, is recorded as excluded and its
  addresses are never contacted.
- **Engagement name:** `-e <name>`, or derived from the first input: the first positional domain,
  else the first line of the domains file, else the first `--org`, `--asn` or `--cidr`. The
  derivation depends on the order of your inputs. Either way, the name is lowercased and sanitised.
- **Re-runs:** inputs and exclusions are added to those already stored for the engagement. Nothing
  is removed because you left it out of a later run.
- **Resume:** a re-run performs only the checks not yet done. Checks that failed (a transient
  error, not a negative result) are retried on later runs. An interrupted run resumes the same way.
- **`--redo <stage>`:** performs every check of one stage again. The stage names are listed in
  `recon --help`.
- **`--skip <stage>`:** turns a stage off (repeatable; the `skip` setting, or `RECON_SKIP` as a
  comma-separated list, does the same). A skipped stage is shown as `not-configured (skipped)`,
  whatever else would stop it, and does nothing: results it found earlier stay in the files. The flag
  replaces the setting for that run, and `--skip none` runs every stage. An unknown stage, a stage
  also given to `--redo`, and `resolve`, `wildcard`, `ipowner` and `providerranges` (other stages'
  safety depends on them) exit with code 2. When every stage that contacts the target is skipped,
  there is no authorisation prompt.

## Configuration

- **Config file:** `$XDG_CONFIG_HOME/recon/config.yaml`, which defaults to
  `~/.config/recon/config.yaml`. Use `--config <file>` to choose another. Unknown keys are
  rejected.
- **Precedence:** flags override `RECON_*` environment variables, which override the file. An
  environment variable is `RECON_<UPPER_SNAKE>` with `.` replaced by `_`, for example
  `RECON_RATE_PER_HOST` and `RECON_CRAWL_MAX_DEPTH`.
- **API keys:** set only as `keys.<source>` in the file or `RECON_KEYS_<SOURCE>` in the
  environment. There are no key flags, so keys never appear in shell history or process lists.
  Keys are redacted from all output and files.
- **Keyed sources:** `securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys` and `chaos`. A
  stage whose key is missing is shown as `not-configured`. `keys.shodan` also turns on `shodan-dns`,
  which lists each in-scope root's subdomains and their A, AAAA, CNAME, MX and NS records; it costs
  one Shodan query credit per result page, for each root. `keys.censys` is a Censys personal access
  token and searches certificates for names under each root. `keys.chaos` is a ProjectDiscovery
  Chaos key. A 401, 403 or 429 stops that stage for the run. Each of these three follows result pages
  up to `shodan_dns.max_pages`, `censys.max_pages` or `chaos.max_pages` (default 10; raising one
  repeats the stage's checks, and reaching one is a warning). Chaos answers with the
  whole list in one page, so its cap is not reached. `certspotter` takes an
  optional key: it runs without one, and sends `keys.certspotter` when it is set. The other sources
  need no key.
- **Settings:** all settings and their defaults are listed by `recon --help`.

Example `config.yaml` (a leading `~/` in `output_dir`, `wordlist` or `sensitive_paths` is your home
directory):

```yaml
output_dir: ~/engagements
concurrency: 10
keys:
  securitytrails: your-securitytrails-key
  shodan: your-shodan-key
  virustotal: your-virustotal-key
  whoisxml: your-whoisxml-key
```

```sh
RECON_KEYS_SHODAN=your-shodan-key recon example.com
```

## Passive boundary

recon limits what target-owned systems can receive. It sends only:

- **DNS lookups.** Zone transfers are never attempted.
- **TCP handshakes** to the configured port list. It reads only what the service sends
  unprompted and sends nothing.
- **HTTP(S) GET and HEAD requests** to in-scope, non-excluded hosts, to same-host links found
  while crawling, to each service's `/robots.txt` and `/sitemap.xml` and the same-host URLs they
  list (robots.txt is read, not obeyed), and to the paths on the sensitive-path list.

It never sends credentials, submits forms, uses other HTTP methods, puts payloads in parameters or
headers, or requests paths beyond those listed. UDP is not used. Candidate hosts (found but not in
scope) and excluded hosts are never contacted. Everything else comes from third parties: CT logs
(crt.sh and Cert Spotter), web archives, passive DNS and search (HackerTarget and urlscan.io),
public DNS resolvers, RDAP/WHOIS, BGP data, keyed APIs and cloud-storage provider endpoints. Only
hostnames are recorded from Cert Spotter, HackerTarget and urlscan.io. When one of these three
reports that its free quota is spent, its stage alone stops, and its checks are retried on the next
run. The `otx` and `anubis` stages no longer exist, because neither service answers an unkeyed
client any more. An engagement that already holds their results keeps them, and a `skip` setting
that names either is rejected as an unknown stage.

The `providerranges` stage fetches the address ranges that seven providers publish: AWS, GCP,
Cloudflare (IPv4 and IPv6), Fastly, DigitalOcean, Oracle Cloud and Linode. Each list is its own
check, fetched once per engagement and refreshed only by `--redo providerranges`. A list that fails
to download, or has no ranges in it, is a failed check (named by `--debug`): the ranges fetched
before keep applying. Azure is classified by ASN only, because Microsoft publishes its ranges at a
changing URL.

All network access goes through one package. On every supported platform, a test fails if any other
package imports a network package or `syscall`, or uses `golang.org/x/sys/unix` for anything other
than signals and file locking, and if any package imports `os/exec`.

## Passive-only mode

`--passive` restricts a run to third-party sources. The stages that contact target-owned systems
(`httpprobe`, `crawl`, `sensitive-paths`, `ports` and `takeover`'s HTTP fingerprinting) are
shown as `not-configured (passive-only)`. Takeover findings that DNS evidence alone supports are
still reported. The restriction applies to that run only; a later run without `--passive` performs
the skipped checks.

## Authorisation acknowledgement

Before any stage that contacts target-owned systems, recon requires you to confirm you are
authorised to test the engagement's scope.

- On a terminal, you can confirm at the prompt or with `--authorised` (`--authorized` also works).
- With `--json` or no terminal there is no prompt, and only `--authorised` counts.
- The confirmation is remembered per engagement.
- Without it, those stages are shown as `not-configured (no authorisation)`, and the run writes one
  warning right after its header that names them and says that `--authorised` confirms
  authorisation. It names exactly the stages shown that way, so a stage left out by `--skip` is not
  named, and there is no warning under `--passive` or when no stage is left out. It appears on every
  run until authorisation is confirmed. Under `--json` it is a `warning` event.

## Large netblocks

If the in-scope IPv4 address count (ASN-expanded netblocks included) exceeds `netblock_limit`,
recon stops before contacting any address in them, shows the total and exits with code 3. Re-run
with `--allow-large-netblocks` to proceed. The approval is remembered with the engagement.

## Root DNS records and third parties

For each in-scope input root the `dnsroot` stage asks the public resolvers for its NS, SOA, TXT
and CAA records, one check per type, so a type that keeps failing does not block the others. It runs
under `--passive`. Zone transfers are never attempted. Each answer is a row in `resolutions.csv`: a
CAA value is written `<flags> <tag> "<value>"`, and an SOA value is the primary name server and
the administrative mailbox as an email address (`john\.doe.example.com` is `john.doe@example.com`).

- A name server (or SOA primary) inside the scope is a hostname, resolved, probed and port-checked
  like any other. A name server outside it is a `third-parties.csv` row with mechanism `ns`, and is
  never a candidate or contacted.
- A root TXT record that starts with one of these prefixes (in any case) is one `txt-verification`
  row per platform and root, naming the platform that domain ownership was verified with:
  `google-site-verification=` (Google), `MS=` (Microsoft 365), `atlassian-domain-verification=`
  (Atlassian), `docusign=` (DocuSign), `facebook-domain-verification=` (Facebook),
  `apple-domain-verification=` (Apple), `stripe-verification=` (Stripe),
  `adobe-idp-site-verification=` (Adobe), `hubspot-developer-verification=` (HubSpot),
  `zoom-domain-verification=` (Zoom), `dropbox-domain-verification=` (Dropbox),
  `salesforce-domain-verification=` (Salesforce), `have-i-been-pwned-verification=` (Have I Been
  Pwned) and `webexdomainverification.` (Cisco Webex). The token is public DNS, so it is in
  `resolutions.csv`, but not in `third-parties.csv`. A TXT record that matches nothing is only a row
  in `resolutions.csv`.

The `+` line for a new third party reads `third-party <platform> via txt-verification on <root>`,
and its `--json` `found` event carries `platform`, `mechanism` and `root`. The prefix list and the
name-server provider names are in the embedded `providers.yaml`.

## Web posture

From the responses `httpprobe` already receives, with no further request, recon records a few
obvious weaknesses of each live in-scope web service, and reports each as a low finding in
`risk-web-posture.csv`, one row per service and condition:

- `missing-hsts`: the first response of an HTTPS service has no `Strict-Transport-Security` header.
- `insecure-cookie`: a cookie set over HTTPS by any response in the redirect chain of an HTTPS
  service lacks `Secure` (a response received over plain HTTP is not judged for `Secure`). The
  cookie names (never their values) are in the row's `detail`, `;`-joined.
- `directory-listing`: the last page of the chain that the service itself served is an automatic
  directory listing (its title or first heading begins `Index of /`).
- `version-disclosure`: the first response's `Server` or `X-Powered-By` header carries a version, a
  `/` followed by a digit (`Apache/2.4.41` does; `nginx` and `ASP.NET` do not).

`web-services.csv` has the evidence in its `hsts` (`yes` or `no`, blank for HTTP), `insecure_cookies`
(each cookie name followed by `(secure)`, `(httponly)` or both, for the flag it lacks),
`directory_listing` (`yes` or `no`) and `version_disclosure` columns. A cookie that lacks only
`HttpOnly` is listed there but is not a finding. A service addressed by an IP literal or served by a
SaaS platform has the columns but no finding. Other headers, such as `Content-Security-Policy` and
`X-Frame-Options`, are not assessed.

An engagement probed by an earlier version has these columns blank, and none of these findings,
until you run `--redo httpprobe`. A condition that is gone after a redo marks its finding not
current.

## TLS detail

`httpprobe` records the TLS version, cipher and trust of each HTTPS service from the one handshake
it already makes, with no further connection. `web-services.csv` has them in three columns, which
take the place of the old `tls_error` and `tls_self_signed`:

- `tls_version`: the version the handshake negotiated (`TLS 1.2`).
- `tls_cipher`: the IANA name of the suite it chose (`TLS_AES_128_GCM_SHA256`).
- `tls_trust`: the first that applies of `expired` (including not yet valid), `hostname-mismatch`
  (the certificate does not name the host that was probed), `self-signed`, `untrusted-chain` or
  `trusted`. `untrusted-chain` depends on the root store of the machine running recon: a private or
  newly added root reads as `untrusted-chain` on a machine that does not hold it. The values come
  from the service's own first response, not from where it redirects, and are as of the probe.

To reach a service that has not moved on, every request recon sends to an in-scope service accepts
TLS 1.0 and 1.1, and offers CBC-mode and RSA key-exchange cipher suites as well as the modern ones.
RC4 and 3DES are never offered, and SSL 3.0 is not supported, so a service that offers only those
fails the handshake and is not recorded, as before. Requests to third-party sources keep the
default minimum of TLS 1.2. A service that supports TLS 1.2 or later is recorded with the version it
negotiates, as before.

recon sees only the version the service negotiates, so a service that offers an old version
alongside a newer one is **not** detected: only a service whose best version is 1.0 or 1.1 is
recorded as such. Enumerating the versions a server offers would take extra handshakes, and is not
done.

`risk-certificates.csv` has two new low findings, joined with `;` to the expiry and self-signed types
of the same service in the one row it has for each:

- `legacy-tls`: the service negotiated TLS 1.0 or 1.1.
- `hostname-mismatch`: the certificate does not name the probed host. A service addressed by an IP
  literal, or a host on shared provider infrastructure (any known provider's CNAME on its chain,
  such as a CDN, SaaS platform or cloud load balancer, or an address in shared provider space), has
  none.

An engagement probed by an earlier version has empty `tls_version` and `tls_cipher` until you run
`--redo httpprobe`. Its `tls_trust` is worked out from what was stored, so `hostname-mismatch` shows
without a redo. A finding that is gone after a redo (a modern version, a matching certificate) is
marked not current.

## Built-in lists and per-run limits

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
- **After an upgrade.** A changed list repeats every permutation check once, on the first run
  that uses it.

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
deferred for each stage (names for permutations, requests for sensitive paths) under `Deferred to
the next run`, and as `deferred` in the `--json` `summary` event. Run the same command again to do
the rest.

## Console and JSON

A run writes two things, to two streams.

- **The log is on stderr.** One line each for the run header, each change of a stage's state
  (`running`, `done` with the number of checks and failures, `done-previously`, `failed` or
  `not-configured` with the reason), each `+` find (with a severity badge for a finding), each
  changed count and each warning. A line is `HH:MM:SS | LEVEL | message`, with the time in the local
  time zone (`TZ`) and the level one of `DEBUG`, `INFO`, `WARN` or `ERROR`. The header, finds,
  counts and the lines of stages that are `running`, `done`, `done-previously` or `not-configured`
  are `INFO`; a stage that `failed` is `ERROR`. Every warning is `WARN` and is shown without any
  flag: a truncated result, a spent quota, addresses skipped because their owner is unknown,
  technology detection being off, the stages left out for lack of authorisation, an interrupted
  run. The same warning is written once per run. A message is never wrapped to the terminal width, and a line is never redrawn.
- **The summary is on stdout,** and is all that stdout holds. It lists counts, the checks that
  failed (a check that failed is retried on the next run; `--debug` shows each failure), the work a
  per-run cap deferred, the high and medium findings, and the high-confidence candidates (see
  [Ranked candidates](#ranked-candidates)). A run that ends without a summary (interrupted, stopped
  by the netblock limit or ended by an error) writes nothing to stdout. The authorisation prompt and
  the `error:` line that ends a failed run are on stderr, with no time or level.

`recon example.com 2> run.log` therefore keeps the log in a file and prints the summary.

- **`--quiet` (`-q`)** writes only `WARN` and above to stderr. The summary is still printed.
- **`--debug`** also writes a `DEBUG` line for each check that failed
  (`<stage> check <key> failed: <message>`). A failed check is not a warning: the stage line and the
  summary count it, and it is retried on the next run.
- `--quiet` with `--debug` exits 2. Neither is a setting: there is no config key or `RECON_*`
  variable for them.

A finding's `+` line and the summary show its severity as a badge: the severity as recorded (`high`,
`medium`, `low`) in a fixed-width column.

**Colour.** A stream is coloured only when it is a terminal, `NO_COLOR` is unset or empty and `TERM`
is not `dumb`. `FORCE_COLOR` and `CLICOLOR_FORCE` do nothing. stdout and stderr are decided
separately. When coloured, the timestamp and separators are grey, the level is a badge, the severity
is a badge, the summary's headings are bold and the `error:` prefix is red. Nothing else is
coloured. Colours are 24-bit when `COLORTERM` is `truecolor` or `24bit`, 256-colour when `TERM`
contains `256color`, and 16-colour otherwise; those variables choose the depth and never turn colour
on. The palette is in `docs/log-colors.md`.

`--json` prints one JSON event per line on stdout, with no styling or prompts. Warnings are events
of type `warning` with no flag, and `--quiet` changes nothing. A failed check is not an event.
stderr is empty unless `--debug` is given, which writes only the `DEBUG` lines there (coloured by
the rule above) and leaves stdout unchanged. A `candidate` event for each high-confidence candidate
comes before the `summary` event. It has `kind` (`root`, `hostname` or `netblock`), `value`,
`sources`, `evidence_count`, `confidence` and `promote`. The `summary` event's `candidates` field
lists the same candidates.

## Ranked candidates

`candidates.csv` lists the roots, hostnames and netblocks that were found but are not in scope.
Each row says how well supported it is, so you can tell which are worth promoting to scope:

| Column | Meaning |
|---|---|
| `type` | `root`, `hostname` or `netblock` |
| `value` | The candidate |
| `sources` | The distinct stages or mechanisms that found it, joined with `;` (listed below) |
| `evidence_count` | The number of distinct pairs of a source and the item that linked the candidate: the address, root, name server, netblock, service or organisation the source was asked about |
| `confidence` | `low`, `medium` or `high` |

The `sources` values are the stages and mechanisms that can find a candidate. Each belongs to one
family: certificate transparency (`crtsh`, `certspotter`, `censys`, `ct-org`), web archive
(`wayback`, `commoncrawl`), passive DNS (`virustotal`, `securitytrails`, `shodan`, `shodan-dns`,
`chaos`, `urlscan`, `hackertarget`, and `otx` and `anubis`, which no longer run but whose stored
results still count) and registrant (`whoisxml`, `org-asn`). `httpprobe`, `rdns` and `crawl` are each a family of their own, and so is any other
source. The names `rdap` (registrant), `reverseip` (reverse IP), `nsreverse` (shared
infrastructure) and `identifier-pivot` (web identifier) are reserved for stages that are not built
yet.

The confidence follows from the families that agree:

- **high**: a registrant match of an `--org` input is joined by any other family, or three or more
  families agree.
- **medium**: two families agree, or a shared self-hosted name server or mail host, or reverse IP on
  two or more addresses, or a registrant match alone.
- **low**: anything else.

A registrant match is evidence from a registrant-family source that was asked about one of the
`--org` inputs. (`org-asn` keeps an autonomous system only if its holder's name contains every word
of the organisation, ignoring legal suffixes such as `Pty` and `Ltd`; `whoisxml` takes the
organisations its reverse WHOIS search returns as they come.) Without an `--org` input no candidate has one, so
a registrant source counts as one family like any other. A candidate root also counts the evidence of
the candidate hostnames under it, so a root found by reverse WHOIS and a hostname under it found by
a redirect support each other. A hostname keeps its own rank.

Confidence is worked out again on every run from the checks that currently support the candidate.
After `--redo` of a stage whose results no longer support a candidate, it drops. Rows are sorted by
confidence (high first), then by evidence count (most first), then by value. A row that is not
current sorts last and shows the confidence it last had.

The summary lists up to 20 `high` candidates with the input that promotes each (a root or hostname
as a positional domain, a netblock as `--cidr`), then `and N more in candidates.csv`, which counts
the high candidates beyond the 20 listed. The medium and low ones are in `candidates.csv` only.

## Output files

Everything is in `<output-dir>/<engagement>/`:

| File | Contents |
|---|---|
| `scope.csv` | Inputs and the netblocks and roots in scope, and where each came from |
| `candidates.csv` | Related domains, hostnames and netblocks found but not in scope, ranked by how many independent sources support each (see [Ranked candidates](#ranked-candidates)); pass one as an input to promote it |
| `excluded.csv` | Excluded items and the reason |
| `subdomains.txt` | In-scope hostnames |
| `resolutions.csv` | DNS records for in-scope names (A, AAAA and CNAME, and the NS, SOA, TXT and CAA records of each root, see below), with a `source` column: `resolve` (recon's own lookup), `shodan` (reported by Shodan only) or `resolve;shodan`. Records only Shodan reports decide nothing: they never make a name resolved or an address contacted, port-checked or probed. |
| `unresolved.txt` | In-scope names that did not resolve |
| `wildcard-excluded.txt` | Names dropped because their domain answers every name (wildcard DNS) |
| `ips.csv` | Addresses with ASN, owner, hosting provider, service (or, where the provider publishes no service, region), scope, port eligibility and hostnames. A published range names the provider even when the owner lookup failed, and takes precedence over the ASN. Cloudflare and Fastly addresses are shared infrastructure and are not port-checked. DigitalOcean addresses and Linode addresses are customers' own machines, so an in-scope hostname that resolves to one is port-checked: DigitalOcean addresses were skipped as shared hosting before its list was fetched, so the next active run may handshake addresses it previously skipped. An address two providers' lists cover shows both, joined with `;`, and is shared if either is. |
| `provider-hosts.csv` | Names that point at shared cloud or SaaS providers, with the evidence |
| `web-services.csv` | Web services found: status, title, server, technologies, redirects, TLS details (see [TLS detail](#tls-detail)) and web posture evidence (see Web posture above) |
| `urls.csv` | URLs from crawling and web archives, with status and source |
| `open-ports.csv` | Open TCP ports with the banner the service sent, if any |
| `email-posture.csv` | SPF, DMARC and MX results per root domain |
| `third-parties.csv` | Organisations a root depends on, with the `root`, the `mechanism` (`ns` or `txt-verification`), the `domain` (a name server's registrable domain), the `provider` (when known) and the `depth` (0 for the root's own records) |
| `storage-unattributed.csv` | Guessed cloud-storage buckets that nothing in scope references |
| `risk-takeover.csv` | Subdomain takeover findings |
| `risk-storage.csv` | Cloud-storage findings: buckets that exist, are public or are listable |
| `risk-sensitive-paths.csv` | Sensitive paths that answered with their expected signature |
| `risk-email.csv` | SPF and DMARC weaknesses |
| `risk-ports.csv` | Open ports on the risky-port list |
| `risk-certificates.csv` | Expired, soon-to-expire and self-signed certificates, certificates that do not name the host, and services that negotiate only TLS 1.0 or 1.1 (see [TLS detail](#tls-detail)) |
| `risk-web-posture.csv` | Low findings from web responses: missing HSTS, cookies without `Secure`, directory listings and disclosed versions |

A file is only written when it has rows, so a missing `risk-*.csv` means no findings of that kind
(a file that later has no rows is removed). Files are sorted, except `candidates.csv`, which is
sorted by confidence. Every CSV ends with `current`, `first_seen` and `last_seen` columns, and records
that were not found by a later run are kept and marked not current. The `.recon/` directory holds
the state database and the run lock. Don't edit it. Finding severities are listed by
`recon --help`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed, including with failed checks or `not-configured` stages |
| 1 | Fatal runtime error, an engagement already locked by another run, or an output directory that is not a recon engagement |
| 2 | Invalid input or configuration. Nothing was contacted |
| 3 | The netblock limit was exceeded without `--allow-large-netblocks` |
| 130 | Interrupted (SIGINT, SIGTERM or SIGHUP). Completed work is saved; re-run to continue |

## Migrating from the Python version

- **Old output directories** are not resumable. recon refuses them (exit 1, naming the directory)
  and never writes into them. Use a different `-e` name, or move the old directory away.
- **Retired:** the `reconsite` single-site command and XSS and SQL injection testing are gone.
- **No external tools:** Amass, subfinder, massdns, httprobe, hakrawler, dalfox and the rest are
  no longer needed, and neither is `install.py`.
