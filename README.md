# nyx recon

This is a reconnaissance tool for gaining a rapid understanding of a new attack surface, such as a
newly acquired company. It is inspired by a variety of bug bounty methodologies, which start with
subdomain enumeration, go on to port and service enumeration, url discovery, etc. The end result is
a set of asset lists that help prioritise what to look at.

It can be kicked off by giving it domains, organisations, ASNs or netblocks. It records the hosts,
IPs, web services, URLs and open ports it can find, plus a severity-ranked list of obvious exposures
(dangling CNAMEs, public cloud storage, weak email policy, risky open ports, sensitive paths,
expiring certificates). It is a single Go binary for macOS and Linux, with no external tools to
install.

## Install

```sh
go install github.com/rafaelh/nyx/cmd/nyx@latest
```

Go 1.21 or later is enough when `GOTOOLCHAIN=auto`, the upstream default: it fetches the toolchain
named in `go.mod`. Some Linux distributions' Go packages set `GOTOOLCHAIN=local`; check with
`go env GOTOOLCHAIN`, and if it says `local`, run `GOTOOLCHAIN=auto go install ...` instead. Set
`CGO_ENABLED=0` for a fully static Linux binary.

From a clone:

```sh
make build   # ./nyx for this machine
make dist    # dist/nyx-{darwin,linux}-{amd64,arm64}
make test    # vet, race tests, and a cross-target vet for all four platforms
```

`nyx --version` prints the build's version (`devel` when there is none). Windows is not supported.

## Quick start

`output_dir` defaults to `.`, so run from a working directory outside this repository, or pass
`--output-dir`.

```sh
nyx example.com                  # all stages; asks you to confirm authorisation on a terminal
nyx example.com --passive        # third-party sources only; nothing at the target is contacted
nyx example.com --authorised     # confirm authorisation up front (needed with --json or no terminal)
nyx -e example-com               # re-run or resume an existing engagement by name
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
- **`--redo <stage>`:** performs every check of one stage again. `nyx help stages` lists the stages
  in run order, with whom each contacts, the key it needs and what it does.
- **`--skip <stage>`:** turns a stage off (repeatable; the `skip` setting, or `NYX_SKIP` as a
  comma-separated list, does the same). A skipped stage is shown as `not-configured (skipped)`,
  whatever else would stop it, and does nothing: results it found earlier stay in the files. The flag
  replaces the setting for that run, and `--skip none` runs every stage. An unknown stage, a stage
  also given to `--redo`, and `resolve`, `wildcard`, `ipowner` and `providerranges` (other stages'
  safety depends on them) exit with code 2. When every stage that contacts the target is skipped,
  there is no authorisation prompt.

## Configuration

- **Config file:** `$XDG_CONFIG_HOME/nyx/config.yaml`, which defaults to
  `~/.config/nyx/config.yaml`. Use `--config <file>` to choose another. Unknown keys are
  rejected.
- **Precedence:** flags override `NYX_*` environment variables, which override the file. An
  environment variable is `NYX_<UPPER_SNAKE>` with `.` replaced by `_`, for example
  `NYX_RATE_PER_HOST` and `NYX_CRAWL_MAX_DEPTH`.
- **API keys:** set only as `keys.<source>` in the file or `NYX_KEYS_<SOURCE>` in the
  environment. There are no key flags, so keys never appear in shell history or process lists.
  Keys are redacted from all output and files.
- **Keyed sources:** `securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys`, `chaos` and
  `github`. A stage whose key is missing is shown as `not-configured`. `keys.shodan` also turns on
  `shodan-dns`, which lists each in-scope root's subdomains and their A, AAAA, CNAME, MX and NS records; it costs
  one Shodan query credit per result page, for each root. `keys.censys` is a Censys personal access
  token and searches certificates for names under each root. `keys.chaos` is a ProjectDiscovery
  Chaos key. A 401, 403 or 429 stops that stage for the run (`shodan-host` too). Each of these three follows result pages
  up to `shodan_dns.max_pages`, `censys.max_pages` or `chaos.max_pages` (default 10; raising one
  repeats the stage's checks, and reaching one is a warning). Chaos answers with the
  whole list in one page, so its cap is not reached. `certspotter` takes an
  optional key: it runs without one, and sends `keys.certspotter` when it is set. `keys.github` is a
  GitHub personal access token for the `github` stage (see [GitHub code search](#github-code-search)),
  which reads up to `github.max_results` results per root (`--github-max-results`, default 500, from
  1 to 1000; changing it repeats the stage's checks). A 401, or a 403 or 429 whose rate limit does not
  lift within 60 seconds, stops that stage for the run. The other sources need no key.
- **Reverse IP.** `keys.securitytrails` also adds SecurityTrails to the `reverseip` stage (see
  [Reverse IP](#reverse-ip)). A rejected key (401 or 403) stops the whole stage, its HackerTarget
  lookups included, until the key is fixed or removed; a 429 stops it for the run. `reverseip.max_domains`
  (`--reverseip-max-domains`, default 100, at least 1) is how many registrable domains one address may
  return before it is treated as shared hosting.
- **Shodan per address.** `keys.shodan` also turns on `shodan-host` (see
  [Shodan per address](#shodan-per-address)). `shodan.max_hosts` (`--shodan-max-hosts`, default 500,
  at least 1) caps the addresses it looks up in one run.
- **JavaScript endpoints.** `jsparse.max_scripts` (`--jsparse-max-scripts`, default 50, at least 1)
  caps the script files `jsparse` reads per origin (see [JavaScript endpoints](#javascript-endpoints)).
- **Web identifiers.** `keys.shodan` also turns on `identifier-pivot` (see
  [Web identifiers](#web-identifiers)). `identifier_pivot.max_queries` (`--identifier-pivot-max-queries`,
  default 50, at least 1) caps the Shodan searches it sends in one run.
- **Settings:** all settings and their defaults are listed by `nyx --help`.

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
NYX_KEYS_SHODAN=your-shodan-key nyx example.com
```

## Passive boundary

nyx limits what target-owned systems can receive. It sends only:

- **DNS lookups.** Zone transfers are never attempted.
- **TCP handshakes** to the configured port list. It reads only what the service sends
  unprompted and sends nothing.
- **HTTP(S) GET and HEAD requests** to in-scope, non-excluded hosts, to same-host links found
  while crawling, to each service's `/robots.txt` and `/sitemap.xml` and the same-host URLs they
  list (robots.txt is read, not obeyed), to the paths on the sensitive-path list, to same-site
  script files referenced by crawled pages (the URLs found inside a script are recorded, never
  requested; see [JavaScript endpoints](#javascript-endpoints)), and to one favicon per web
  service: the same-host `<link rel="icon">` URL of its page, or `/favicon.ico` (see
  [Web identifiers](#web-identifiers)).

It never sends credentials, submits forms, uses other HTTP methods, puts payloads in parameters or
headers, or requests paths beyond those listed. UDP is not used. Candidate hosts (found but not in
scope) and excluded hosts are never contacted. Everything else comes from third parties: CT logs
(crt.sh and Cert Spotter), web archives, passive DNS and search (HackerTarget and urlscan.io),
GitHub's code search, public DNS resolvers, RDAP/WHOIS, BGP data, keyed APIs and cloud-storage
provider endpoints. Only hostnames are recorded from Cert Spotter, HackerTarget and urlscan.io. When one of these three
reports that its free quota is spent, its stage alone stops, and its checks are retried on the next
run. HackerTarget (and SecurityTrails, with its key) also receives the engagement's dedicated
addresses, for its reverse IP lookup (see [Reverse IP](#reverse-ip)); the target never does. The
`otx` and `anubis` stages no longer exist, because neither service answers an unkeyed client any
more. An engagement that already holds their results keeps them, and a `skip` setting
that names either is rejected as an unknown stage.

The `rdap` stage contacts only IANA (`data.iana.org`, for the bootstrap file) and the five regional
registries' RDAP servers; see [RDAP](#rdap-netblocks-and-registrants).

The `providerranges` stage fetches the address ranges that seven providers publish: AWS, GCP,
Cloudflare (IPv4 and IPv6), Fastly, DigitalOcean, Oracle Cloud and Linode. Each list is its own
check, fetched once per engagement and refreshed only by `--redo providerranges`. A list that fails
to download, or has no ranges in it, is a failed check (named by `--debug`): the ranges fetched
before keep applying. Azure is classified by ASN only, because Microsoft publishes its ranges at a
changing URL.

Shodan is queried per dedicated in-scope address, up to `shodan.max_hosts` a run, and each lookup
is a request to Shodan, never to the address. Shodan's host lookup is rate-limited rather than
credited, as far as its documentation says: it lists query credits only for filtered searches and for
result pages after the first, and does not list the host lookup among them. That was not confirmed
against Shodan's current terms when this was written, so check your plan before a large run. The
netblock search pages past the first still cost query credits as before. What Shodan reports is
shown, never acted on: a port only Shodan names is never connected to, and widens nothing.

All network access goes through one package. On every supported platform, a test fails if any other
package imports a network package or `syscall`, or uses `golang.org/x/sys/unix` for anything other
than signals and file locking, and if any package imports `os/exec`.

## Passive-only mode

`--passive` restricts a run to third-party sources. The stages that contact target-owned systems
(`httpprobe`, `crawl`, `jsparse`, `sensitive-paths`, `ports` and `takeover`'s HTTP fingerprinting) are
shown as `not-configured (passive-only)`. Takeover findings that DNS evidence alone supports are
still reported. The restriction applies to that run only; a later run without `--passive` performs
the skipped checks.

## Authorisation acknowledgement

Before any stage that contacts target-owned systems, nyx requires you to confirm you are
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
nyx stops before contacting any address in them, shows the total and exits with code 3. Re-run
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

### Service records and well-known hostnames

The `dnsroot` stage also asks each in-scope root for these SRV names, as one more check per root
(a SERVFAIL or timeout on any of them fails that check, which is retried on the next run):
`_sip._tls`, `_sip._tcp`, `_sipfederationtls._tcp`, `_autodiscover._tcp`, `_ldap._tcp`,
`_kerberos._tcp`, `_xmpp-server._tcp`, `_xmpp-client._tcp`, `_caldav._tcp`, `_carddav._tcp`,
`_imaps._tcp`, `_submission._tcp`, `_matrix._tcp` and `_minecraft._tcp`. An engagement that already
holds the four record types runs only this check.

- Each answer is a row in `resolutions.csv` with type `SRV`, the service name (such as
  `_sip._tls.example.com`) as the name and `priority weight port target` as the value. A service name is
  not a hostname: it is never resolved or tested for wildcard DNS. A target of `.` (a service that is
  not offered) records nothing.
- A target inside the scope is a hostname, resolved, probed and port-checked like any other. Any
  other target is a `third-parties.csv` row with mechanism `srv` and the target's registrable
  domain, and is never a candidate or contacted.
- The ports the answers advertise are reported, not connected to: the `srv_ports` column of
  `ips.csv` lists, `;`-joined, the ports SRV records give for the address's in-scope hostnames. The
  `ports` stage still checks only the configured port list.
- An SRV target that a root added later brings into scope becomes a hostname only after
  `--redo dnsroot` (its third-party row hides itself at once).

The permutations stage also always tries a few well-known labels, such as `autodiscover`, directly
under each root, even when the wordlist lacks them (see the well-known labels in
[Built-in lists and per-run limits](#built-in-lists-and-per-run-limits)).

The `+` line for a new third party reads `third-party <platform> via <mechanism> on <root>` (the
platform is the provider, else the domain),
and its `--json` `found` event carries `platform`, `mechanism` and `root`. The prefix list and the
name-server provider names are in the embedded `providers.yaml`.

### Mail and SaaS dependencies

The `email` stage (it runs under `--passive`, and only asks DNS) adds third parties to the same file
from the records it already reads for each in-scope root:

- `spf`: every domain the SPF walk follows (`include:` and a `redirect=` that the record's own `all`
  does not make unreachable) and every domain named by `a:`, `mx:` or `exists:` at any level, with the
  `depth` it was named at. Arguments with macros are skipped, and an include that has no SPF record is
  still listed. A SERVFAIL on any include fails the root's email check, which is retried on the next
  run, so that run records no third parties for the root.
- `dmarc`: the mailbox domain of each `rua=` and `ruf=` address (the `!10m` size suffix is removed,
  and anything but a `mailto:` address is ignored). It belongs to the root whose policy it is, also
  when the policy came from the organisational domain.
- `mx`: the registrable domain of each MX host.
- `cname`: the name suffix (`github.io`, `myshopify.com`) of each SaaS platform that appears at any
  hop of an in-scope name's CNAME chain, listed for the most specific in-scope root above the name.
  Names that only a wildcard answers, and excluded names, are not listed. `provider-hosts.csv` is
  unchanged. These rows are derived from the resolutions, so
  `--redo resolve` is what retires one.

A domain that is, or is under, an in-scope root is not a third party, and neither is one sharing the
registrable domain of the root it was found on. That is decided when the file is written, so a root
added later hides the row. A root has one row per mechanism and domain, and third-party domains are
never candidates. `--redo email` retires a row the root no longer references.

The `provider` column is filled when the domain is on the built-in list of mail and SaaS providers
(and name-server operators) in `providers.yaml`; the domain itself is never replaced. The mail and
SaaS providers are Google, Microsoft 365, Microsoft, Amazon SES, Mailgun, SendGrid, Mailchimp,
SparkPost, Postmark, Proofpoint, Mimecast, Barracuda, Zoho, Proton, Fastmail, GoDaddy, Apple,
Salesforce, HubSpot, Marketo, GitHub, Shopify, Zendesk, ReadMe, Squarespace, Wix, Atlassian, Unbounce
and Ghost.

For a root with at least one MX host that is not a null MX, the `email` stage also asks for the TXT
records at `_mta-sts.<root>` (the root's own name, with no fallback to the organisational domain).
A timeout or SERVFAIL fails the check, as for SPF and DMARC. The policy file over HTTPS is never
fetched. A missing record (or more than one) is the low finding `mta-sts-missing` in `risk-email.csv`. The lookup is part
of the email check, so an engagement from an earlier version runs its email checks once more.

## Web posture

From the responses `httpprobe` already receives, with no further request, nyx records a few
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

## JavaScript endpoints

The `crawl` stage notes every `<script src>` on the pages it fetches, whatever host the script is
on. The `jsparse` stage (it contacts the target, so it is skipped under `--passive` and until you
confirm authorisation) then reads each of those scripts that is on an in-scope host, with one GET
each, and records what the script names:

- **URLs.** Absolute `http(s)` URLs and `//host/path` references whose host is under an in-scope
  root, and quoted paths that start with `/` (at least two characters, with no whitespace, backslash
  or template placeholder such as `${` or `{{`, and a first segment that is not just an extension),
  joined to the script's origin. An absolute URL written with escaped slashes (`https:\/\/…`, as
  JSON has it) is found too, and one with a template placeholder after its host is cut at the
  placeholder, as `"https://api.example.com/v1/" + id` would be. They go in `urls.csv` with
  `jsparse` in `found_by` and no status.
  A script names at most 500; the rest are dropped with a warning.
- **Hostnames.** Hostnames under an in-scope root are recorded as hostnames. Hosts outside scope are
  ignored, as the crawl does.

Nothing found in a script is ever requested: the crawl follows only links from pages it fetched, and
the only script URLs the stage can request are those the crawl recorded. A script on a CDN or any
other host that is not in scope, on an excluded host, on a wildcard-only name or served by a SaaS
platform is not fetched. A redirect is followed only to the same host, and any answer other than
2xx, or one that is HTML (a `text/html` type, or a body that starts with `<`), records nothing. A
timeout is a failed check, retried on the next run.

`jsparse.max_scripts` caps the scripts fetched per origin, in URL order, with a warning that says how
many were left. A script already read keeps its place when new ones appear, so a re-crawl does not
read the same bundles again. Scripts are read up to 4 MiB (the usual limit on a response is 1 MiB,
but bundles are large); a longer script is read as far as 4 MiB, what is in that part is recorded
and a warning says it was cut. Only the script text is read: source maps and inline scripts are not,
and nothing is executed or searched for secrets.

When a re-crawl no longer references a script, the URLs found only in it are marked not current.
An engagement crawled by an earlier version has no script records until you run `--redo crawl`.
The check for a script is keyed by its URL and the parser, not by the scope, so a root you add later
is applied to the scripts already read only after `--redo jsparse`.

## Web identifiers

Some things on a page are shared by the sites of one organisation: a tracking ID, the favicon, the
copyright line. `httpprobe` and `crawl` record them for each web service, as the union over the
pages they fetched, and `web-services.csv` has them in four columns after the posture ones:

| Column | Contents |
|---|---|
| `analytics_ids` | Google Analytics and Tag Manager IDs (`UA-…`, `G-…`, `GTM-…`), `;`-joined. Each is read from `gtag/js?id=`, `gtag('config', …)`, or the Tag Manager loader, snippet or noscript frame; an ID that is only mentioned in the text of a page is not recorded. |
| `pixel_ids` | Facebook pixel IDs, from `fbq('init', '<digits>')` or `facebook.com/tr?id=`, `;`-joined |
| `favicon_hash` | The hash Shodan's `http.favicon.hash` filter uses (a signed 32-bit MurmurHash3 of the base64 of the icon file). |
| `copyright` | The first line of the root page's visible text with `©` or `(c)` followed, anywhere later on that line, by a year (`© 2026 Acme`, `© Acme Pty Ltd 2026`), cut to 120 characters |

The probe makes one extra GET for each service's icon: the same-host `<link rel="icon">` URL of the
last page on the service's host, or `/favicon.ico` when the page has none, or its link is on
another host. A redirect is followed once, and only to the same host. A 404, a web page, or
anything that is not an image gives no hash; so does an icon that is an SVG or other text. An
empty file has the hash `0`. The CSV writer puts a `'` in front of any cell that starts with `-`,
so a negative hash is written `'-1165240594`: the quote is not part of the hash.

An engagement probed by an earlier version has none of these until you run `--redo httpprobe` and
`--redo crawl` (the probe reads the root page and the icon, the crawl the other pages). A plain
re-run sends nothing. Under `--passive` no identifier is collected, as the probe and the crawl do
not run.

### Pivoting on them

With `keys.shodan`, the `identifier-pivot` stage (it runs under `--passive`, over the identifiers
earlier runs recorded, and is `not-configured (no key)` without the key) searches Shodan once for
each distinct analytics ID, pixel ID or favicon hash on an in-scope web service: `http.html:"<id>"`
or `http.favicon.hash:<hash>`. It reads the first page of results only.

- **What it records.** A hostname on a returned host is a hostname if it is under an in-scope root.
  Otherwise its registrable domain is a candidate root, with `identifier-pivot:<id>` in `sources`
  (every `identifier-pivot:<id>` source is in the web identifier family, so any number of identifiers is one family, and a candidate
  that only identifiers found is `low`). A returned address is recorded in `ips.csv`, classified by
  the usual scope rules, and never contacted unless it is in scope.
- **What it skips.** A service that a SaaS platform serves (its tracker is the platform's), a copyright
  line (never searched), and the favicon hashes of defaults that every installation shares: the
  empty file (`0`), Spring Boot (`116323821`), Jenkins (`81586312`) and Apache Tomcat
  (`-297069493`). A search that returns more than 200 hosts records nothing and prints a warning.
- **Cap.** At most `identifier_pivot.max_queries` searches (default 50) are sent per run, in the
  order of their check keys (`favicon|…`, then `html|…`). The rest wait for later runs, which is not a
  failure; the number deferred is under `Deferred to the next run` (the unit of that number is
  searches). A search that fails still counts.
- **Keys and credits.** A key without search access (a 401 or 403) fails the stage with one
  warning, and so does a 429. No query credits (a 402) stop the stage for the run; the search that
  was refused and the ones not yet sent run next time.
- **Refresh.** A search is made once per identifier; `--redo identifier-pivot` repeats it. The check is
  keyed by the identifier and not by the scope, so a hostname under a root you promote later was
  recorded only as a candidate root, and becomes a hostname after `--redo identifier-pivot`.

## TLS detail

`httpprobe` records the TLS version, cipher and trust of each HTTPS service from the one handshake
it already makes, with no further connection. `web-services.csv` has them in three columns, which
take the place of the old `tls_error` and `tls_self_signed`:

- `tls_version`: the version the handshake negotiated (`TLS 1.2`).
- `tls_cipher`: the IANA name of the suite it chose (`TLS_AES_128_GCM_SHA256`).
- `tls_trust`: the first that applies of `expired` (including not yet valid), `hostname-mismatch`
  (the certificate does not name the host that was probed), `self-signed`, `untrusted-chain` or
  `trusted`. `untrusted-chain` depends on the root store of the machine running nyx: a private or
  newly added root reads as `untrusted-chain` on a machine that does not hold it. The values come
  from the service's own first response, not from where it redirects, and are as of the probe.

To reach a service that has not moved on, every request nyx sends to an in-scope service accepts
TLS 1.0 and 1.1, and offers CBC-mode and RSA key-exchange cipher suites as well as the modern ones.
RC4 and 3DES are never offered, and SSL 3.0 is not supported, so a service that offers only those
fails the handshake and is not recorded, as before. Requests to third-party sources keep the
default minimum of TLS 1.2. A service that supports TLS 1.2 or later is recorded with the version it
negotiates, as before.

nyx sees only the version the service negotiates, so a service that offers an old version
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
deferred for each stage (names for permutations, requests for sensitive paths, addresses for `shodan-host`, searches for `identifier-pivot`) under `Deferred to
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

`nyx example.com 2> run.log` therefore keeps the log in a file and prints the summary.

- **`--quiet` (`-q`)** writes only `WARN` and above to stderr. The summary is still printed.
- **`--debug`** also writes a `DEBUG` line for each check that failed
  (`<stage> check <key> failed: <message>`). A failed check is not a warning: the stage line and the
  summary count it, and it is retried on the next run.
- `--quiet` with `--debug` exits 2. Neither is a setting: there is no config key or `NYX_*`
  variable for them.

A finding's `+` line and the summary show its severity as a badge: the severity as recorded (`high`,
`medium`, `low`) in a fixed-width column.


`--json` prints one JSON event per line on stdout, with no styling or prompts. Warnings are events
of type `warning` with no flag, and `--quiet` changes nothing. A failed check is not an event.
stderr is empty unless `--debug` is given, which writes only the `DEBUG` lines there (coloured by
the rule above) and leaves stdout unchanged. A `candidate` event for each high-confidence candidate
comes before the `summary` event. It has `kind` (`root`, `hostname` or `netblock`), `value`,
`sources`, `evidence_count`, `confidence` and `promote`. The `summary` event's `candidates` field
lists the same candidates.

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
  `summary` event carries it as `unconfirmed_risky_ports`, with the stages' lines as `notes`.

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
  during the wait exits 130 promptly, with the roots already searched kept. A reset further away, a
  sixth refusal of the same page, a 401, and any other 403 or 429 stop the stage for the run, with
  the roots not yet searched retried on the next. Reading stops after GitHub's tenth page of 100
  results, the last it serves.
- **Refresh.** A root's search completes once. New mentions appear only after `--redo github`, or when
  `github.max_results` changes, which searches again. A root added to scope later is searched in the
  next run. The check is keyed by the root and the cap, not by the scope, so a hostname under a root
  you add later was ignored and is recorded only after `--redo github`. After a redo, a match that is
  gone is marked not current, and its row keeps only its URL (which names the repository and the path).
  A file that mentions two roots is one row, from the root searched last.

## Ranked candidates

`candidates.csv` lists the roots, hostnames, netblocks, autonomous systems and organisations that were found but are not in scope.
Each row says how well supported it is, so you can tell which are worth promoting to scope:

| Column | Meaning |
|---|---|
| `type` | `root`, `hostname`, `netblock`, `asn` or `organisation` |
| `value` | The candidate |
| `sources` | The distinct stages or mechanisms that found it, joined with `;` (listed below) |
| `evidence_count` | The number of distinct pairs of a source and the item that linked the candidate: the address, root, name server, netblock, service or organisation the source was asked about |
| `confidence` | `low`, `medium` or `high` |

The `sources` values are the stages and mechanisms that can find a candidate. Each belongs to one
family: certificate transparency (`crtsh`, `certspotter`, `censys`, `ct-org`), web archive
(`wayback`, `commoncrawl`), passive DNS (`virustotal`, `securitytrails`, `shodan`, `shodan-dns`, `shodan-host`,
`chaos`, `urlscan`, `hackertarget`, and `otx` and `anubis`, which no longer run but whose stored
results still count), registrant (`whoisxml`, `org-asn`, `rdap`) and reverse IP (`reverseip`).
`httpprobe`, `rdns` and `crawl` are each a family of their own, and so is any other source.
The web identifier family is `identifier-pivot`; the `sources` value is `identifier-pivot:<id>`, with
the identifier that found the candidate, so each is a source of its own but they are one family
(see [Web identifiers](#pivoting-on-them)). The name `nsreverse` (shared infrastructure) is reserved
for a stage that is not built yet.

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
as a positional domain, a netblock as `--cidr`, an autonomous system as `--asn`, an organisation as
`--org`), then `and N more in candidates.csv`, which counts
the high candidates beyond the 20 listed. The medium and low ones are in `candidates.csv` only.

## Output files

Everything is in `<output-dir>/<engagement>/`:

| File | Contents |
|---|---|
| `scope.csv` | Inputs and the netblocks and roots in scope, and where each came from |
| `candidates.csv` | Related domains, hostnames, netblocks, autonomous systems and organisations found but not in scope, ranked by how many independent sources support each (see [Ranked candidates](#ranked-candidates)); pass one as an input to promote it |
| `excluded.csv` | Excluded items and the reason |
| `subdomains.txt` | In-scope hostnames |
| `resolutions.csv` | DNS records for in-scope names (A, AAAA and CNAME, the NS, SOA, TXT and CAA records of each root, and the SRV records of the listed service names, see below), with a `source` column: `resolve` (nyx's own lookup), `shodan` (reported by Shodan only) or `resolve;shodan`. Records only Shodan reports decide nothing: they never make a name resolved or an address contacted, port-checked or probed. |
| `unresolved.txt` | In-scope names that did not resolve |
| `wildcard-excluded.txt` | Names dropped because their domain answers every name (wildcard DNS) |
| `ips.csv` | Addresses with ASN, owner, hosting provider, service (or, where the provider publishes no service, region), scope, port eligibility and hostnames, then the `registrant`, `registrant_netblock` and `registry` the `rdap` stage found, then `srv_ports`, the ports SRV records advertise for the address's in-scope hostnames (reported only; never connected to). A published range names the provider even when the owner lookup failed, and takes precedence over the ASN. Cloudflare and Fastly addresses are shared infrastructure and are not port-checked. DigitalOcean addresses and Linode addresses are customers' own machines, so an in-scope hostname that resolves to one is port-checked: DigitalOcean addresses were skipped as shared hosting before its list was fetched, so the next active run may handshake addresses it previously skipped. An address two providers' lists cover shows both, joined with `;`, and is shared if either is. |
| `provider-hosts.csv` | Names that point at shared cloud or SaaS providers, with the evidence |
| `web-services.csv` | Web services found: status, title, server, technologies, redirects, TLS details (see [TLS detail](#tls-detail)), web posture evidence (see Web posture above) and web identifiers (see [Web identifiers](#web-identifiers)) |
| `urls.csv` | URLs from crawling, the scripts of crawled pages (see [JavaScript endpoints](#javascript-endpoints)) and web archives, with status and source |
| `open-ports.csv` | TCP ports that nyx found open, and ports Shodan reports (see [Shodan per address](#shodan-per-address)), with the banner, the `source` (`nyx`, `shodan` or `nyx;shodan`), `confirmed` (`yes` when nyx completed a handshake) and `shodan_last_seen` (empty on a row only nyx saw) |
| `email-posture.csv` | SPF, DMARC and MX results per root domain, then `mta_sts`: `present` when exactly one TXT record at `_mta-sts.<root>` begins `v=STSv1`, `absent` otherwise, and empty for a root without a mail host |
| `third-parties.csv` | Organisations a root depends on, with the `root`, the `mechanism` (`ns`, `txt-verification`, `spf`, `dmarc`, `mx`, `cname` or `srv`), the `domain` (as written for `spf` and `dmarc`, the registrable domain for `ns`, `mx` and `srv`, the platform's name suffix for `cname`), the `provider` (when known) and the `depth` (0 for a domain the root's own records name, 1 for one named by a record that one includes, and so on; always 0 for the other mechanisms, and 0 on a row that is no longer current, whose depth is not kept) |
| `code-mentions.csv` | Files in public GitHub repositories that mention an in-scope root, from the `github` stage: `repository`, `path`, `url`, the in-scope `hostnames` the match names (`;`-joined) and the `root` searched for. A match that is no longer current keeps only its `url` (see [GitHub code search](#github-code-search)) |
| `storage-unattributed.csv` | Guessed cloud-storage buckets that nothing in scope references |
| `risk-takeover.csv` | Subdomain takeover findings |
| `risk-storage.csv` | Cloud-storage findings: buckets that exist, are public or are listable |
| `risk-sensitive-paths.csv` | Sensitive paths that answered with their expected signature |
| `risk-email.csv` | SPF, DMARC and MTA-STS weaknesses (`mta-sts-missing`, low: a root with a mail host that does not publish exactly one MTA-STS policy record) |
| `risk-ports.csv` | Open ports on the risky-port list, with `confirmed` (`no` for a port only Shodan reports, which is one severity step lower) |
| `risk-certificates.csv` | Expired, soon-to-expire and self-signed certificates, certificates that do not name the host, and services that negotiate only TLS 1.0 or 1.1 (see [TLS detail](#tls-detail)) |
| `risk-web-posture.csv` | Low findings from web responses: missing HSTS, cookies without `Secure`, directory listings and disclosed versions |

A file is only written when it has rows, so a missing `risk-*.csv` means no findings of that kind
(a file that later has no rows is removed). Files are sorted, except `candidates.csv`, which is
sorted by confidence. Every CSV ends with `current`, `first_seen` and `last_seen` columns, and records
that were not found by a later run are kept and marked not current. The `.nyx/` directory holds
the state database and the run lock. Don't edit it. Finding severities are listed by
`nyx help findings`.

## Exporting an engagement

`nyx export -e <name>` writes everything recorded about an engagement to stdout as JSON lines, for
other tooling. The CSV columns are for people and may change; the export is the form to read from
a program. `--output-dir` and `--config` find the engagement as they do for a run.

```sh
nyx export -e acme > acme.jsonl
nyx export -e acme --current --kind hostname --kind web_service --output hosts.jsonl
```

- **Lines.** There is one line for each input (`kind` `input`, with `type` of `root`, `org`, `asn` or
  `cidr`, `value` and `added`) and each exclusion (`kind` `exclusion`, with `value` and `added`),
  then one line for each record of the engagement, current or not, in kind order and then key order.
  A record line has `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen` and `stages`, the
  stages that observe it now (none when it is not current), and then either `scope` or `shown`.
  `scope` is `in-scope`, `candidate` or `excluded`, for hostnames, roots, netblocks and excluded
  items. `shown` is `true` or `false` for every other kind, as the files and summary decide it:
  whether the record is shown for the engagement's scope. Both are worked out when you export,
  from the engagement's inputs and your current configuration, the same way a run does, so an
  exclusion added since a record was found is reflected.
- **Attributes.** `attrs` are the record's attributes merged from the stages that observe it, later
  stages in the registry winning a field, as in the CSV files. The store keeps attributes only
  from current observations, so a record that is not current has `attrs` of `{}`. `finding` and
  `candidate_rank` records are derived from the others: they are exported like any other record,
  but their `stages` name the pseudo-stage that derived them (`findings`, `candidate-rank`), which
  is not a stage you can `--redo`.
- **`--current`** keeps only current records. **`--kind`** (repeatable) keeps only the kinds
  named; `nyx export --help` lists them, including `input` and `exclusion`. The two combine. An
  unknown kind exits 2.
- **`--output <file>`** writes to the file instead, replacing it atomically: the lines go to a
  temporary file beside it, which is renamed into place, so a failed write leaves an existing
  file as it was. A write failure exits 1.
- **Left out.** The authorisation acknowledgement, the netblock approval and the settings are not
  exported, and an API key never is: any configured key value in the text is replaced with `****`.
  Text a target supplied (titles, banners) is sanitised as for console output.
- **Reading only.** `export` takes no lock, so it works while a run is in progress and shows the
  state as of one moment, writes nothing to the engagement and makes no network requests. It exits 1
  for an engagement that does not exist (creating nothing) or a directory that is not a nyx
  engagement.

**What stays stable.** The names of the stored attributes (they are what the state database keeps,
so renaming one would break resuming an engagement) and the export's own field names and kind
names. The attributes of a `finding` record are derived and may change, and so may anything in the
CSV files.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed, including with failed checks or `not-configured` stages |
| 1 | Fatal runtime error, an engagement already locked by another run, or an output directory that is not a nyx engagement. For `nyx export`, also an engagement that does not exist and a failure to write the export |
| 2 | Invalid input or configuration. Nothing was contacted |
| 3 | The netblock limit was exceeded without `--allow-large-netblocks` |
| 130 | Interrupted (SIGINT, SIGTERM or SIGHUP). Completed work is saved; re-run to continue |

## Migrating from the Python version

- **Old output directories** are not resumable. nyx refuses them (exit 1, naming the directory)
  and never writes into them. Use a different `-e` name, or move the old directory away.
- **Retired:** the `reconsite` single-site command and XSS and SQL injection testing are gone.
- **No external tools:** Amass, subfinder, massdns, httprobe, hakrawler, dalfox and the rest are
  no longer needed, and neither is `install.py`.
