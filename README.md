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
nyx recon example.com --passive        # third-party sources only; nothing at the target is contacted
nyx recon example.com --authorised     # all stages; confirms you are authorised to test the scope
nyx recon -e example-com               # re-run or resume an existing engagement by name
nyx recon example.com --passive --json --timeout 30m   # one JSON object on stdout; stop by the deadline
```

Results are written to `<output-dir>/<engagement>/`. The log goes to stderr and the summary to stdout
(see [Console and JSON](#console-and-json)). A run that a deadline or a failed check left partly done
exits 7; run the same command again to carry on (see [Deadline](#deadline) and
[Exit codes](#exit-codes)).

## Commands

- **`nyx recon [domain...] [flags]`** runs an engagement: everything below. **`nyx recon export`**
  writes what an engagement holds as JSON lines (see [Exporting an engagement](#exporting-an-engagement)).
- **`nyx cve <CVE-ID>... [flags]`** looks CVEs up in the NVD by CVE ID (see [CVE lookup](#cve-lookup)).
  It needs no engagement and no authorisation, and writes no files.
- **`--timeout <duration>`** is a recon flag: `nyx recon example.com --json --timeout 30m` stops by
  that deadline and exits 7, and a re-run carries on (see [Deadline](#deadline)). `export` makes no
  network calls and takes no `--timeout`.
- **Help.** `nyx --help`, `nyx help` and a bare `nyx` print the whole reference: examples, every
  command with its everyday flags and one example, the valid values of each fixed-set flag (the
  stages, the export kinds) and the exit codes. The recon example in `nyx --help` and in
  `nyx recon --help` passes `--json` and `--timeout`, and the root help lists `--timeout` among
  recon's everyday flags. `nyx help <command>` (or `nyx <command> --help`) is
  one command's full help; recon's tuning settings are listed only there. The root help also lists
  cve's flags and the field names `--fields` accepts. `nyx help stages` and
  `nyx help findings` are the two help topics. Help goes to stdout and exits 0.
- **Shared flags.** Every command takes `--json` (`-J`), `--quiet` (`-q`) and `--debug`, before or
  after its name (`nyx --json recon example.com` runs recon). `--json` implies `--quiet`, and
  `--quiet` with `--debug` exits 2. None of them is a setting. Any other flag goes after the
  command: one placed before it exits 2 with the same call, the command moved first, as the hint.
- **Flags are spelt in full.** An abbreviation (`--pass` for `--passive`) is an unknown flag;
  `--authorized` is the one alias.
- **No prompts, no stdin.** No command asks a question, and none loads a `.env` file: the
  environment is the one you gave it. Only `nyx cve`, given a lone `-`, reads stdin.
- **Version.** `nyx --version` prints the version; every HTTP request nyx makes carries
  `nyx/<version>` (`nyx/devel` for a build with no version) as its User-Agent.

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
  error, not a negative result) are retried on later runs, and a run in which any check failed exits 7
  (see [Exit codes](#exit-codes)). An interrupted run resumes the same way, and so does one that a
  deadline stopped (see [Deadline](#deadline)).
- **`--redo <stage>`:** performs every check of one stage again. `nyx help stages` lists the stages
  in run order, with whom each contacts, the key it needs and what it does.
- **`--skip <stage>`:** turns a stage off (repeatable; the `skip` setting, or `NYX_SKIP` as a
  comma-separated list, does the same). A skipped stage is shown as `not-configured (skipped)`,
  whatever else would stop it, and does nothing: results it found earlier stay in the files. The flag
  replaces the setting for that run, and `--skip none` runs every stage. An unknown stage, a stage
  also given to `--redo`, and `resolve`, `wildcard`, `ipowner` and `providerranges` (other stages'
  safety depends on them) exit with code 2.

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
- **The NVD key:** `nyx cve` reads its key from `NVD_API_KEY`, and otherwise from `keys.nvd` in the
  file. `NYX_KEYS_NVD` is not read (see [CVE lookup](#cve-lookup)). `keys.nvd` is a valid key for
  every command.
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
- **Shared name servers.** `keys.securitytrails` also turns on `nsreverse` (see
  [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)). A rejected key (401 or
  403) or a 429 stops it for the run. `nsreverse.max_domains` (`--nsreverse-max-domains`, default
  1000, at least 1) is how many domains one server may host before it is treated as shared hosting.
- **Origin exposure.** `keys.securitytrails` also turns on `dnshistory` (see
  [Origin exposure](#origin-exposure)). `dnshistory.max_hosts` (`--dnshistory-max-hosts`, default
  200, at least 1) caps the hostnames it asks about in one run, and `origincheck.max_candidates`
  (`--origincheck-max-candidates`, default 5, at least 1) caps the candidate origins kept, and
  checked, for each hostname.
- **Shodan per address.** `keys.shodan` also turns on `shodan-host` (see
  [Shodan per address](#shodan-per-address)). `shodan.max_hosts` (`--shodan-max-hosts`, default 500,
  at least 1) caps the addresses it looks up in one run.
- **JavaScript endpoints.** `jsparse.max_scripts` (`--jsparse-max-scripts`, default 50, at least 1)
  caps the script files `jsparse` reads per origin (see [JavaScript endpoints](#javascript-endpoints)).
- **Web identifiers.** `keys.shodan` also turns on `identifier-pivot` (see
  [Web identifiers](#web-identifiers)). `identifier_pivot.max_queries` (`--identifier-pivot-max-queries`,
  default 50, at least 1) caps the Shodan searches it sends in one run.
- **End-of-life software.** `eol_warn_days` (`--eol-warn-days`, default 90, at least 0) is how many
  days before the end of a release cycle's security support the low `eol-approaching` finding is
  reported; 0 turns it off (see [End-of-life software](#end-of-life-software)).
- **Settings:** all settings and their defaults are listed by `nyx recon --help`.

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
NYX_KEYS_SHODAN=your-shodan-key nyx recon example.com
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

- **One GET of `/` to an address it is already allowed to contact, with an in-scope hostname as
  the server name and the Host header.** The `origincheck` stage sends it to see whether a
  hostname behind a CDN or WAF is also served directly by its origin server (see
  [Origin exposure](#origin-exposure)). The address is one that may be port-checked: inside an
  in-scope netblock, or dedicated to the organisation, known, not excluded, and the current address
  of an in-scope hostname. It is asked in place of the CDN, so that the answer says what that address
  serves for the hostname; it is never an address nyx would not already handshake. One GET goes over
  HTTPS on 443 and, only if nothing answers there, one over HTTP on 80; a redirect is not followed.

It never sends credentials, submits forms, uses other HTTP methods, puts payloads in parameters or
headers, or requests paths beyond those listed. UDP is not used. Candidate hosts (found but not in
scope) and excluded hosts are never contacted. Everything else comes from third parties: CT logs
(crt.sh and Cert Spotter), web archives, passive DNS and search (HackerTarget and urlscan.io),
GitHub's code search, public DNS resolvers, RDAP/WHOIS, BGP data, keyed APIs and cloud-storage
provider endpoints. Only hostnames are recorded from Cert Spotter, HackerTarget and urlscan.io. When one of these three
reports that its free quota is spent, its stage alone stops, the checks it did not do are failed (the
run exits 7, see [Exit codes](#exit-codes)), and they are retried on the next run. HackerTarget (and SecurityTrails, with its key) also receives the engagement's dedicated
addresses, for its reverse IP lookup (see [Reverse IP](#reverse-ip)); SecurityTrails also receives
the hostnames behind a CDN or WAF, for their DNS history (see [Origin exposure](#origin-exposure)); the
target never does. The
`otx` and `anubis` stages no longer exist, because neither service answers an unkeyed client any
more. An engagement that already holds their results keeps them, and a `skip` setting
that names either is rejected as an unknown stage.

Common Crawl's index is often overloaded, and its gateway gives up on a slow query with a 502, 503
or 504. The `commoncrawl` stage sends such a request again, up to three times, after the wait a
`Retry-After` of at most 60 seconds asks for, or else after 1, 2 and then 4 seconds; an interrupt
during a wait ends the run promptly. A fourth such answer fails the root's check, which is retried
on the next run. Pages of the index are read in turn until it answers that a page is past the last,
up to 30 pages per root.

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
(`httpprobe`, `crawl`, `jsparse`, `sensitive-paths`, `origincheck`, `ports` and `takeover`'s HTTP fingerprinting) are
shown as `not-configured (passive-only)`. Takeover findings that DNS evidence alone supports are
still reported. The restriction applies to that run only; a later run without `--passive` performs
the skipped checks.

## Authorisation acknowledgement

Before any stage that contacts target-owned systems, nyx requires you to confirm you are
authorised to test the engagement's scope, with `--authorised` (`--authorized` also works). There
is no prompt, on a terminal or anywhere else.

- The confirmation is remembered per engagement, so later runs need not repeat it.
- Without it, those stages are shown as `not-configured (no authorisation)`, and the run writes one
  warning right after its header that names them and says that `--authorised` confirms
  authorisation. It names exactly the stages shown that way, so a stage left out by `--skip` is not
  named, and there is no warning under `--passive` or when no stage is left out. It appears on every
  run until authorisation is confirmed. Under `--json` it is in the envelope's `meta.warnings` and not
  on stderr.

## Large netblocks

If the in-scope IPv4 address count (ASN-expanded netblocks included) exceeds `netblock_limit`,
nyx stops before contacting any address in them, writes the output files and exits 2 with an
`INVALID_INPUT` error that gives the total. Its hint is your own call with
`--allow-large-netblocks` added (and any `--redo` left out), which proceeds. The approval is
remembered with the engagement.

## Deadline

`--timeout <duration>` gives a recon run a deadline: `--timeout 30m`, `--timeout 2h`, `--timeout
1m30s`. It is a flag only, with no default and no config key or `NYX_*` variable (`NYX_TIMEOUT` is
ignored and a `timeout:` key in the config file is an unknown key). A value that is not a positive
duration (`0`, `-5s`, `abc`, and `30` with no unit) exits 2. `nyx recon export` makes no network
calls and takes no `--timeout`. Without the flag a run takes as long as it needs.

- **The reserve.** nyx aims to exit by the deadline, so the work stops before it. The reserve is a
  tenth of the timeout, at least 2 seconds, at most 60 seconds and never more than half the timeout:
  checks get 27 seconds of a 30-second timeout, 9 minutes of 10, and 1 hour 59 minutes of 2 hours.
  When the reserve before the deadline is reached, recon stops starting checks and cancels the
  ones in flight. It then writes the output files and the summary or envelope, in time to exit by
  the deadline.
- **The late finish.** If writing takes longer than the reserve, recon finishes writing and exits
  after the deadline, with current files, rather than stopping part-way. A run that finishes its
  work before the deadline is unaffected and exits as it would without `--timeout`.
- **A cancelled check** is neither done nor failed. Nothing is recorded for it, no failure and no
  completion, so it runs on the next run, and the evidence earlier runs recorded stays current.
- **Exit 7.** A run the deadline ended prints its summary or envelope and exits 7 with a `PARTIAL`
  error. Its message says the deadline stopped the run, how many checks completed in this run, how
  many were cancelled and in which stages (`the deadline (--timeout 30m) stopped the run: 412
  checks completed, 6 cancelled (permutations 2, crawl 4)`), and then names the stages with failed
  checks, if any (`; failed checks: crtsh 2, shodan 14`). A check is completed when it ran and
  finished in this run, whether it succeeded or failed; a check a stage abandoned without running it
  is failed but not completed. The same counts are `meta.deadline_exceeded`, `meta.checks_completed`
  and `meta.checks_cancelled` in the envelope, and the human summary ends with `Stopped by the
  deadline: N checks completed, M cancelled`. The error has one of two hints:
  - **To carry on.** The hint is your own invocation, shell-quoted, with `--redo` and its value left
    out and every other argument kept, `--timeout` included. Run it to do the cancelled checks and
    the rest. The error is marked transient.
  - **To raise the deadline.** When no check succeeded in this run (the timeout was too small to
    start one, or every check started was cancelled or failed) the hint says to raise `--timeout`:
    `raise --timeout: no check succeeded within 30m`. Running the same command again would make no
    progress, so the error is not marked transient.
- **Long checks.** A single permutations check (one per root: about 4,900 lookups, at the default
  50 a second) or crawl check (one per service) can take minutes, and the deadline cancels a check
  that has not finished. A short `--timeout` may therefore never finish one: a run that stops at one
  makes no progress past it on the next. Give such a run a longer `--timeout` (or none).

## Root DNS records and third parties

For each in-scope input root the `dnsroot` stage asks the public resolvers for its NS, SOA, TXT
and CAA records, one check per type, so a type that keeps failing does not block the others. It runs
under `--passive`. Zone transfers are never attempted. Each answer is a row in `resolutions.csv`: a
CAA value is written `<flags> <tag> "<value>"`, and an SOA value is the primary name server and
the administrative mailbox as an email address (`john\.doe.example.com` is `john.doe@example.com`).

- A name server (or SOA primary) inside the scope is a hostname, resolved, probed and port-checked
  like any other. A name server outside it is a `third-parties.csv` row with mechanism `ns`, and is
  never a candidate or contacted. Its A and AAAA records are looked up, unless it is on a known
  provider's domain, only to say whether the organisation runs it itself (the `self_hosted` column
  of its NS row in `resolutions.csv`; see [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)).
  The server is not resolved, probed or port-checked because of that lookup, and a lookup that
  fails is skipped, not retried. An engagement from before this lookup repeats its NS check once.
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
and the row it announces is in `third-parties.csv` and in `nyx recon export`, with the `provider`,
`mechanism` and `root`. The prefix list and the name-server provider names are in the embedded
`providers.yaml`.

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

## End-of-life software

From versions nyx already captured, with no further request, it reports software whose release
cycle is past the end of security support, or about to be, in `risk-eol-software.csv`. The versions
come from two places only: the `Name:version` technologies Wappalyzer reads from each in-scope web
service (the `technologies` column of `web-services.csv`), and the banner of each open SSH, FTP or
SMTP port (the `banner` of `open-ports.csv`, nyx's own, or Shodan's for a port only Shodan reports).
Neither the `Server` and `X-Powered-By` text of `version_disclosure` nor any other source is read,
and no CVE is matched.

The dates are embedded in the binary, as [endoflife.date](https://endoflife.date) records them: the
end of security support of each release cycle (its `eol` date), for these products, which are the
ones it tracks that nyx can version (the names are Wappalyzer's, or the banner's for the last
three): Apache HTTP Server, Nginx, PHP, Apache Tomcat, Jetty, Spring, Ruby on Rails, Django,
Laravel, Symfony, Drupal, WordPress, Joomla, Magento, Node.js, Express, Python, Ruby, jQuery,
jQuery UI, Bootstrap, AngularJS, Angular, OpenSSL, MySQL, MariaDB, PostgreSQL, Elasticsearch,
Kibana, Grafana, GitLab, Nextcloud, MediaWiki, phpMyAdmin, Moodle, RoundCube, Zabbix, Vue.js,
React, Ember.js, Next.js, Jenkins, Atlassian Bitbucket, Artifactory (and Artifactory Web Server),
Discourse, Concrete CMS, Backdrop, Umbraco, Shopware, SonarQube, Gerrit, YouTrack, Apache APISIX,
Kong, Neos CMS, Perl, Lua, CouchDB, Subversion, Jekyll, Varnish (Vinyl Cache), Postfix,
Exim and ProFTPD. The data was taken on **2026-11-17**; a run more than twelve months after that
date prints one WARN line saying so (with no flag), and still uses the data. `make eol-data`
downloads it again (it needs `curl` and `jq`) for review and commit.

A version belongs to the release cycle named by its first one, two or three dotted numbers (as
the product names its cycles, so `7.4.3` is PHP 7.4 and `1.3.5e` is ProFTPD 1.3.5). A version that
matches no cycle, a cycle with no end announced, and a technology with no version give no finding.

- `eol` (medium): the cycle's end date is on or before the run date (UTC). A cycle endoflife.date
  lists as ended with no date (`jQuery` 1.x) is `eol` too, with an empty `end_date`.
- `eol-approaching` (low): the end date is after the run date and within `eol_warn_days`
  (`--eol-warn-days`, default 90, at least 0; 0 turns this type off and leaves `eol`).

A version carrying a distribution suffix (`Debian`, `Ubuntu`, `CentOS`, `+deb`, `~bpo` and the
like) is one step lower, because a distribution backports fixes under the upstream version: `eol`
becomes low, with `distribution build` in the `detail`. Wappalyzer reports a header's version
without the suffix, so for a web service the `Server` or `X-Powered-By` value that carries the
version is read for it (`Apache/2.4.41 (Ubuntu)`, `PHP/7.4.3-4ubuntu2.19`). A version known only from a Shodan port
report is one step lower too, with `confirmed` `no` (as for [Shodan per address](#shodan-per-address)),
and becomes the full severity once nyx's own banner names it. Each end-of-life product on a service
or port is its own row.

`risk-eol-software.csv` has `severity`, `target` (the service URL, or `ip:port`), `hostnames` (the
in-scope names behind the address, for a port), `type`, `product`, `version`, `end_date`, `seen`
(`web` or `banner`) and `confirmed`. Findings are derived on every run from the latest probe and
banner records and the run date, so one can appear with no new contact when the date passes an end
date, and under `--passive` they come from records kept by earlier runs. A finding goes not current
when `--redo httpprobe` or `--redo ports` no longer shows that version. Only in-scope web services
and port-eligible addresses are assessed, as for other findings.

`open-ports.csv` has `product` and `version` columns, read from the banner shown in its `banner`
column when it is one of OpenSSH, Dropbear, ProFTPD, vsftpd, Pure-FTPd, Postfix, Exim, Sendmail,
Microsoft IIS FTP or Microsoft Exchange (SMTP); any other banner leaves both empty, and a banner that
names no version leaves `version` empty. The columns are worked out when the file is written, so an
earlier engagement has them after its next run, with no new contact. OpenSSH, Dropbear, vsftpd,
Pure-FTPd, Sendmail, IIS FTP and Exchange are recognised but not assessed: endoflife.date does not
track the first five, and an Exchange banner's version is a build number that no cycle names.

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
deferred for each stage (names for permutations, requests for sensitive paths, addresses for `shodan-host`, searches for `identifier-pivot`, hostnames for `dnshistory`) under `Deferred to
the next run`, and as the envelope's `deferred` list under `--json`. A run that only deferred work
exits 0. Run the same command again to do the rest.

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
  technology detection being off, the stages left out for lack of authorisation. The same warning
  is written once per run. On a terminal a long message wraps (see [Terminal layout](#terminal-layout));
  anywhere else a message is never wrapped. A line is never redrawn.
- **The summary is on stdout,** and is all that stdout holds. It lists counts, the checks that
  failed (a check that failed is retried on the next run; `--debug` shows each failure), the work a
  per-run cap deferred, the high and medium findings, and the high-confidence candidates (see
  [Ranked candidates](#ranked-candidates)). When the deadline ended the run it ends with the line
  `Stopped by the deadline: N checks completed, M cancelled` (see [Deadline](#deadline)). A run
  that ends without a summary (interrupted, stopped by the netblock limit or ended by an error)
  writes nothing to stdout. A run that exits 7 has written its summary: the error that follows it
  is on stderr, with no time or level (see [Errors](#errors)).

`nyx recon example.com 2> run.log` therefore keeps the log in a file and prints the summary.

- **`--quiet` (`-q`)** writes only `WARN` and above to stderr. The summary is still printed.
- **`--debug`** also writes a `DEBUG` line for each check that failed
  (`<stage> check <key> failed: <message>`). A failed check is not a warning: the stage line and the
  summary count it, and it is retried on the next run.
- `--quiet` with `--debug` exits 2. Neither is a setting: there is no config key or `NYX_*`
  variable for them.

A finding's `+` line and the summary show its severity as a badge: the severity as recorded (`high`,
`medium`, `low`) in a fixed-width column.

### Terminal layout

When a stream is a terminal, nyx lays its human output out for reading: the recon summary, the log
lines, `nyx cve` records, help and `nyx recon --palette`. A stream that is not a terminal (a pipe, a
file) gets exactly the plain text described elsewhere in this document, so scripts and saved logs do
not change, and neither does anything under `--json`: with `--json`, help and the palette sheet are
written as for a stream that is not a terminal, and the envelope is the same. `--debug` lines on a
terminal stderr are log lines and are laid out like the rest. The `error:` line is never laid out.
`NO_COLOR` or `TERM=dumb` turns the colour off but not the layout: no escape byte is written, and
rules and borders are drawn with ASCII (`-`, `|`, `+`).

- **Margin.** A blank line comes before nyx's output and another after it, to set it apart from
  the shell prompts. When stdout and stderr are both terminals they share it: the first line goes
  to whichever is written first and the last to whichever is written last. A stream nyx writes
  nothing to stays empty. There is no margin under `--json`.
- **Width.** Each terminal stream has its own width: `COLUMNS` when it is a positive number, else
  the width of that terminal, else 100, and never less than 60. A log line reads the width each time
  it is written, so resizing the window applies from the next line. For `nyx cve` output that is not
  a terminal the old rule stays: `COLUMNS`, else 100, at least 60.
- **Wrapping.** No line is wider than the width, measured in terminal cells, with these exceptions:
  usage and example lines in help, which never wrap; a hostname, an IP address or netblock (a
  hostname or address may carry a `:port`), an email address or a URL with a scheme, which is never
  broken even if it is wider than the space; the SEVERITY, CATEGORY, EVIDENCE and PROMOTE cells of
  a table; and a table row whose wrapping columns have already shrunk to 10 cells. Such a line runs
  past the width rather than break. A log message that wraps continues under the message column
  (19 cells in, or 21 with colour).
- **Headings and rules.** Headings are bold in the info colour. Each heading of the summary has a
  rule beneath it, `─` in the separator colour, or `-` without colour.
- **Tables.** The summary shows its findings ("Findings" and "New findings": SEVERITY, CATEGORY,
  TARGET and DETAIL, with DETAIL left out when no row has one) and its candidates (VALUE, EVIDENCE,
  SOURCES and PROMOTE) as tables with a bold header row and no borders. The counts blocks keep their
  labels, with the numbers right-aligned. `nyx help findings` and `nyx help stages` are bordered
  tables. When a table is too wide, its long columns shrink and wrap: DETAIL then TARGET, or SOURCES
  then VALUE. A table with no rows is not shown, heading included.
- **Stage lines.** With colour, the state word is coloured: `running` in the info colour, `done` and
  `done-previously` in the success colour, `failed` in the error colour and `not-configured` in the
  muted timestamp colour. A found line's `+` is in the success colour, and in a line of the form
  `category: value` the category is in the info colour.
- **CVE records.** Each record starts with a bar as wide as the layout width, with the CVE ID at
  the left and the severity at the right, in the severity's badge colours. Without colour the bar is
  the ID and `[SEVERITY]` at either end of the line. Field labels have no colon and the values
  line up in one column in each section.
- **Help.** Descriptions, paragraphs and footers wrap to the width; lists of values wrap after
  commas.
- **`nyx recon --palette`** also shows a heading, a sample table, a CVE bar for each severity, a
  stage line for each state, a found line and a log line longer than the width, so a new terminal or
  theme can be checked by eye.

Rules and table borders use box-drawing characters, which Unicode classes as East Asian Ambiguous: a
terminal set to a CJK locale may draw them two cells wide, which pushes a rule or border past the
width. nyx measures them as one cell.

### The `--json` envelope

`--json` replaces the log and the summary with one JSON object, written to stdout when the run
ends: compact, on one line, with the two keys `data` and `meta`. There are no event lines. The
files and `nyx recon export` are the detailed record of what a run found; the envelope is its
outcome.

- **stdout** holds the envelope on exit 0 and on exit 7, and nothing on any other exit. A run
  that is interrupted, ended by an error or stopped by the netblock limit writes no envelope.
- **stderr** is empty on exit 0, apart from the `DEBUG` lines that `--debug` writes (coloured by
  the rule above), which leave stdout unchanged. On a non-zero exit it holds the one error (see
  [Errors](#errors)).
- **Warnings** are not written anywhere else: every warning the run raised is in `meta.warnings`,
  never on stderr. `--quiet` changes nothing.
- **Every key is on every run.** An empty list is `[]`, and a value that is absent is `null` (said
  below for each). Figures per stage or per category are lists of objects with fixed keys, never
  objects keyed by a stage or category name.
- **Redaction.** Text a target supplied is sanitised and any configured API key is replaced with
  `****`, in the warnings and the findings' `detail` as everywhere else.

`data` has these keys, in this order:

| Key | Type | Contents |
|---|---|---|
| `engagement` | string | The engagement's name |
| `directory` | string | Its directory, as an absolute path, even when `--output-dir` is relative |
| `counts` | list of `{category, n}` | The count of each category (`hosts`, `ips`, `web services` and so on), sorted by category, with `n` a number. The categories the log's count lines show |
| `failed_checks` | list of `{stage, n}` | The checks that failed in this run, per stage, sorted by stage name. `[]` when none did |
| `deferred` | list of `{stage, n}` | The work a per-run cap deferred, per stage, sorted by stage name; the unit of `n` is the stage's own (see [Built-in lists and per-run limits](#built-in-lists-and-per-run-limits)). `[]` when nothing was deferred |
| `not_configured` | list of `{stage, reason}` | Each stage that did not run, in registry order, and why: `skipped`, `passive-only`, `no authorisation`, or the stage's own reason such as `no key`. `[]` when every stage ran |
| `findings` | list of `{severity, category, target, detail}` | Every current high and medium finding, high first and then by target. `detail` is a string, or `null` when the finding has none |
| `candidates` | list of `{kind, value, sources, evidence_count, confidence, promote}` | The first 20 current high-confidence candidates, best first (see [Ranked candidates](#ranked-candidates)). `kind` is the kind of record the candidate is (`root` or `hostname`, for example), `sources` is a list of strings, `evidence_count` is a number and `promote` is the input that promotes it |
| `candidates_total` | number | How many current high-confidence candidates there are, whether or not `candidates` lists them |
| `unconfirmed_risky_ports` | number | How many risky ports only a third party reports (see [Shodan per address](#shodan-per-address)); 0 when none |
| `notes` | list of strings | The lines the stages add to the summary. `[]` when there are none |
| `changes` | object or `null` | What changed since the last run (see [What changed since the last run](#what-changed-since-the-last-run)): `null` on a first run, otherwise `{counts, findings}` |

`meta` has these keys, in this order:

| Key | Type | Contents |
|---|---|---|
| `count` | number | Always 1: the envelope holds one record, the run's outcome |
| `deadline_exceeded` | boolean | `true` when `--timeout` ended the run (see [Deadline](#deadline)) |
| `checks_completed` | number | The checks that ran and finished in this run, whether they succeeded or failed. Present with or without `--timeout` |
| `checks_cancelled` | number | The checks the deadline cancelled |
| `warnings` | list of strings | Every warning the run raised, in order. `[]` when there were none |

An example, wrapped here for reading (nyx writes it on one line):

```json
{"data":{
  "engagement":"example-com",
  "directory":"/home/me/engagements/example-com",
  "counts":[{"category":"findings","n":2},{"category":"hosts","n":212},{"category":"ips","n":96},{"category":"web services","n":41}],
  "failed_checks":[{"stage":"shodan","n":14}],
  "deferred":[{"stage":"permutations","n":3}],
  "not_configured":[{"stage":"censys","reason":"no key"},{"stage":"takeover","reason":"passive-only"}],
  "findings":[
    {"severity":"high","category":"takeover","target":"old.example.com","detail":null},
    {"severity":"medium","category":"certificates","target":"https://vpn.example.com","detail":"expired certificate (vpn.example.com), expires 2026-10-20"}],
  "candidates":[{"kind":"root","value":"example-corp.net","sources":["crtsh","whoisxml","wayback"],"evidence_count":5,"confidence":"high","promote":"example-corp.net"}],
  "candidates_total":1,
  "unconfirmed_risky_ports":0,
  "notes":[],
  "changes":{"counts":[{"kind":"finding","change":"new","n":1},{"kind":"hostname","change":"new","n":6}],
             "findings":[{"severity":"high","category":"takeover","target":"old.example.com","detail":null}]}},
 "meta":{"count":1,"deadline_exceeded":false,"checks_completed":412,"checks_cancelled":0,
         "warnings":["quota spent or key rejected; 14 checks will be retried next run"]}}
```

(That run exits 7: 14 checks failed.)

**What stays stable.** The keys of the envelope, in `data` and `meta`, and the types of their
values are an interface: a new key may be added, but renaming, removing or retyping one is a
breaking change. The same holds for the keys of the rows inside a list. The wording of warnings,
notes and `detail` text may change. A reader should ignore keys it does not know.

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

## Shared name servers and mail hosts

A name server or mail host that an organisation runs itself is a strong sign that the other domains
it serves belong to the same owner. The `nsreverse` stage finds them. It needs `keys.securitytrails`
and runs under `--passive`; without the key its state is `not-configured (no key)` and only the
markers below are produced.

A name server (an NS record of an in-scope root) or a mail host (an MX host of one) is
**self-hosted** when it is in scope, or when an address looked up for it is inside an in-scope
netblock, or is dedicated to the organisation: its owner is known, it is not shared provider
infrastructure, and an in-scope hostname resolves to it. A server on a known provider's domain
(Cloudflare, Route 53's own domains and so on), on a shared address, or on an address whose owner is
unknown is never a sign, and nothing is fetched for it. A server's address is looked up by `dnsroot`
(name servers) and `email` (mail hosts) through the public resolvers; the server itself is not
contacted. Route 53 name servers (`ns-123.awsdns-45.com`) match no domain entry, so they are ruled out
by their shared addresses instead.

- **Markers.** `resolutions.csv` has `self_hosted` on the NS rows of nyx's own lookup (`yes` or `no`;
  blank on every other row, on an NS row only Shodan reports, and on a row that is no longer
  current), and `email-posture.csv` has `mx_self_hosted`, the self-hosted MX hosts joined with `;`.
  Both are worked out when the files are written.
- **What is asked.** For each self-hosted name server SecurityTrails is asked for the domains hosted
  on it, and for each self-hosted mail host for the domains whose MX it is. Each domain's registrable
  domain is a candidate root in `candidates.csv`, with `shared-ns` or `shared-mx` in `sources`. A
  candidate found this way is at least `medium`; an excluded root stays excluded. Candidate roots are
  never resolved or contacted, and this lookup is the only way they are found.
- **Shared hosting.** A server that hosts more than `nsreverse.max_domains` domains (default 1000)
  records nothing, and a WARN line names it. The total is read from the first page, so such a server
  usually costs one query; the domains listed on later pages are counted against the cap too. The
  cap is part of the check, so changing it asks every server again.
- **Quota.** A rejected key (401 or 403) or a 429 stops the stage for the run, and the checks that
  remain are made on the next run.
- **Refresh.** Each server is asked once per engagement; new results arrive only with
  `--redo nsreverse`. The check is keyed by the server and the cap, not by the scope, so a name
  server that a root you promote later brings into scope is asked once it is self-hosted by either
  test, and a server whose addresses change is not asked again before `--redo nsreverse`. Name
  servers and mail hosts already on record have their addresses looked up the next time `dnsroot`
  and `email` run their checks, which an engagement from before repeats once.

## Origin exposure

A site behind a CDN or WAF is only as protected as its origin server is hidden. nyx looks for
origin servers that can be reached directly, in two stages.

The `dnshistory` stage runs under `--passive` and needs `keys.securitytrails`; without it the stage
is `not-configured (no key)`. For each in-scope hostname that currently resolves to a known CDN or
WAF (a CNAME on its chain, or an address, that belongs to CloudFront, Azure Front Door and CDN,
Cloudflare, Fastly, Akamai, Imperva or Sucuri, or an address of Vercel's or Yandex's network), it asks SecurityTrails for the hostname's
historical A and AAAA records. Each historical address is a row in `resolutions.csv` of type
`A-historical` or `AAAA-historical`, with the dates the source gave, and an address in `ips.csv`,
where its owner is looked up. A historical address is never treated as a current one: it is not
probed or port-checked, and takes no part in wildcard detection, because of that alone.

- **Cap.** At most `dnshistory.max_hosts` hostnames (default 200) are asked in a run, in name order.
  The rest are deferred, which is not a failure: the number under `Deferred to the next run` counts
  hostnames. Each hostname is asked once per engagement, and again only after `--redo dnshistory`.
- **Quota.** A 401, 403 or 429 from SecurityTrails stops the stage for the run, as it does for the
  other keyed sources. Each hostname is two requests, one per record type, and each further page
  of a long history is another, up to five pages per type.
- **Not verified against the live API.** The request and response shapes were taken from
  SecurityTrails' documentation and have not been tried with a real key.

A hostname's **candidate origins** are addresses whose owner is known and that are not shared
provider infrastructure, and that are either a historical address of the hostname or the current
address of a *sibling*: another in-scope, non-wildcard-only hostname that is not itself behind a
CDN or WAF, and whose certificate names the hostname or whose page title equals the hostname's
(neither empty nor one a CDN, WAF or default server page shows). Up to `origincheck.max_candidates`
(default 5) are kept for each hostname: historical addresses most recent first, then siblings. An
address in a CDN's published range, or whose origin AS is a CDN's, is the CDN's own and never a
candidate. Without a SecurityTrails key only siblings are candidates.

The `origincheck` stage contacts the target, so it is skipped under `--passive` and until you
confirm authorisation. It makes one check for each pair of a hostname and a candidate, but only if
the candidate may be contacted (it is inside an in-scope netblock, or is the current address of an
in-scope hostname with a known, dedicated owner, and is not excluded) and the probe has a 2xx
result for the hostname's HTTPS service. Every other candidate is reported as a possible origin and
is never contacted. The check is one `GET /` over HTTPS on port 443 with the hostname as both the TLS
server name and the Host header, and, only if nothing answers on 443 (not if it fails the TLS
handshake), one over HTTP on port 80. Redirects are not followed, and a 3xx confirms nothing. If
the title or certificate the probe saw changes, the pair is checked again.

The exposure is **confirmed** when the response's non-empty title equals the probe's title for the
hostname and is not a CDN, WAF or default-server title, or when the response has the same status as
the probe, a body length within 10% of it, and a certificate that names the hostname. A certificate
alone is not enough. The finding is a medium `origin-exposure`, with the console line `+ medium origin
exposure <hostname> -> <address> (behind <provider>)`; a candidate that is not confirmed is a low
possible origin in the same row, which becomes the medium finding if a later check confirms it.
The finding is no longer current when the hostname is no longer behind a CDN or WAF, the address
becomes provider infrastructure, or the sibling no longer matches; after `--redo origincheck`, an
answer that no longer confirms leaves the row current as a possible origin.

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
(see [Web identifiers](#pivoting-on-them)). Shared infrastructure is a family of two sources,
`shared-ns` and `shared-mx` (see [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)),
so a root found by both is still one family.

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
| `resolutions.csv` | DNS records for in-scope names (A, AAAA and CNAME, the NS, SOA, TXT and CAA records of each root, and the SRV records of the listed service names, see below), with a `source` column: `resolve` (nyx's own lookup), `shodan` (reported by Shodan only) or `resolve;shodan`, then `self_hosted`: `yes` or `no` on an NS row of nyx's own lookup and blank otherwise (see [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)). Records only Shodan reports decide nothing: they never make a name resolved or an address contacted, port-checked or probed. Historical addresses of a hostname behind a CDN or WAF are rows of type `A-historical` or `AAAA-historical`, source `dnshistory`, with the `historical_first_seen` and `historical_last_seen` columns (the last two before `current`; blank on every other row). A historical address is never a current one: it is not probed, port-checked or used to detect wildcards (see [Origin exposure](#origin-exposure)). |
| `unresolved.txt` | In-scope names that did not resolve |
| `wildcard-excluded.txt` | Names dropped because their domain answers every name (wildcard DNS) |
| `ips.csv` | Addresses with ASN, owner, hosting provider, service (or, where the provider publishes no service, region), scope, port eligibility and hostnames, then the `registrant`, `registrant_netblock` and `registry` the `rdap` stage found, then `srv_ports`, the ports SRV records advertise for the address's in-scope hostnames (reported only; never connected to). A published range names the provider even when the owner lookup failed, and takes precedence over the ASN. Cloudflare and Fastly addresses are shared infrastructure and are not port-checked. DigitalOcean addresses and Linode addresses are customers' own machines, except that an address whose origin AS is a CDN's (Linode's list holds some of Akamai's edge space) stays shared, so an in-scope hostname that resolves to one of the others is port-checked: DigitalOcean addresses were skipped as shared hosting before its list was fetched, so the next active run may handshake addresses it previously skipped. An address two providers' lists cover shows both, joined with `;`, and is shared if either is. |
| `provider-hosts.csv` | Names that point at shared cloud or SaaS providers, with the evidence |
| `web-services.csv` | Web services found: status, title, server, technologies, redirects, TLS details (see [TLS detail](#tls-detail)), web posture evidence (see Web posture above) and web identifiers (see [Web identifiers](#web-identifiers)) |
| `urls.csv` | URLs from crawling, the scripts of crawled pages (see [JavaScript endpoints](#javascript-endpoints)) and web archives, with status and source |
| `open-ports.csv` | TCP ports that nyx found open, and ports Shodan reports (see [Shodan per address](#shodan-per-address)), with the banner, the `source` (`nyx`, `shodan` or `nyx;shodan`), `confirmed` (`yes` when nyx completed a handshake), `shodan_last_seen` (empty on a row only nyx saw), and `product` and `version` where the banner is a recognised SSH, FTP or SMTP banner (see [End-of-life software](#end-of-life-software)) |
| `email-posture.csv` | SPF, DMARC and MX results per root domain, then `mta_sts`: `present` when exactly one TXT record at `_mta-sts.<root>` begins `v=STSv1`, `absent` otherwise, and empty for a root without a mail host, then `mx_self_hosted`, the mail hosts the organisation runs itself, joined with `;` (see [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)) |
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
| `risk-eol-software.csv` | Web technologies and banners whose version is past the end of security support (`eol`, medium) or within `eol_warn_days` of it (`eol-approaching`, low), with `product`, `version`, `end_date`, `seen` (`web` or `banner`) and `confirmed`; a distribution build or a version only Shodan reports is one step lower (see [End-of-life software](#end-of-life-software)) |
| `risk-origin-exposure.csv` | One row per hostname behind a CDN or WAF and address that may be its origin server: the `provider`, the `address`, `found_by` (`historical`, `sibling-certificate`, `sibling-title`, joined with `;`), `confirmed_by` (`title` or `status-body-certificate`) and `confirmed` (`yes` or `no`). Confirmed rows are medium and possible origins low (see [Origin exposure](#origin-exposure)) |
| `changes.csv` | What is new, returned or gone since the run started (see [What changed since the last run](#what-changed-since-the-last-run)): `change`, `kind`, `key`, `scope` and, for a finding, `severity` |

A file is only written when it has rows, so a missing `risk-*.csv` means no findings of that kind
(a file that later has no rows is removed). Files are sorted, except `candidates.csv`, which is
sorted by confidence. Every CSV ends with `current`, `first_seen` and `last_seen` columns, and records
that were not found by a later run are kept and marked not current. The `.nyx/` directory holds
the state database and the run lock. Don't edit it. Finding severities are listed by
`nyx help findings`.

## What changed since the last run

After a re-run, `changes.csv`, the end of the console summary and the envelope's `changes` key say
what is new and what has disappeared, so you need not diff the CSV files. A change is a difference between what the output
files showed when the run started and what they show when it ends, for the things the files list
(hostnames, addresses, DNS records, web services, URLs, open ports, email posture, third parties, code
mentions, findings, candidates, excluded names and netblocks). Evidence and internal records are not
listed.

- **`new`** is shown at the end and was not on record at the start, **`returned`** is shown at the end
  and was on record but not shown at the start (a finding that stopped being derived and is derived
  again, a host a scope change had hidden), and **`gone`** was shown at the start and is not shown at
  the end. A hostname that an exclusion hides is `gone` as a hostname and `new` as an excluded name.
- **`changes.csv`** has one row per change: `change`, `kind` (the label above, such as `hostname`,
  `web service`, `open port` or `finding`), `key` (what the other files call it), `scope`
  (`in-scope`, `candidate` or `excluded` for hostnames, candidates, excluded names and netblocks,
  `in-scope` for records shown only while their host or address is, and blank otherwise) and, for a
  finding, `severity`, then `current`, `first_seen` and `last_seen`. A `gone` row has the scope and
  severity the thing had when it was last shown, and is not current. The file is replaced on each
  run, and removed when a run has no changes.
- **A first run** (an engagement with no records when the run starts) writes no `changes.csv`,
  prints no block and has `null` for `changes` in the envelope.
- **The console summary** ends with a "Since last run" block: the number of new (including returned)
  hostnames, addresses, web services, open ports, candidates and findings, and of gone findings,
  then the new high and medium findings as a list.
- **The envelope's `changes`** is `null` on a first run, and otherwise an object with two keys.
  `counts` is a list of `{kind, change, n}`, one for each kind and change (`new`, `returned` or
  `gone`) whose `n` is above zero, sorted by kind and then change; `kind` is the label above. The
  summary's block adds `returned` to `new`; the envelope keeps them apart. `findings` is the list of
  new high and medium findings, in the shape of the envelope's `findings`. Each row of a change is
  in `changes.csv` and in `nyx recon export`, not in the envelope.
- **Resuming.** The comparison is with the state when this invocation started, which nyx saved
  each time it wrote the files, so a run that resumes an interrupted one compares against where the
  interrupted run stopped. An interrupted run writes `changes.csv` for the work it completed, then
  exits 130. A run that the deadline ended does the same, and its `changes` count what it completed.
- **With no contact.** Findings can become new or gone when nothing was contacted: a certificate
  passes its expiry date, a setting such as `--cert-expiry-days` changes, or the binary does. A
  `--passive` run never reports a record gone when every stage that observed it made contact with
  the target, because those stages did not run; findings are the exception, since they are worked
  out again on every run.

Only the last two states are compared: nyx keeps no history across more than one run, and does not
report a change in the attributes of something that stayed shown.

## Exporting an engagement

`nyx recon export -e <name>` writes everything recorded about an engagement to stdout as JSON lines, for
other tooling. The CSV columns are for people and may change; the export is the form to read from
a program. `--output-dir` and `--config` find the engagement as they do for a run.

```sh
nyx recon export -e acme > acme.jsonl
nyx recon export -e acme --current --kind hostname --kind web_service --output hosts.jsonl
```

- **Lines.** There is one line for each input (`kind` `input`, with `type` of `root`, `org`, `asn` or
  `cidr`, `value` and `added`) and each exclusion (`kind` `exclusion`, with `value` and `added`),
  then one line for each record of the engagement, current or not, in kind order and then key order.
  A record line has `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen` and `stages`, the
  stages that observe it now (none when it is not current), and then either `scope` or `shown`.
  `scope` is `in-scope`, `candidate` or `excluded`, for hostnames, roots, netblocks, autonomous
  systems, organisations and excluded items, and is `candidate` exactly when `candidates.csv` lists
  the record. An organisation that matches no `--org` input and is not an organisation candidate
  is listed in no file, so it has `shown` `false` instead. `shown` is `true` or `false` for every
  other kind, as the files and summary decide it: whether the record is shown for the engagement's
  scope. Both are worked out when you export,
  from the engagement's inputs and your current configuration, the same way a run does, so an
  exclusion added since a record was found is reflected.
- **Attributes.** `attrs` are the record's attributes merged from the stages that observe it, later
  stages in the registry winning a field, as in the CSV files. The store keeps attributes only
  from current observations, so a record that is not current has `attrs` of `{}`. `finding` and
  `candidate_rank` records are derived from the others: they are exported like any other record,
  but their `stages` name the pseudo-stage that derived them (`findings`, `candidate-rank`), which
  is not a stage you can `--redo`.
- **`--current`** keeps only current records. **`--kind`** (repeatable) keeps only the kinds
  named; `nyx recon export --help` lists them, including `input` and `exclusion`. The two combine.
  A missing `-e`, an unknown kind and an `--output` whose directory does not exist exit 2, all
  reported together. `--json` changes only the format of an error (see [Errors](#errors)), not one
  line of the export, and there is no envelope, cap or paging: the lines are the whole export.
- **`--output <file>`** writes to the file instead, replacing it atomically: the lines go to a
  temporary file beside it, which is renamed into place, so a failed write leaves an existing
  file as it was. A write failure exits 1.
- **Left out.** The authorisation acknowledgement, the netblock approval and the settings are not
  exported, and an API key never is: any configured key value in the text is replaced with `****`.
  Text a target supplied (titles, banners) is sanitised as for console output.
- **Reading only.** `export` takes no lock, so it works while a run is in progress and shows the
  state as of one moment, writes nothing to the engagement and makes no network requests, so it
  takes no `--timeout`. An engagement that does not exist exits 3 (`NOT_FOUND`, creating nothing),
  with a hint listing up to ten of the engagements in the output directory. A directory that is not
  a nyx engagement exits 2, naming it, and a failure to write the export exits 1.

**What stays stable.** The names of the stored attributes (they are what the state database keeps,
so renaming one would break resuming an engagement) and the export's own field names and kind
names. The attributes of a `finding` record are derived and may change, and so may anything in the
CSV files.

## CVE lookup

`nyx cve` looks CVEs up in the NVD by CVE ID and returns one record for each ID the NVD holds. By
default a record has every field but the two long lists, the affected products and the references,
and in their place the number of entries in each, so a record is as short for CVE-2021-44228 as for
a CVE with one entry in each list. Ask for the lists, or for part of them, when you need them.

```sh
nyx cve CVE-2021-44228 CVE-2024-3094 --json
nyx cve - --json < ids.txt
nyx cve CVE-2021-44228 --fields id,cvss_score,cvss_severity --json
nyx cve CVE-2021-44228 --fields affected_products --match log4j --limit 10 --json
```

- **IDs.** Pass one or more as arguments, or a lone `-` to read them from stdin, one per line, with
  blank lines ignored. `-` alongside other arguments exits 2, and so does a bare `nyx cve` or a `-`
  with no IDs on stdin, with the hint `nyx --help`. Case and surrounding whitespace are tidied
  (`cve-2021-44228` is `CVE-2021-44228`), an ID given twice is looked up and returned once, and
  records come back in argument order. Every ID is checked against `CVE-YYYY-NNNN` (four or more
  digits) before the first request. A malformed one becomes an `INVALID_INPUT` entry and the others
  are still looked up.
- **The record.** These are the keys, in this order, and `--fields all` returns every one. A key with
  no value is `null`, and an empty list is `[]`. A rejected CVE is a record with the status
  `Rejected`, not a not-found.

  | Key | Meaning |
  |---|---|
  | `id` | The CVE ID |
  | `status` | The NVD's status: `Analyzed`, `Modified`, `Awaiting Analysis`, `Rejected` and the like |
  | `published`, `last_modified` | RFC 3339 in UTC, to the second |
  | `description` | The first English description, trimmed, else the first in any language |
  | `cvss_version`, `cvss_score`, `cvss_severity`, `cvss_vector`, `cvss_source` | One CVSS score: the highest version present (4.0, 3.1, 3.0, then 2.0), and within it the NVD's own (`Primary`) score over anyone else's. The severity is upper case |
  | `weaknesses` | The English CWE values, de-duplicated in order (`NVD-CWE-Other` and `NVD-CWE-noinfo` are kept) |
  | `affected_products_count`, `references_count` | How many entries the list after it has, as an object: `{"total":n}`, with `"matched":m` added under `--match` and `"omitted":k` under `--limit` when its list is shown too (see below). Every value is a number, and which keys there are depends on the flags, never on the data |
  | `affected_products` | Each vulnerable CPE match, once: `cpe`, `vendor`, `product`, `version` (from the CPE, unescaped, `null` for `*` or `-`) and the four `version_start_*`/`version_end_*` bounds |
  | `references` | Each reference's `url` and `tags` |

- **`--fields a,b,c`** returns only those keys, plus `id`, in both modes; `all` returns every key,
  both lists and both counts included, and `--fields ""` returns `id` alone. An unknown name exits 2
  with the valid names in the hint. Without `--fields` a record has every key but
  `affected_products` and `references`. A count can be named like any field, and naming a list
  brings its count with it, so a list is never shown without its numbers.
- **How to see the lists.** When the default or `--fields` leaves out a list that at least one
  record has entries in (matching entries, under `--match`), the call says once how to see it,
  naming only the lists that have some: `use --fields affected_products,references (or --fields all)
  to list them`. Under `--json` it is `meta.hint`; in human mode it is one `INFO` line on stderr
  after the records, which `--quiet` hides. Nothing is said when nothing was left out, or what was
  left out has no entries.
- **`--limit N`** shows at most the first N entries of each list that is shown, in the NVD's order,
  and says how many were left out: `"omitted":k` in the count under `--json` (`0` when none were),
  and a line `k more not shown` after the list in human mode, only when k is above 0. By default
  there is no limit. N must be a positive whole number and `--limit` may be given once; anything
  else exits 2, and so does `--limit` when `--fields` shows neither `affected_products` nor
  `references`. It limits entries, never records: every ID given is still returned.
- **`--match TEXT`** keeps only the entries of the lists whose text contains TEXT, ignoring case.
  For an affected product that is the line human mode shows (vendor, product, version and the
  version bounds, such as `apache log4j (>= 2.0.1, < 2.3.1)`, and not the fixed `cpe:2.3:<part>:`
  start of its CPE), and for a reference it is the URL or any one of its tags. The match is made
  against the NVD's text as `--json` writes it. Surrounding whitespace in TEXT is trimmed; an empty
  TEXT or a second `--match` exits 2, and so does `--match` when `--fields` shows neither list nor
  either count. The default shows the counts, so `nyx cve CVE-2021-44228 --match log4j` says how
  many entries match. With `--match` a count has both `"matched":m` and `"total":n` (`3 of 163` in
  human mode), and the match comes before `--limit`, so a limit and the number left out refer to the
  matching entries. `--match` never removes a record: a list with no matching entry says that
  nothing matched (`No affected products match.`), which is not the NVD listing none.
- **`--json`** prints one compact object,
  `{"data":[…],"meta":{"count":n,"errors":[…],"warnings":[…],"hint":…}}`. `meta.errors`,
  `meta.warnings` and `meta.hint` are always present: `[]` when there are no errors or warnings, and
  `null` when there is no hint. Each `meta.errors` entry has the five keys of
  the error (see [Errors](#errors)), with the argument exactly as given in `input`. The NVD's text
  is written as the NVD sent it.
- **Without `--json`** each record is laid out for reading: its ID and a severity badge, then a
  section each for the status and dates, the description, the CVSS score, the weaknesses, the
  affected products and the references, as `--fields` selects them. A list's section has its number
  in the heading, `Affected Products (163)`, or `Affected Products (3 of 163 match)` under
  `--match`; where only the count is shown, the section is that number alone, `163 listed` or
  `3 of 163 match`. Records are separated by a
  blank line, and text is wrapped to `COLUMNS` (default 100, at least 60). The NVD's text is
  stripped of anything that would act on a terminal. On a terminal the layout is the one in
  [Terminal layout](#terminal-layout): a header bar, headings, and labels with no colon.
- **The key.** `NVD_API_KEY`, and otherwise `keys.nvd` in the config file. `nyx cve` takes
  `--config` and reads the configuration as recon does: an unreadable or invalid config file, or an
  invalid `NYX_*` setting, exits 2, and a missing default file is fine. `NYX_KEYS_NVD` is not read:
  when it is set and no key was found, the call warns `NYX_KEYS_NVD is not read; set NVD_API_KEY
  instead`, in `meta.warnings` under `--json`, as a `WARN` line on stderr otherwise, and in the
  error's hint when the call fails with nothing on stdout. The key never appears in any output.
- **Pacing.** Requests are paced to the NVD's rate limit with a sliding window: 50 per rolling 30
  seconds with a key and 5 without, with at most 4 in flight. A batch longer than that waits for the
  window, within the deadline.
- **`--timeout`** (default `60s`) is the deadline for the whole call. A network error, a 502, 503 or
  504, and a rate-limit answer (a 429, or a 403 that does not name the API key) are retried up to
  twice, after the NVD's `Retry-After` when it gives one in seconds, else after a backoff of about
  1s, then 2s. A wait that would pass the deadline fails that ID at once, marked transient, with the
  wait in its hint: `RATE_LIMITED` when it was for the window or for a rate-limit retry, `TIMEOUT`
  otherwise. A request still in flight at the deadline is `TIMEOUT`. A stdin that is not closed by
  the deadline is `TIMEOUT` too.
- **A refused key** is `AUTH_FAILED` (exit 1), however the NVD says so: a 401, or a 403 or 404 whose
  `message` header or body names the API key. The first refusal stops the batch: the IDs not yet
  sent fail with the same error. A 404 that does not name the key is `UPSTREAM_ERROR` (the NVD
  answers 404 to a parameter it refuses), never `NOT_FOUND`: an ID the NVD does not hold is a 200
  with no results.
- **Contact.** `nyx cve` contacts only `services.nvd.nist.gov`, keeps no state and writes no files,
  so the same call gives the same result.

**The outcome** of a call depends on how many IDs succeeded:

| Outcome | Exit | stdout |
|---|---|---|
| Every ID succeeded | 0 | The records |
| Some succeeded | 7 | The records and the failures |
| None succeeded, all with one error code | That code's: 3 when all are `NOT_FOUND`, 1 for `AUTH_FAILED` or `RATE_LIMITED`, 2 when every ID is malformed | Empty. The one error covers every ID: its `input` is `{"id":[…]}`, the IDs as given |
| None succeeded, with different codes | 7 | No records, and the failures |

On exit 7 the `PARTIAL` error counts what succeeded and what did not (`3 of 5 IDs returned, 2
failed`, or `none of 3 IDs returned`), its `input` lists the IDs that failed as given, and it is
transient when any failure is. In human mode one `error: <input>: <message> (<CODE>)` line follows
for each ID that failed. The hint is the command to run for the IDs worth retrying (the transient
failures), with the flags you gave, after the longest known wait: `after 25s, run: nyx cve
CVE-2024-3094 --json`. When none is worth retrying it lists the IDs to check. Past 20 IDs it points
at the failures instead of listing them. A single-code error that is transient carries the same
command, listing every ID however many, as its failures are not written; when the code is `TIMEOUT`
it adds `, or raise --timeout`. One that is not transient keeps its code's hint, such as `check the
ID; the NVD lists only published CVEs` or `check NVD_API_KEY`.

**Differences from the `cve` tool.** The default record leaves out the affected products and the
references, which the `cve` tool returns, and has a count of each (see above). A 404 is never "not
found" (see above). The `--api-key` flag is gone: the key comes only from `NVD_API_KEY` or
`keys.nvd`. Colours are nyx's palette.

**A deliberate break.** Leaving the two lists out of the default record broke the promise that
every record has every key (see [Errors](#errors), "What stays stable"). It was made once, on
purpose, in the change that added `--limit` and `--match`: ask for `--fields all` to get the
previous record, with a count in front of each list.

## Exit codes

Every command uses the same exit codes:

| Code | Meaning | Error codes |
|---|---|---|
| 0 | Success: the run did all its work and no check failed. A `not-configured` stage, work a per-run cap deferred and a result a page cap truncated do not stop it being a success | none |
| 1 | System error: the arguments were fine and something else went wrong, including an engagement locked by another run | `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED`, `UPSTREAM_ERROR`, `AUTH_FAILED`, `LOCKED`, `UNEXPECTED_ERROR` |
| 2 | Usage error: a bad flag, setting, config file, input or file named on the command line, an output directory that is not a nyx engagement, or the netblock limit; for `nyx cve`, no IDs, or only malformed ones. Nothing was created or contacted, except that the netblock limit is found once a run has started | `INVALID_INPUT` |
| 3 | Not found: an engagement that does not exist, or no CVE ID the NVD holds | `NOT_FOUND` |
| 7 | Partial result: a recon run the deadline ended, or in which any check failed; a `nyx cve` batch in which some IDs failed, or every ID failed with different error codes | `PARTIAL` |
| 130, 143, 129 | Interrupted by SIGINT, SIGTERM or SIGHUP | `INTERRUPTED` |

**Exit 7 for recon.** A recon run exits 7 when the deadline ended it (see [Deadline](#deadline)) or
when any check failed in it. Exit 0 no longer covers failed checks. The summary or envelope has been
written to stdout, and the files are current, before the error that follows it on stderr. A failed
check is one that returned a transient error, one a stage abandoned when it stopped for the run on
a 401, 403, 429 or spent quota, and one that panicked (a panic inside one check is that check's
failure: the run carries on, and the check is retried on the next run).

- **The error** names each stage with failed checks and how many (`16 checks failed: crtsh 2,
  shodan 14`). Its hint is your own invocation, shell-quoted, with `--redo` and its value left out
  and every other argument kept: run it to retry the failed checks. The error is marked
  transient unless every failure was a key the source refused (a 401 or 403 from a keyed source, and
  a 401 from GitHub, which answers 403 for a rate limit): waiting does not cure those, so fix or
  remove the key.
- **Not partial.** These do not make a run partial: a `not-configured` stage, work a per-run cap
  deferred, a result truncated by a page cap, and failures recorded by earlier runs for stages that
  did not run this time.
- **The deadline's error** is the `PARTIAL` of the [Deadline](#deadline) section, with the failed
  checks of the run named in it as well.

**Several outcomes.** One is reported, the first of these that applies: a signal (130, 143 or 129),
a fatal error (exit 1), the netblock limit (exit 2), the deadline (exit 7), failed checks (exit 7).
A signal that arrives while a deadline run is writing its files leaves `INTERRUPTED` and an empty
stdout; one that arrives after the result is written leaves exit 7 standing.

**Engagement problems** get the code of their kind:

- An engagement locked by another run exits 1 with `LOCKED`, marked transient: wait for the other
  run to finish, or use another `-e`.
- An output directory that is not a nyx engagement (one that holds files and no `.nyx`, such as
  the Python version's) exits 2 naming the directory, with a hint to choose another `-e` or move it
  away. Nothing is written into it.
- `nyx recon -e <name>` with no inputs, for an engagement that does not exist, exits 3 with
  `NOT_FOUND` and creates nothing. The hint lists up to ten engagements in the output directory and
  says how many more there are, or says there are none and how to start one. When the call has other
  problems, they are reported alone, as exit 2.
- `nyx recon export` follows the same rules: an engagement that does not exist exits 3 with that
  hint, a directory that is not a nyx engagement exits 2, and a failure to write the export exits 1.

Any other failure to open, read or write an engagement is `UNEXPECTED_ERROR` (exit 1), which
prints its stack trace to stderr only with `--debug`.

A signal ends the command with its own code. recon saves the work completed so far, as it does for
any interruption; run the same command again to continue. A second signal exits at once with the
first one's code.

### Errors

Every non-zero exit writes one error to stderr. stdout is empty on every exit but 0 and 7: a recon
run that exits 7 has written its summary, or its envelope under `--json`, first, and a `nyx cve`
batch its records (none, in human mode, when no ID succeeded). The error is never
sent through the log formatter.

```
error: invalid domain "co.uk": it is a public suffix, not a registrable domain (INVALID_INPUT)
hint: nyx recon --help
```

A `hint:` line follows when there is a next step, and `retry: may succeed after a wait` when the
error is transient. A partial result from several targets adds one `error: <input>: <message>
(<CODE>)` line for each target that failed. `input` is `null` for the `PARTIAL` error of a recon run;
for `nyx cve` it is `{"id":[…]}`, the IDs that failed as given. Under `--json`, even when the arguments fail to parse,
the error is one compact line of JSON with exactly the keys `error`, `code`, `hint`, `input` and
`transient`, in that order; `hint` and `input` are `null` when there is nothing to say, and `input`
maps each failing argument to the list of its values as given:

```json
{"error":"invalid domain \"co.uk\": it is a public suffix, not a registrable domain","code":"INVALID_INPUT","hint":"nyx recon --help","input":{"domain":["co.uk"]},"transient":false}
```

Checks of values and combinations report every problem they find in one error. API keys are masked
in the error as everywhere else.

**What stays stable.** The exit codes, the error codes, the five keys of the error, the keys of
the recon `--json` envelope (see [The `--json` envelope](#the---json-envelope)), and the keys of the
CVE record and of the `nyx cve` envelope (see [CVE lookup](#cve-lookup)) are an interface: a
new one may be added, but renaming, removing or retyping one is a breaking change. The wording of
messages and hints may change. The one exception so far is that the default `nyx cve` record no
longer has the lists `affected_products` and `references`, only their counts: that was a deliberate
break, made once when `--limit` and `--match` were added, and `--fields all` still returns them.

## Departures from `docs/agent-tools`

The guidance in `docs/agent-tools` is followed, except in these eleven ways:

1. recon has no default `--timeout`: a run takes as long as it needs unless you give a deadline.
2. `nyx recon export` writes JSON lines with no envelope, cap or paging.
3. API keys may come from the config file (`keys.<source>`), as well as from the environment.
4. A stage whose key is missing is `not-configured`, not a usage error.
5. `--authorized` is accepted as an alias of `--authorised`.
6. `--quiet` with `--debug` is rejected (exit 2).
7. SIGHUP exits 129.
8. recon can finish slightly after its deadline, when writing the files takes longer than the
   reserve (see [Deadline](#deadline)).
9. recon's requests are paced by token buckets, not a sliding window (`nyx cve` uses a sliding
   window).
10. A failed recon request is not retried within the run: its check is retried on the next run.
    The exceptions are GitHub's rate limit (see [GitHub code search](#github-code-search)) and an
    overloaded Common Crawl index (see [Passive boundary](#passive-boundary)). `nyx cve` retries
    within the call.
11. recon's HTTP connections are not reused.

## Migrating from the Python version

- **Commands.** What `nyx <domain>` did is now `nyx recon <domain>`, and `nyx export` is
  `nyx recon export`. The old forms exit 2 with the corrected command as the hint, and do nothing
  else. A bare `nyx` prints the help. There is no authorisation prompt any more: pass
  `--authorised`.
- **Old output directories** are not resumable. nyx refuses them (exit 2, naming the directory,
  with a hint to choose another `-e`) and never writes into them. Use a different `-e` name, or move
  the old directory away.
- **Retired:** the `reconsite` single-site command and XSS and SQL injection testing are gone.
- **No external tools:** Amass, subfinder, massdns, httprobe, hakrawler, dalfox and the rest are
  no longer needed, and neither is `install.py`.
