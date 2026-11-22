# Passive boundary and authorisation

## Passive boundary

nyx limits what target-owned systems can receive. It sends only:

- **DNS lookups.** Zone transfers are never attempted.
- **TCP handshakes** to the configured port list. It reads only what the service sends
  unprompted and sends nothing.
- **HTTP(S) GET and HEAD requests** to in-scope, non-excluded hosts, to same-host links found
  while crawling, to each service's `/robots.txt` and `/sitemap.xml` and the same-host URLs they
  list (robots.txt is read, not obeyed), to the paths on the sensitive-path list, to same-site
  script files referenced by crawled pages (the URLs found inside a script are recorded, never
  requested; see [JavaScript endpoints](web.md#javascript-endpoints)), and to one favicon per web
  service: the same-host `<link rel="icon">` URL of its page, or `/favicon.ico` (see
  [Web identifiers](web.md#web-identifiers)).

- **One GET of `/` to an address it is already allowed to contact, with an in-scope hostname as
  the server name and the Host header.** The `origincheck` stage sends it to see whether a
  hostname behind a CDN or WAF is also served directly by its origin server (see
  [Origin exposure](web.md#origin-exposure)). The address is one that may be port-checked: inside an
  in-scope netblock, or dedicated to the organisation, known, not excluded, and the current address
  of an in-scope hostname. It is asked in place of the CDN, so that the answer says what that address
  serves for the hostname; it is never an address nyx would not already handshake. One GET goes over
  HTTPS on 443 and, only if nothing answers there, one over HTTP on 80; a redirect is not followed.

It never sends credentials, submits forms, uses other HTTP methods, puts payloads in parameters or
headers, or requests paths beyond those listed. UDP is not used. Candidate hosts (found but not in
scope) and excluded hosts are never contacted, except that a candidate that is the host of one of
the third parties below (a cloud-storage account an in-scope page redirected to, say) is still asked
as that third party; an excluded host never is. Everything else comes from third parties: CT logs
(crt.sh and Cert Spotter), web archives, passive DNS and search (HackerTarget and urlscan.io),
GitHub's code search, public DNS resolvers, RDAP/WHOIS, BGP data, keyed APIs and cloud-storage
provider endpoints. Only hostnames are recorded from Cert Spotter, HackerTarget and urlscan.io. When one of these three
reports that its free quota is spent, its stage alone stops, the checks it did not do are failed (the
run exits 7, see [Exit codes](exit-codes.md#exit-codes)), and they are retried on the next run. HackerTarget (and SecurityTrails, with its key) also receives the engagement's dedicated
addresses, for its reverse IP lookup (see [Reverse IP](sources.md#reverse-ip)); SecurityTrails also receives
the hostnames behind a CDN or WAF, for their DNS history (see [Origin exposure](web.md#origin-exposure)); the
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
registries' RDAP servers; see [RDAP](sources.md#rdap-netblocks-and-registrants).

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

Team Cymru, through the public resolvers, also receives one query for each /24 (IPv4) or /48 (IPv6)
that holds an in-scope netblock address nyx knows, or for an in-scope netblock that is smaller. The
query names the first address of that /24, /48 or netblock, and its answer is the origin AS the
abusive-network check uses (see [Abusive networks](abusive-networks.md)). It is a third-party lookup,
so it runs under `--passive`, and the target never receives it. No command contacts ipapi.is: its
lists of abusive networks and ASNs are a snapshot built into nyx.

**`nyx ip`** keeps no engagement and has no scope, so the list above is for recon and is unchanged.
By default `nyx ip` sends nothing to the address it looks up. It contacts only third parties and DNS
resolvers: Shodan's InternetDB (`internetdb.shodan.io`), RIPEstat (`stat.ripe.net`), HackerTarget
(`api.hackertarget.com`), IANA (`data.iana.org`, for the RDAP bootstrap file), the five regional
registries' RDAP servers (`rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net` and
`rdap.afrinic.net`), and the public DNS resolvers, for the Team Cymru TXT lookups, PTR names and
the A and AAAA records of a hostname. A hostname you give is sent to the public resolvers, except a
single-label name, which is never sent to one. An address that is not public (see
[IP lookup](ip.md)) is never sent to any third party or public resolver, and a CIDR is looked
up one address at a time.

`nyx ip --active` also sends the address, and only the address, these requests: a TCP handshake to
each port on its list, which reads what the service sends unprompted and sends nothing; a TLS
handshake on each of a few TLS ports, which completes the handshake, sends no application data and
neither trusts nor rejects the certificate; and one HTTP or HTTPS GET of `/` on each of a few web
ports, with no redirect followed (see [IP lookup](ip.md) for the ports). It never sends
credentials, uses another method, or requests another path. It sends them to:

- every public address that is not shared provider infrastructure (a CDN, SaaS, WAF or
  shared-hosting provider, or an address in a provider range nyx has built in; a cloud provider's
  address is not shared and is contacted);
- every non-public address, except an unspecified, this-network, multicast or broadcast address, an
  IPv6 link-local address (which needs a zone to be dialled), and a non-public address that only the
  public resolvers gave for a hostname: a hostile name could otherwise aim the connections at your
  own machine or your cloud's metadata service. One you gave as an address or in a CIDR, or that
  this machine's resolver gave, is contacted.

Passing `--active` is the confirmation that you may do this: it takes no `--authorised` (see
[Authorisation acknowledgement](#authorisation-acknowledgement)). Unlike recon, `nyx ip --active`
connects to the ports that InternetDB reports for the address, as well as its built-in list.

Under `--active`, three lookups go to this machine's own resolver rather than the public ones: a
single-label name, a name the public resolvers do not know (tried again there), and the PTR name of a
non-public address. They go wherever that resolver sends them, which may be a public resolver that
nyx cannot see; nyx never sends a non-public address to a public resolver itself, but your resolver
may forward it. Without `--active`, none of these lookups is made.

`nyx setup` contacts a source only to test a key you ask it to test, with one authenticated request
to that source alone and never to a target: `api.securitytrails.com`, `api.shodan.io`,
`www.virustotal.com`, `user.whoisxmlapi.com`, `api.platform.censys.io`, `dns.projectdiscovery.io`,
`api.github.com`, `api.certspotter.com` and `services.nvd.nist.gov`. A key test may spend a query
from the source's quota (VirusTotal and Censys do).

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
- The acknowledgement applies to recon only. `nyx ip` has no engagement to remember it in, and no
  `--authorised` flag: passing `--active` is the confirmation that you may connect to the addresses
  you gave it (see [IP lookup](ip.md)). Without `--active` it never contacts them.
