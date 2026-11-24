# Web services

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

## JavaScript endpoints

The `crawl` procedure notes every `<script src>` on the pages it fetches, whatever host the script is
on. The `jsparse` procedure (it contacts the target, so it is skipped under `--passive` and until you
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
the only script URLs the procedure can request are those the crawl recorded. A script on a CDN or any
other host that is not in scope, on an excluded host, on a wildcard-only name or served by a SaaS
platform is not fetched. A redirect is followed only to the same host, and any answer other than
2xx, or one that is HTML (a `text/html` type, or a body that starts with `<`), records nothing. A
timeout is a failed job, retried on the next run.

`jsparse.max_scripts` caps the scripts fetched per origin, in URL order, with a warning that says how
many were left. A script already read keeps its place when new ones appear, so a re-crawl does not
read the same bundles again. Scripts are read up to 4 MiB (the usual limit on a response is 1 MiB,
but bundles are large); a longer script is read as far as 4 MiB, what is in that part is recorded
and a warning says it was cut. Only the script text is read: source maps and inline scripts are not,
and nothing is executed or searched for secrets.

When a re-crawl no longer references a script, the URLs found only in it are marked not current.
An engagement crawled by an earlier version has no script records until you run `--redo crawl`.
The job for a script is keyed by its URL and the parser, not by the scope, so a root you add later
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

With `keys.shodan`, the `identifier-pivot` procedure (it runs under `--passive`, over the identifiers
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
  order of their job keys (`favicon|…`, then `html|…`). The rest wait for later runs, which is not a
  failure; the number deferred is under `Deferred to the next run` (the unit of that number is
  searches). A search that fails still counts.
- **Keys and credits.** A key without search access (a 401 or 403) fails the procedure with one
  warning, and so does a 429. No query credits (a 402) stop the procedure for the run; the search that
  was refused and the ones not yet sent run next time.
- **Refresh.** A search is made once per identifier; `--redo identifier-pivot` repeats it. The job is
  keyed by the identifier and not by the scope, so a hostname under a root you promote later was
  recorded only as a candidate root, and becomes a hostname after `--redo identifier-pivot`.

## Origin exposure

A site behind a CDN or WAF is only as protected as its origin server is hidden. nyx looks for
origin servers that can be reached directly, in two procedures.

The `dnshistory` procedure runs under `--passive` and needs `keys.securitytrails`; without it the procedure
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
- **Quota.** A 401, 403 or 429 from SecurityTrails stops the procedure for the run, as it does for the
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

The `origincheck` procedure contacts the target, so it is skipped under `--passive` and until you
confirm authorisation. It makes one job for each pair of a hostname and a candidate, but only if
the candidate may be contacted (it is inside an in-scope netblock, or is the current address of an
in-scope hostname with a known, dedicated owner, and is not excluded) and the probe has a 2xx
result for the hostname's HTTPS service. Every other candidate is reported as a possible origin and
is never contacted. The job is one `GET /` over HTTPS on port 443 with the hostname as both the TLS
server name and the Host header, and, only if nothing answers on 443 (not if it fails the TLS
handshake), one over HTTP on port 80. Redirects are not followed, and a 3xx confirms nothing. If
the title or certificate the probe saw changes, the pair is probed again.

The exposure is **confirmed** when the response's non-empty title equals the probe's title for the
hostname and is not a CDN, WAF or default-server title, or when the response has the same status as
the probe, a body length within 10% of it, and a certificate that names the hostname. A certificate
alone is not enough. The finding is a medium `origin-exposure`, with the console line `+ medium origin
exposure <hostname> -> <address> (behind <provider>)`; a candidate that is not confirmed is a low
possible origin in the same row, which becomes the medium finding if a later probe confirms it.
The finding is no longer current when the hostname is no longer behind a CDN or WAF, the address
becomes provider infrastructure, or the sibling no longer matches; after `--redo origincheck`, an
answer that no longer confirms leaves the row current as a possible origin.
