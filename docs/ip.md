# IP lookup

`nyx ip` returns who runs each address, where it is, what it is called and what is known to be
exposed on it: a readable record for each address, or one JSON envelope. It is for triaging an
address seen in a log or an alert in seconds, with no engagement and no key. By default it contacts
third parties and DNS resolvers only, and sends nothing to the address (see
[Passive boundary](passive-boundary.md#passive-boundary)). Recon and `nyx cve` are unchanged.

```sh
nyx ip 1.1.1.1 --json
nyx ip 203.0.113.0/28 198.51.100.7 example.com
nyx ip - --json < addresses.txt
nyx ip 192.0.2.10 --fields asn,as_name,rdap_org,ptr --json
nyx ip 192.0.2.10 --active
```

- **Inputs.** Pass IPv4 and IPv6 addresses, hostnames and CIDRs as arguments, or a lone `-` to read
  them from stdin, one per line, with blank lines ignored and surrounding whitespace trimmed. A bare
  `nyx ip`, a `-` alongside other arguments, and a `-` with no inputs on stdin exit 2. `nyx ip`
  takes no `--config`: nothing configures it, and the port lists and
  paces below are built in.
  - A **hostname** has two or more labels, parses as a domain name and is not all digits and dots. It
    is resolved (A and AAAA) through the public resolvers, and each address it gives has a record.
    Under `--active` a **single-label name** (`intranet`) is a hostname too, resolved only through
    this machine's resolver and never sent to a public one; without `--active` it is `INVALID_INPUT`,
    and the hint says to add `--active`. Only NXDOMAIN, or no A and no AAAA records, is `NOT_FOUND`: a
    resolver that fails is `NETWORK_ERROR` or `TIMEOUT`, marked transient. Under `--active`, a name the
    public resolvers do not know is tried again through this machine's resolver.
  - A **CIDR** has its host bits masked and expands to every address it holds, its first and last
    included.
  - Anything else, a URL or a `host:port` too, is an `INVALID_INPUT` entry (the hint gives the bare
    host), and the other inputs are still looked up. When the call exits 2, every `INVALID_INPUT`
    problem is reported together.
  - **One record for each distinct address**, at its first appearance and in its canonical form, which
    lists every input hostname that gave it. An IPv4-mapped IPv6 address is the IPv4 address. A CIDR's
    addresses come in address order, and a hostname's come IPv4 first, then IPv6, each in address
    order.
  - **At most 256 distinct addresses.** When the literal addresses and CIDRs alone pass 256, the call
    exits 2 before any request. Addresses a hostname gives count once it resolves: when the total
    passes 256, the call exits 2 having sent only DNS lookups.
- **Address kinds.** Every record has a `kind`: `public`, or the kind of non-public address it is. An
  address is non-public when IANA's special-purpose address registries (IPv4 and IPv6) mark it
  globally reachable `False` or `N/A`, so a longer prefix can differ from the one that holds it
  (192.0.0.0/24 is `False`, and 192.0.0.9/32 in it is `True`, so public). Teredo and 6to4 are
  non-public (`N/A`), and 64:ff9b::/96 is public. Multicast has registries of its own, and an IPv6
  address outside 2000::/3 that no row lists is `reserved`, from IANA's IPv6 Address Space registry,
  a different registry from the other kinds'. The table was written by hand from the registries as
  they stood on 21 November 2026, and they gain rows now and then.

  | Kind | Addresses |
  |---|---|
  | `public` | Globally reachable |
  | `private` | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
  | `ula` | fc00::/7 |
  | `loopback` | 127.0.0.0/8, ::1 |
  | `link-local` | 169.254.0.0/16, fe80::/10 |
  | `cgnat` | 100.64.0.0/10 |
  | `multicast` | 224.0.0.0/4, ff00::/8 |
  | `unspecified` | 0.0.0.0 and :: |
  | `this-network` | The rest of 0.0.0.0/8 |
  | `broadcast` | 255.255.255.255 only |
  | `documentation` | 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 3fff::/20 |
  | `benchmarking` | 198.18.0.0/15, 2001:2::/48 |
  | `reserved` | 240.0.0.0/4 but for the broadcast address, and IPv6 outside 2000::/3 that no row lists |
  | `ietf-protocol` | 192.0.0.0/24 and 2001::/23, but for the rows below and the reachable ones |
  | `6to4` | 2002::/16 |
  | `teredo` | 2001::/32 |
  | `nat64-local` | 64:ff9b:1::/48 |
  | `discard` | 100::/64 |
  | `dummy` | 192.0.0.8 and 100:0:0:1::/64 |
  | `srv6` | 5f00::/16 |
  | `nat64-discovery` | 192.0.0.170 and 192.0.0.171 |
  | `6a44-relay` | 192.88.99.2 (the rest of the terminated 192.88.99.0/24 is public) |
  | `ipv4-mapped` | Never occurs: an IPv4-mapped address is looked up as the IPv4 address it carries |

- **A non-public address** is sent to no third party and to no public DNS resolver. Without
  `--active` no PTR lookup is made for it either; under `--active` its PTR name is looked up through
  this machine's resolver only, which may itself forward the query to a public resolver that nyx
  cannot see (see [Passive boundary](passive-boundary.md#passive-boundary)). Its record has its kind and every other
  selected key `null` or `[]`. It counts as a success, and has no failures, but for one of that local
  PTR lookup.
- **The record.** These are the keys, in this order. Without `--fields` every key the mode allows is
  returned. A single value that is unknown is `null`, and a list with no entries is `[]`. A source
  that answers that it knows nothing about the address (a 404, or an empty answer) has answered, and
  its keys are empty; the keys of a source that failed are `null`.

  | Key | Meaning |
  |---|---|
  | `address` | The address, in canonical form |
  | `hostnames` | The input hostnames that gave it, `[]` for a literal address or one from a CIDR |
  | `kind` | `public`, or the non-public kind |
  | `asn`, `as_name`, `as_prefix` | The origin AS number, its name, and the announced prefix (Team Cymru) |
  | `rdap_netblock`, `rdap_org`, `rdap_registry` | The registered netblock (a CIDR when the range is exactly one, otherwise `start-end`), the registrant organisation, and the registry (RDAP) |
  | `ptr` | The PTR names |
  | `provider`, `provider_class` | The shared cloud or CDN provider and its class, from nyx's built-in provider data and the ASN. No provider range list is downloaded, so the answer can differ from recon's |
  | `geo_country`, `geo_city` | Approximate location. `?` or an empty country, and an empty city, are `null`. There is no region |
  | `internetdb_ports`, `internetdb_hostnames`, `internetdb_tags`, `internetdb_cpes`, `internetdb_vulns` | What Shodan's InternetDB reports: open ports, hostnames, tags, CPEs and CVE IDs |
  | `reverse_ip`, `reverse_ip_count` | HackerTarget's reverse-IP hostnames: the first 100, sorted, and the total count. `null` for an IPv6 address or a shared provider address, which is not asked and is not a failure |
  | `abusive_networks` | The entries of ipapi.is's most-abusive network list that hold the address, the most specific first, each `{network, rank, score_tag, abuse_score, org, org_type, updated}` (`rank` an integer, `abuse_score` the percentage as a number, `updated` the list's date, `YYYY-MM-DD`). From the snapshot built into nyx, so it needs no request and is `[]` when nothing holds the address; `null` for a non-public address (see [Abusive networks](abusive-networks.md)) |
  | `abusive_asn` | The entry of ipapi.is's most-abusive ASN list for the address's origin AS: a list of at most one `{asn, rank, score_tag, abuse_score, org, org_type, updated}`. `[]` when the AS is known and not listed, and when Team Cymru found no owner; `null` when Team Cymru failed (that failure is in `failures`, and the call exits 7) and for a non-public address. Asking for it asks Team Cymru |
  | `not_contacted` | Only under `--active`: why the address was not contacted, or `null` when it was |
  | `ports` | Only under `--active`: a list of `{port, state, banner}` |
  | `tls` | Only under `--active`: a list of `{port, server_name, outcome, names, issuer, expiry}` |
  | `web` | Only under `--active`: a list of `{port, scheme, host, outcome, status, server, title, location}` |
  | `failures` | A list of `{source, code, message, transient, quota}`, always last, `[]` when there are none |

  `address`, `hostnames`, `kind` and `failures` are always present. A failure's `source` is one of
  `cymru`, `rdap`, `ptr`, `ripestat`, `internetdb`, `hackertarget` or `probe`; `code` is an error
  code (see [Errors](exit-codes.md#errors)); and `quota` is true only for HackerTarget's spent daily quota. A
  failed probe is a result, never a failure: only an error of nyx's own, when it could not make the
  connection, is a `probe` failure.
- **`--fields a,b,c`** returns only those keys, plus `address`, `hostnames`, `kind` and `failures`.
  `all` returns every key the mode allows, and `--fields ""` returns only the four that are always
  present. An unknown name exits 2 with the valid names in the hint, and so does naming a key of
  `--active` (`not_contacted`, `ports`, `tls`, `web`) without `--active`. Only the sources the
  selected keys need are asked, with those they depend on: the provider needs the AS number from Team
  Cymru, HackerTarget needs the provider, and active probing needs the provider and InternetDB's
  ports. Under `--active` whether an address is shared provider infrastructure is always worked out,
  whatever `--fields` selects.
- **Sources.** For each address the sources are asked together, each at its own pace.

  | Source | Gives | Pace |
  |---|---|---|
  | Team Cymru (TXT over DNS) | `asn`, `as_name`, `as_prefix`, and the AS for `abusive_asn` | DNS, 50 a second |
  | RDAP (IANA's bootstrap file, then the registry, referrals followed) | the `rdap_*` keys | IANA and each registry host 1 a second |
  | PTR (DNS) | `ptr` | DNS, 50 a second |
  | RIPEstat, `maxmind-geo-lite` | `geo_country`, `geo_city` | 4 a second |
  | Shodan InternetDB | the `internetdb_*` keys | 1 a second |
  | HackerTarget | `reverse_ip`, `reverse_ip_count` | 1 a second |
  | The snapshot built into nyx (ipapi.is's most-abusive lists) | `abusive_networks`, and the entry of the AS for `abusive_asn` | no request |

  Under `--active`, connections to one address are also limited to 10 a second.
  - **RIPEstat's** geolocation is MaxMind GeoLite data, and RIPEstat is run by the RIPE NCC: credit
    the RIPE NCC and MaxMind if you publish it. It is approximate (a country, and often a city), has
    no region, and says where an address is registered more than where a machine is.
  - **InternetDB** is Shodan's free API. It is for non-commercial use, and it is limited for each
    client address.
  - **HackerTarget** is asked only for an IPv4 address that is not shared provider infrastructure,
    because its daily quota is small and a CDN address returns thousands of meaningless names. The
    names are cleaned as recon cleans them, de-duplicated and sorted; `reverse_ip` has the first 100
    and `reverse_ip_count` the total.
  - **The snapshot** counts as a source that always answers. An address whose only failed source is
    Team Cymru therefore still has its record, with its `abusive_networks` and a `null` `abusive_asn`,
    and the call exits 7. `--fields abusive_networks` sends no request beyond resolving a hostname
    input, and `--fields abusive_asn` asks Team Cymru. A match changes nothing about `--active`.
  - **A 429** from InternetDB, RIPEstat or one RDAP host is `RATE_LIMITED`, transient, and that source
    (for RDAP, that host) is not asked again in the call: each address not yet asked records
    `RATE_LIMITED`, with "not asked: rate-limited earlier in this call", and one warning names the
    source. HackerTarget's spent quota (a 429, or an answer that starts `API count exceeded`) latches
    the same way, but its failures are `RATE_LIMITED` with `quota` true, not transient, and the
    warning says the quota resets daily. A transport error is `NETWORK_ERROR`, transient; another
    non-2xx status, or a body that is unreadable or cut short, is `UPSTREAM_ERROR`, transient; a
    source that has not answered by the deadline is `TIMEOUT`, transient. Team Cymru answering
    NXDOMAIN, or with nothing, is an answer: the owner is unknown, which is not a failure.
- **The deadline.** `--timeout` (a positive duration such as `30s` or `2m`) is the deadline for the
  whole call, and replaces the default. The default grows with the number of addresses, because
  InternetDB's pace dominates a batch: 6 seconds plus 1.25 seconds for each address after the first,
  and under `--active` 30 seconds plus 2 seconds for each address after the first. While stdin is
  read, the one-address value applies from the start of the call. Once the inputs are read the
  default comes from the number of inputs, where a hostname counts as one address and a CIDR as
  its size, and once the hostnames resolve it is fixed from the number of distinct addresses. A
  stdin not closed by the deadline is `TIMEOUT`. Only one public address in the default mode is
  promised 6 seconds, on a working connection; neither a batch nor `--active` is. A source that has
  not answered by the deadline is a `TIMEOUT` failure in the record, and a port that was not
  probed in time is `not-probed`.
- **`--active`.** Passing it is the confirmation (see
  [Authorisation acknowledgement](passive-boundary.md#authorisation-acknowledgement)). nyx contacts the addresses
  [Passive boundary](passive-boundary.md#passive-boundary) says, and for each one:
  - **Ports.** It makes a TCP handshake to a built-in list of common ports, 21, 22, 23, 25, 53, 80,
    110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 853, 993, 995, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 9443, 11211 and 27017, and to the
    ports InternetDB reports that are not on it, lowest first, at most 64 of them. Unlike recon, it
    connects to the ports InternetDB reports. It reads the unprompted banner (at most 1024 bytes,
    with invalid UTF-8 replaced) and sends nothing. A port is `open`, `closed`, `no-answer`, or
    `not-probed` when the deadline came first.
  - **TLS.** On each open port of 443, 465, 636, 853, 993, 995, 8443 and 9443 it makes a second
    connection with a TLS handshake, once for each input hostname that gave the address, with that
    hostname as the server name, or once with none when there is no hostname. It records the
    certificate's names, issuer and expiry (`YYYY-MM-DD`, in UTC), and neither trusts nor rejects
    the certificate. InternetDB's tags describe an address and not a port, so no other port gets a
    handshake. The outcome is `ok`, `no-answer`, `refused`, `not-tls`, `reset` or `not-probed`.
  - **Web.** On each open port of 80, 443, 8000, 8080, 8443, 8888 and 9443 it sends `GET /` once for
    each input hostname that gave the address, with the hostname as the Host (or once with the
    address as the Host when there is none). It goes over HTTPS when the port is also a TLS port,
    and HTTP otherwise. It records the status, the `Server` header and the page title; a redirect is
    reported (its `location`), not followed. The outcome is one of the values above.
  - **Never contacted.** An address that is not contacted has its reason in `not_contacted`:
    unspecified, this-network, multicast or broadcast; an IPv6 link-local address ("needs a zone",
    so a zoned input such as `fe80::1%eth0` is reported, never contacted); a non-public address that
    only public DNS gave ("non-public address from public DNS"); shared provider infrastructure
    (`shared provider infrastructure (<provider>, <class>)`: a CDN, SaaS, WAF or shared-hosting
    provider or one of the built-in provider ranges, but not a hyperscaler, which DigitalOcean and
    IBM Cloud count as); and an address whose owner could not be found (`owner unknown: cymru
    <code>`), as nothing can say whether it is shared.
  - **Results are not failures.** No answer, not TLS and a reset are recorded as results. An error of
    nyx's own that stops a connection from being made is a `probe` failure, `NETWORK_ERROR`,
    transient.
- **`--json`** prints one compact object,
  `{"data":[…],"meta":{"count":n,"errors":[…],"warnings":[…],"hint":null}}`. `count` is the number of
  records. `meta.errors` and `meta.warnings` are always present, `[]` when there are none, and
  `meta.hint` is always `null`. Each `meta.errors` entry has the five keys of the error (see
  [Errors](exit-codes.md#errors)), with `input` mapping `input` to the inputs as given and, for an error of one
  address, `address` to that address. Text from third parties and the target is written sanitised.
- **Without `--json`** each record is laid out for reading, as [Terminal layout](console-and-json.md#terminal-layout)
  describes, and records are separated by a blank line. One `error: <input>: <message> (<CODE>)` line
  for each failure follows the records, and each warning is a `WARN` line on stderr.
- **Contact.** `nyx ip` keeps no state and writes no files, so a call gives the same result for the
  same answers, and a crash leaves nothing behind.

**The outcome** of a call depends on how many of its inputs succeeded. An input succeeds when it is
valid, resolves (for a hostname), and every address it gives is a success. An address is a success
when every source it needed answered, and a non-public address is always one. A source that failed
for want of its quota never counts against it: the failure is in the record and the warning, and
nowhere else. An address for which none of the sources it needed answered is a failed input, with the
failures' error code, and has no record. The snapshot of abusive networks is a source that always answers (see [Abusive networks](abusive-networks.md)), so while `abusive_networks` is selected, which it is by default, an address always has its record, and one whose every other source failed is a partial result (exit 7) and not a failed input. Selecting keys that leave it out (`--fields`) restores the rule.

| Outcome | Exit | stdout |
|---|---|---|
| Every input succeeded | 0 | The records |
| At least one record, and anything failed | 7 | The records and the failures |
| No record, every input failed with one error code | That code's: 1 for `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED` or `UPSTREAM_ERROR`, 2 when all are `INVALID_INPUT`, 3 when all are `NOT_FOUND` | Empty |
| No record, with different codes | 7 | The failures |

On exit 7 the `PARTIAL` error counts what succeeded and what did not, its `input` lists what failed
as given, and it is transient when any failure it counts is. Its hint is the command, with the flags
you gave, that retries the failing addresses themselves, not the CIDR or hostname that gave them,
after the longest known wait. It lists only failures worth retrying, and leaves out quota failures.
Past 20 it points at `meta.errors` instead. A signal ends the call with the exit code every command
uses, and an empty stdout.
