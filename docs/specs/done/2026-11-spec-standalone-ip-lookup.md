# Spec: standalone IP lookup

## Goal

Given one or more IP addresses, or hostnames or CIDRs that stand for addresses, `nyx ip` returns
who runs each address, where it is, what it is called and what is known to be exposed on it: a
readable record per address for a person, or one JSON envelope for an agent. This is so that an
address seen in a log or an alert can be triaged in seconds without starting an engagement. For one
public address in the default mode the call returns within six seconds on a working connection. It
needs no engagement and no key, and by default it sends nothing to the address.

## Behaviours

- **B1 Inputs.** `nyx ip <input>...` takes IPv4 and IPv6 addresses, hostnames and CIDRs as
  arguments, or a lone `-` to read them from stdin, one per line, with blank lines ignored and
  surrounding whitespace trimmed. A bare `nyx ip`, a `-` alongside other arguments, or a `-` with no
  inputs on stdin exits 2. A stdin not closed by the deadline is `TIMEOUT`. The command needs no
  engagement and no acknowledgement, writes no files, and takes no `--config`: no settings apply to
  it.
- **B2 Hostnames and invalid inputs.** A hostname is a name of two or more labels that parses as a
  domain name and is not all digits and dots. Under `--active` a single-label name (such as
  `intranet`) is also a hostname. Without `--active` it is `INVALID_INPUT`, and the hint says to add
  `--active`. An input that is not an address, CIDR or hostname is an `INVALID_INPUT` entry, and the
  other inputs are still looked up. That includes a URL or a `host:port`, whose hint gives the bare
  host. When the call exits 2, every `INVALID_INPUT` problem is reported together. (amended by D6)
- **B3 Resolving hostnames.** A hostname is resolved (A and AAAA) through the public resolvers.
  Under `--active`, a name the public resolvers do not know is tried again through this machine's
  resolver. A single-label name is resolved only through this machine's resolver and is never sent
  to a public resolver. Each address a hostname gives has a record. Only NXDOMAIN, or no A and no
  AAAA records, is a `NOT_FOUND` entry. A resolver failure is `NETWORK_ERROR` or `TIMEOUT`, marked
  transient. (amended by D6)
- **B4 CIDRs.** A CIDR's host bits are masked, and it expands to every address it contains. Its
  first and last addresses are ordinary addresses.
- **B5 One record per address.** Each distinct address gets one record, at its first appearance and
  in canonical form, listing every input hostname that gave it. An IPv4-mapped IPv6 address is the
  IPv4 address. A CIDR's addresses come in address order. A hostname's addresses come IPv4 first,
  then IPv6, each in address order.
- **B6 Cap.** A call holds at most 256 distinct addresses. When literal addresses and CIDRs alone
  pass 256, the call exits 2 before any request. Addresses from hostnames count once the hostnames
  resolve: when the total passes 256, the call exits 2 having sent only those DNS lookups.
- **B7 Non-public addresses.**
  - An address is non-public when IANA's special-purpose address registries mark it globally
    reachable `False` or `N/A`.
  - Its record names its kind. The README lists the kind names (private, ULA, loopback, link-local,
    CGNAT, multicast, unspecified, broadcast, documentation, reserved and so on). "Broadcast" means
    255.255.255.255 only.
  - Such an address is sent to no third party and to no public DNS resolver. Without `--active` no
    PTR lookup is made for it. Under `--active` its PTR is looked up through this machine's resolver
    only. The README says that this resolver may itself forward the query to a public resolver,
    which nyx cannot see. Its record has every selected key, `null` or `[]`. It counts as a success
    and has no source failures, except a failure of that local PTR lookup. (amended by D7, D22)
- **B8 The record of a public address.** It has:
  - network owner: ASN, AS name and announced prefix;
  - registrant (RDAP): registered netblock, registrant organisation and registry;
  - PTR names;
  - shared cloud or CDN provider, decided from nyx's built-in provider data and the address's ASN.
    No provider range lists are downloaded, so the answer can differ from recon's;
  - approximate geolocation (country and city) from RIPEstat's MaxMind GeoLite data, named and
    credited in the README (amended by D1);
  - InternetDB exposure: open ports, hostnames, tags, CPEs and CVE IDs;
  - HackerTarget reverse-IP hostnames: the first 100 names, plus the total count. HackerTarget is not
    asked for an IPv6 address or for a shared provider address. Their value is `null`, and that is
    not a failure (amended by D3);
  - the source failures: each source that failed, timed out, was rate-limited, or was not asked
    because its quota was spent, with the reason. A quota failure is marked as one (amended by D18).

  Every record, public or not, has the address kind (`public` or a non-public kind). The record's
  keys and their order are listed in the README and are a stable interface. A single value that is
  unknown is `null`, and a list with no entries is `[]`. A source that answers that it knows nothing
  about the address (a 404 or an empty answer) has answered, and its keys are empty. A value from a
  source that failed is `null`.
- **B9 Default contact.** By default only third parties and DNS resolvers are contacted, and the
  README names every host. The address itself receives nothing.
- **B10 `--active`.**
  - **Confirmation.** Passing `--active` is the confirmation: no acknowledgement is needed, and the
    README says the acknowledgement applies to recon only.
  - **Which addresses.**
    - `--active` contacts every public address that is not shared provider infrastructure. Shared
      means a CDN, SaaS, WAF or shared-hosting provider, or a built-in provider range. A cloud
      (hyperscaler) address is not shared and is contacted.
    - It also contacts every non-public address except:
      - an unspecified, this-network, multicast or broadcast address;
      - an IPv6 link-local address, which needs a zone to be dialled;
      - one that only the public resolvers gave for a hostname. It is contacted only when it was
        given as a literal or in a CIDR, or this machine's resolver gave it.
    - A non-public address is still sent to no third party.

    (amended by D2, D4, D16)
  - **Shared check.** Whether a public address is shared is always worked out under `--active`,
    whatever `--fields` selects. A public address whose owner could not be found (its source failed
    or timed out) is not contacted. A record that was not contacted says so and why.
  - **For each address it contacts, nyx:**
    - makes a TCP handshake to the ports InternetDB reported (at most 64 beyond the built-in list,
      lowest first) plus a built-in short list of common ports, named in the README. It reads the
      unprompted banner and sends nothing. Each port is open, closed, no answer, or not probed when
      the deadline came first (amended by D16);
    - on each built-in TLS port (named in the README) that is open, makes a second connection with
      a TLS handshake once per input hostname that gave the address, with that hostname as the
      server name, or once with no server name when there is none. It records the certificate's
      names, issuer and expiry, neither trusting nor rejecting the certificate. (amended by D5, D9)
    - on each built-in web port (named in the README) that is open, sends `GET /` once per input
      hostname that gave the address, with that hostname as the Host, or once with the address as
      the Host when there is none. The request goes over HTTPS when the port is also a TLS port and
      over HTTP otherwise. It records the status, the `Server` header and the page title. A redirect
      is reported, not followed. (amended by D5)
  - **Probe outcomes.** A probe's outcome (no answer, not TLS, reset) is recorded as a result, never
    as a source failure.
  - **InternetDB ports.** Unlike recon, `--active` connects to ports that InternetDB reports, and
    the README says so.
  - **Keys.** The keys these checks add appear only under `--active`.
- **B11 Time.**
  - The sources for an address are asked concurrently, and each source is paced (the README names
    each pace).
  - `--timeout` sets the deadline for the whole call. By default the deadline is six seconds for one
    address in the default mode and grows with the number of addresses, by a rule the README gives.
    `--active` has its own, longer default.
  - While stdin is read, the one-address default applies. Once the inputs are read, a provisional
    default comes from the number of inputs: each hostname counts as one address and each CIDR as
    its size. Once hostnames resolve, the default is fixed from the number of addresses. (amended
    by D20)
  - A source that has not answered by the deadline is a timed-out failure in the record.
  - Once HackerTarget's quota is spent, it is not asked again in the call, and one warning says so
    and that the quota resets daily. Each address not yet asked records a HackerTarget failure
    marked as quota.
- **B12 Outcome.**
  - **Success.** An address is a success when every source it needed answered, and a non-public
    address is a success. A quota failure never counts against success: it is listed in the record
    and in the warning, and nowhere else. An address for which none of its needed sources answered
    (quota failures aside) is a failed input with the failures' error code, not a record. An input
    succeeds when it is valid, resolves (for a hostname), and every address it gives is a success.
    (amended by D8)
  - **Exit 0.** The call exits 0 only when every input succeeds.
  - **Exit 7.** When at least one record is returned and anything failed, the call exits 7 with
    `PARTIAL`. Its hint is the command, with the flags given, to retry the failing addresses
    themselves, not the CIDR or hostname that gave them. It includes only failures worth retrying
    and leaves out quota failures. The error is transient when any of those failures is.
  - **No record.** When no record is returned and every input failed with one error code, the call
    exits with that code's exit code (1 for `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED` or
    `UPSTREAM_ERROR`, 2 when all are `INVALID_INPUT`, 3 when all are `NOT_FOUND`), and stdout is
    empty. With mixed codes it exits 7.
  - **Signals.** A signal ends the call with the exit code every command uses.
- **B13 `--fields`.**
  - `--fields a,b,c` returns only those keys, plus the address, the input hostnames that gave it,
    the address kind and the source failures, which are always present (`[]` when there are no
    failures).
  - `all` returns every key the mode allows, and `--fields ""` returns only the keys that are
    always present.
  - An unknown name exits 2 with the valid names in the hint, and so does naming an `--active` key
    without `--active`.
  - Only the sources the selected keys need are asked, along with the sources those depend on: the
    provider needs the ASN, HackerTarget needs the provider, and active probing needs the provider
    and InternetDB's ports. (amended by D3)
  - Without `--fields`, every key is returned.
- **B14 `--json`.** It prints one compact `{"data":[…],"meta":{"count","errors","warnings","hint"}}`
  envelope. Every `meta` key is always present: `[]` when there are no errors or warnings, and
  `null` when there is no hint. `meta.hint` is `null` in every case this spec defines. `count` is
  the number of records. Each error entry has the five keys of the error, and its `input` maps a key
  the README names to the inputs as given.
- **B15 Human mode.** Each address gets one record: a header with the address and its input
  hostnames, then a labelled section per category, laid out as in "Terminal layout". Third-party
  and target text is sanitised. As in `nyx cve`, `error:` lines follow the records and `WARN` lines
  go to stderr.
- **B16 Help and README.** The root help lists `ip` with an example and its flags, and `nyx help
  ip` is the full help. The README's Commands, Passive boundary, Authorisation acknowledgement,
  Console and JSON, Exit codes, Errors ("What stays stable": the `nyx ip` record and envelope keys)
  and Terminal layout sections describe `nyx ip`. Recon and `nyx cve` behave as before.

## Out of scope

- Keyed sources (Shodan host, SecurityTrails): `nyx ip` uses unkeyed sources only, plus HackerTarget.
- Settings and `--config`: the port lists and paces are built in.
- Downloading provider range lists: the provider answer comes from built-in data and the ASN.
- A six-second promise for batches or for `--active`: only one public address in the default mode
  is promised six seconds.
- Contacting shared provider infrastructure under `--active`.
- TLS handshakes on ports other than the built-in TLS ports. InternetDB's tags describe an address,
  not a port, so they name no TLS ports (D9).
- A region in the geolocation: no unkeyed source whose terms allow this use gives one (D1).
- Rejecting internal addresses: they are reported, never sent to a third party.
- Storing results in an engagement or writing files.
- Zoned IPv6 link-local inputs (`fe80::1%eth0`): such an address is reported, never contacted (D16).

# Design

## External facts

- **InternetDB** (*confirmed live*):
  - `GET https://internetdb.shodan.io/<ip>` returns 200 with
    `{"cpes":[],"hostnames":[],"ip":"…","ports":[…],"tags":[],"vulns":[]}`. It took about 0.25 s.
  - An address it has no data on gets 404 with `{"detail":"No information available"}`.
  - IPv6 works, with the same shape.
  - Tags describe the whole address (`cloud`, `cdn`, `pqc`, `vpn` …), never a port.
- **InternetDB limits** (*from docs*: community reports, no official number):
  - The limit is per client address. Going over it gives 429 with a `Retry-After` of about an hour,
    after a few dozen to about 600 requests in a burst. Projects pace at 1/s.
  - The free API is for non-commercial use.
- **RIPEstat geolocation** (*confirmed live*):
  - `GET https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=<ip>&sourceapp=nyx`
    returns `data.located_resources[0].locations[]`, each
    `{country, city, resources:[prefix], covered_percentage}`.
  - `country` is `"?"` when unknown, and `city` is often `""`. There is no region.
  - It took about 1.0 s.
  - Shape: `status` is `"ok"`, with `status_code` 200.
- **RIPEstat terms** (*from docs*):
  - The service is for "network analysis, network monitoring and debugging and research" (Art. 3.1).
    Paid products need written permission.
  - Published results credit the RIPE NCC and the data source.
  - No hard request limit, but register beyond 1000 requests a day, and at most 8 concurrent
    requests per client address.
- **HackerTarget** (*confirmed live*):
  - `GET https://api.hackertarget.com/reverseiplookup/?q=<ipv4>` returns `text/plain`, one name per
    line. For 1.1.1.1 that was about 11 KB.
  - The headers carry `X-API-Quota: 21` and `X-API-Count: 0`.
- **HackerTarget quota** (*from codebase*, `internal/stages/httpsrc/httpsrc.go`):
  - A spent quota is a 200 whose text starts `API count exceeded`, or a 429.
  - The "no records" replies are empty answers.
- **HackerTarget daily allowance** (*assumed*): about 20 lookups a day, read from `X-API-Quota`.
  The design doesn't depend on the number.
- **Team Cymru** (*from codebase*, `internal/stages/dns/ipowner.go`): TXT
  `<rev>.origin.asn.cymru.com` (and `origin6`) answers `"ASN | prefix | CC | rir | date"`, and
  `AS<n>.asn.cymru.com` answers `"ASN | CC | rir | date | NAME, CC"`. Both go through the public
  resolvers.
- **RDAP** (*from codebase*, `internal/stages/rdap/rdap.go`): the IANA bootstrap at
  `data.iana.org/rdap/ipv{4,6}.json`, then the five RIR hosts, following referrals by hand (up to 3).
  A 404 means nothing is registered.
- **IANA special-purpose registries** (*confirmed live*, `iana-ipv{4,6}-special-registry-1.csv`):
  - Each row has a "Globally Reachable" column of `True`, `False` or `N/A`.
  - Some rows are footnoted (`False [1]`), and a terminated row (`192.88.99.0/24`) has empty columns.
  - A more specific row can differ from its parent: 192.0.0.0/24 is `False`, but 192.0.0.9/32 is
    `True`.
  - Teredo (2001::/32) and 6to4 (2002::/16) are `N/A`, and 64:ff9b::/96 is `True`.
  - Multicast (224.0.0.0/4, ff00::/8) is not in these registries; it has registries of its own.
- **Rejected geolocation sources** (*from docs*):
  - DB-IP's free API: 500 requests a day, and its terms don't cover API use.
  - ipwho.is: non-commercial use only.
- **Go's resolver with `CGO_ENABLED=0`** (*from docs*):
  - On Linux, `net.DefaultResolver` uses the pure-Go resolver, which reads `/etc/hosts`,
    `/etc/resolv.conf` and its search domains.
  - On macOS it calls the system resolver through libSystem.
  - `net.Resolver{PreferGo: true, Dial: …}` can point it at a test server.
- **The HTTPS GET exposes the chain** (*from codebase*): with `InsecureSkipVerify`, Go's TLS client
  returns the presented chain in `ConnectionState.PeerCertificates` (`internal/egress/http.go`).

## Decisions

**User decisions**

- **D1 Geolocation is RIPEstat `maxmind-geo-lite`.** It fills `geo_country` and `geo_city`, and
  there is no region. A country of `?` or `""` and a city of `""` are `null`. With several locations,
  the one with the highest `covered_percentage` is used.
  - The README names the source and credits the RIPE NCC and MaxMind GeoLite.
  - It is not cached, since a /24 at 4/s fits the deadline.
  - Why: it is the only unkeyed source whose terms fit "network analysis and debugging", and nyx
    already uses RIPEstat.
- **D2 What "shared" means for `nyx ip`.**
  - Shared is `provider.Classify(addr, owner, nil)` with `Shared` true and a class other than
    `hyperscaler`. That covers the `cdn`, `saas`, `waf` and `shared-hosting` classes and the static
    ranges.
  - The predicate is `provider.Result.SharedInfrastructure()` in `internal/provider`, with
    constants `ClassHyperscaler` and `ClassSharedHosting`.
  - DigitalOcean (AS14061) and SoftLayer (AS36351) move to class `hyperscaler` in `providers.yaml`.
    Recon's shared decisions don't change: nothing branches on those two class strings, and its
    `Shared` value comes from the range rules or the ASN, not the class.
  - HackerTarget and `--active` both use this one predicate.
  - Why: the user chose to contact cloud VMs, and also to treat DigitalOcean and IBM Cloud as cloud.
- **D3 HackerTarget.**
  - Not asked for a shared address (D2) or an IPv6 address. Both give `null`, not a failure.
  - Names are cleaned with the same rule as recon (`reverseLines`), deduplicated and sorted.
    `reverse_ip` holds the first 100, and `reverse_ip_count` the total.
  - Because the shared check needs the ASN, HackerTarget waits for Cymru.
  - Why: the quota is small, and a CDN address returns thousands of meaningless names.
- **D4 Non-public addresses from public DNS are not contacted.** Each address records how it was
  found: as a literal, in a CIDR, from public DNS or from the local resolver. Under `--active`, a
  non-public address found only through public DNS gets `not_contacted` set to "non-public address
  from public DNS". Why: a hostile name could otherwise point the probes at the operator's own
  machine or cloud metadata service.
- **D5 TLS and GET once per hostname.** The TLS handshake and the `GET /` run once per
  (input hostname, port) for every input hostname that gave the address, or once with none (or
  with the address as the Host). The TCP scan runs once per address. Why: virtual hosts and SNI.
- **D6 Single-label names under `--active` only.**
  - They are resolved only through this machine's resolver.
  - Without `--active` they are `INVALID_INPUT`, with the hint "add --active to resolve
    single-label names through this machine's resolver".
- **D7 Under `--active`, a non-public address gets a PTR lookup through this machine's resolver.**
  Its failure is a `ptr` source failure.
- **D8 Quota failures never count against success.**
  - They are listed in the record's `failures` with `quota: true`, and in the one warning.
  - The outcome rules ignore them entirely: for success, for the none-answered rule, for the exit
    code and for the retry hint.
- **D9 TLS handshakes only on the built-in TLS ports.** InternetDB has no per-port tags.
- **D20 Provisional deadline once stdin closes** (rule in D12).
- **D22 Local resolver disclosure.** The README says the `--active` local lookups go wherever this
  machine's resolver sends them, which can be a public resolver.

**Technical decisions**

- **D10 Address kinds: new pure package `internal/addrkind`.**
  - A hand-written table from the two IANA special-purpose registries, with a comment naming the
    registry file and the date it was read.
  - The longest prefix wins. `False` and `N/A` mean non-public, so 6to4 and Teredo are non-public,
    as B7's rule says. Terminated rows are left out. Addresses are unmapped first.
  - Multicast (224.0.0.0/4, ff00::/8) comes from the multicast registries.
  - IPv6 outside 2000::/3 that no row lists is `reserved`. That comes from IANA's IPv6 Address
    Space registry, a different registry, and the README says so.
  - API: `func Of(a netip.Addr) Kind`, where `Kind` is a string and `Public` is `"public"`.
  - Kind names:
    - `public`, `private`, `cgnat`, `loopback`, `link-local`, `ula`, `multicast`;
    - `unspecified` (0.0.0.0/32, ::/128), `this-network` (the rest of 0.0.0.0/8);
    - `broadcast` (255.255.255.255/32), `documentation`, `benchmarking`;
    - `reserved` (240.0.0.0/4 less broadcast, unlisted non-2000::/3 IPv6), `ietf-protocol`;
    - `6to4`, `teredo`, `nat64-local` (64:ff9b:1::/48), `discard` (100::/64), `dummy`, `srv6`,
      `nat64-discovery`, `ipv4-mapped`.
  - 64:ff9b::/96 is `True`, and stays public.
  - Why: no such table exists, and `netip`'s helpers don't follow the registry.
- **D11 Source code extracted into one run-free package, `internal/ipsource`.**
  - It holds:
    - Cymru: `Origin(ctx, egress.Resolver, addr) (Owner{ASN, Prefix}, found bool, err error)` and
      `ASName(ctx, egress.Resolver, asn)`, with the TXT parsing;
    - the RDAP IP lookup: a `Bootstrap` cache the caller owns, `Lookup(ctx, egress.ThirdPartyHTTP,
      *Bootstrap, addr, warn func(string)) (Registration, found bool, err error)`, with
      `Registration{Start, End, Registrant, Registry, Handle}`, plus the referral following and the
      registry table;
    - the HackerTarget reply rules: `HackerTargetLines(body) (lines []string, quota bool)` and
      `ReverseNames`.
  - It returns its own `ErrQuota` sentinel. The stages wrap it into `run.ErrQuota`.
  - `stages/dns/ipowner.go`, `stages/rdap/rdap.go` (whose run state keeps the found-range skip and
    holds the `Bootstrap`), `stages/httpsrc` and `stages/reverseip` switch to it.
  - It lands as its own `refactor:` commit with the recon tests unchanged.
  - Why: `httpsrc` and the stages import `internal/run`, which a standalone command shouldn't need.
    One package rather than three tiny ones.
- **D12 Deadline rule.**
  - Default mode: 6 s + 1.25 s × (addresses − 1). `--active`: 30 s + 2 s × (addresses − 1).
  - While stdin is read, the one-address value (6 s or 30 s) applies from the start of the call.
  - Once stdin closes (or with arguments), the provisional deadline is the start of the call plus
    the rule for the input count: a hostname counts as 1, a literal as 1, a CIDR as its size.
  - Once hostnames resolve, it is the start of the call plus the rule for the distinct address
    count.
  - `--timeout` replaces all of this.
  - The rule is a pure function in `internal/iplookup/deadline.go`.
  - Why: InternetDB's 1/s pace dominates a batch, and RDAP at 1/s per registry fits inside it.
- **D13 Egress for the sources.**
  - One `egress.New` for DNS and the third parties, with no Policy (as `nvdHTTP` in
    `internal/cli/cve.go` does). It is built from `d.Egress` so the test hooks apply.
  - `nyx ip` sets its own values only where the base options are zero: DNSTimeout 2 s,
    ConnectTimeout 3 s, BannerWait 2 s, HTTPTimeout 5 s, RatePerHost 10/s.
  - New `Options.SourceRates map[string]float64` sets a pace per source pattern, overriding
    `RatePerSource`:
    - `internetdb.shodan.io` 1/s, `api.hackertarget.com` 1/s, `stat.ripe.net` 4/s;
    - `data.iana.org` and each RDAP registry host at the default 1/s.
  - DNS uses egress's 50/s limiter.
  - Sources: `internetdb.shodan.io`, `stat.ripe.net`, `api.hackertarget.com`, `data.iana.org` and
    the five RDAP registry hosts.
  - Why: egress already paces per source pattern, so this reuses it. A Policy installed on this
    Egress would refuse source hosts under an input hostname.
- **D14 Rate limits and latches.**
  - A 429 from InternetDB, from RIPEstat or from one RDAP host is `RATE_LIMITED`, transient. That
    source is not asked again in the call: for RDAP, that host only.
  - Each address not yet asked records `RATE_LIMITED`, transient, with "not asked: rate-limited
    earlier in this call". One warning is given per latched source.
  - HackerTarget's quota (429 or `API count exceeded`) latches the same way, but its failures are
    `RATE_LIMITED`, `quota: true`, not transient. The warning says the quota resets daily.
  - Other mappings:
    - transport error: `NETWORK_ERROR`, transient;
    - another non-2xx status, or an unreadable or truncated body: `UPSTREAM_ERROR`, transient;
    - the call deadline: `TIMEOUT`, transient;
    - SERVFAIL, or no response from any public resolver: `NETWORK_ERROR`, transient.
  - Cymru NXDOMAIN or an empty answer means it answered and knows nothing. An unknown owner is not
    a failure, and per B10 it is contacted.
- **D15 Active probing: one target Egress per contacted address, through a probe-only
  constructor.**
  - New `egress.NewProbe(o Options, p *Policy) Probe`, where `Probe{TCP TargetTCP; HTTP TargetHTTP;
    TLS TargetTLS}`. `Clients` is unchanged, so recon stages never get a TLS handshake.
  - Each address's Policy:
    - `Scope: scope.New(scope.Config{Roots, Netblocks, Resolutions})`, where Roots are its input
      hostnames, Netblocks the address as /32 or /128, and Resolutions each hostname → [address];
    - `Resolutions`, the same map, on the Policy too (`vetted` reads `Policy.Resolutions`);
    - `Ack: true` and `Passive: false`;
    - `Ports`: that address's probe ports only;
    - `Shared: nil`.
  - TCP goes through `Probe.TCP.Connect`. A GET goes through `egress.RootAt(host, scheme, port,
    addr)`, or `egress.Root(addr.String(), scheme, port)` when there is no hostname.
  - New `TargetTLS.Handshake(ctx, addr, port, serverName) (TLSResult, error)` in
    `internal/egress/tls.go`:
    - the same gates as `targetTCP.Connect` (target refusal, port allowed, port eligible, host
      limiter);
    - it completes a handshake with `targetTLSConfig(serverName)`, sends no application data, and
      closes;
    - results: `TLSCert{Names (DNS and IP SANs), Issuer, NotAfter, Version}`,
      `NoService{Reason: timeout|refused|tls-failed|other}` or `Refused`;
    - a local failure is an error.
  - CLAUDE.md's passive-boundary invariant and the README's Passive boundary gain: "`nyx ip
    --active` also completes TLS handshakes".
  - Why: each Policy holds exactly one address and its own ports, with no shared state and no
    `SetPolicy` races, and the existing egress gates enforce the passive boundary.
- **D16 Probe plan per address.**
  - Built-in common ports: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 853, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443,
    8888, 9200, 9443, 11211, 27017.
  - Plus InternetDB's ports not in that list, lowest first, at most 64.
  - TLS ports: 443, 465, 636, 853, 993, 995, 8443, 9443.
  - Web ports: 80, 443, 8000, 8080, 8443, 8888, 9443. HTTPS when the port is also a TLS port.
  - TCP first, all ports concurrently, behind the host limiter. Then TLS on the open TLS ports, then
    GET on the open web ports.
  - Port states: `open`, `closed`, `no-answer`, `not-probed` (the deadline came first).
  - TLS and web outcomes: `ok`, `no-answer`, `refused`, `not-tls`, `reset`, `not-probed`.
  - A local failure (an egress error) is a source failure with source `probe`, `NETWORK_ERROR`,
    transient.
  - Never contacted, with `not_contacted` saying why:
    - `unspecified`, `this-network`, `multicast` or `broadcast`;
    - an IPv6 `link-local` address ("needs a zone");
    - D4's case;
    - a shared address ("shared provider infrastructure (<provider>, <class>)");
    - an owner lookup that failed ("owner unknown: cymru <code>").
- **D17 Record keys, in this order** (a stable interface; the table is in
  `internal/iplookup/fields.go`, modelled on `internal/cve/fields.go`):
  - Always: `address`, `hostnames`, `kind`.
  - Default-mode keys:
    - `asn`, `as_name`, `as_prefix` (Cymru);
    - `rdap_netblock` (the CIDR when the range is exactly one, otherwise `start-end`),
      `rdap_org`, `rdap_registry` (RDAP);
    - `ptr` (DNS);
    - `provider`, `provider_class` (Cymru + `provider`);
    - `geo_country`, `geo_city` (RIPEstat);
    - `internetdb_ports`, `internetdb_hostnames`, `internetdb_tags`, `internetdb_cpes`,
      `internetdb_vulns` (InternetDB);
    - `reverse_ip`, `reverse_ip_count` (HackerTarget + Cymru).
  - `--active` only:
    - `not_contacted` (reason or `null`);
    - `ports` `[{port, state, banner}]`;
    - `tls` `[{port, server_name, outcome, names, issuer, expiry}]`;
    - `web` `[{port, scheme, host, outcome, status, server, title, location}]`.
  - Always last: `failures` `[{source, code, message, transient, quota}]`.
  - Source names: `cymru`, `rdap`, `ptr`, `ripestat`, `internetdb`, `hackertarget`, `probe`.
  - Dependencies:
    - any active key needs Cymru, and needs InternetDB unless only `not_contacted` is selected;
    - `ports` alone skips TLS and GET;
    - `tls` and `web` need the TCP scan.
  - Text values:
    - `banner` is the unprompted bytes as text, with invalid UTF-8 replaced and at most 1024 bytes;
    - `expiry` is `YYYY-MM-DD`, in UTC;
    - `title` uses recon's title rule, moved to an exported pure helper (D21).
- **D18 Failure entries** are `{source, code, message, transient, quota}`. `quota` is true only for
  HackerTarget's spent quota.
- **D19 Outcome logic shared with `nyx cve`.**
  - The generic part of `internal/cve/outcome.go` moves into a new package, `internal/batch`:
    - the one-code rule and its message;
    - the PARTIAL message, its `Targets` and its transient flag;
    - `retryHint` with its wait, the `--timeout` hint and `maxListed = 20`.
  - It is parametrised by the noun ("IDs", "inputs") and a hint function. `cve.Outcome` becomes a
    thin wrapper, and its tests stay unchanged.
  - `iplookup.Outcome` uses it. The units are:
    - failed inputs: invalid, `NOT_FOUND`, a resolver failure;
    - failed addresses: none of the needed sources answered.
  - A failed address's code is that of its first failing source, in the source order of D17.
  - The retry items are the failed addresses, plus hostnames whose resolution failed transiently.
    For any address that has a transient failure, the hint lists the address.
  - `meta.errors[].input` is `{"input": [inputs as given]}`. For an address failure it also has
    `"address": "<address>"`.
- **D21 Pure helpers.**
  - `input.ParseHostname(s, singleLabel bool)` shares its checks with `ParseDomain` through one
    unexported function with options. The hostname form allows public suffixes and needs two labels
    unless `singleLabel` is set.
  - `input.BareHost(s) (host string, ok bool)` recognises a URL, `host:port` or `[v6]:port`, for the
    hint.
  - The page title (`stages/web/html.go` `title`) moves to an exported pure function in a new
    package, `internal/webpage`, which the web stage calls.
- **D23 Local resolver in egress.**
  - `(*Egress).Local() LocalResolver`, with `Addrs(ctx, name) ([]netip.Addr, error)` and
    `PTR(ctx, addr) ([]string, error)`; an empty answer with no error is "not found".
  - A timeout is `egress.ErrLocalTimeout`; any other failure is an error.
  - Test hook `Options.LocalResolverAddr`: a PreferGo resolver dialling that address.
  - A single-label name is sent only here. Under `--active`, a two-label name goes here only after
    the public resolvers say NXDOMAIN or give no addresses.
- **D24 Command.**
  - In `internal/cli/ip.go`: `newIPCommand(inv)`, registered in `internal/cli/help.go`, with an
    `Example` and help annotations.
  - Flags: `--active`, `--fields`, `--timeout` and `-h`. No `--config`, and no `NYX_*` settings are
    read.
  - stdin is read through `readIDs`, made generic (`readLines(ctx, r, noun)`) so that the cve
    messages stay byte-for-byte the same.
  - Validation collects every problem into `clierr.Problems` before any request: inputs, fields,
    timeout, the literal cap, active keys without `--active`.
  - Signals behave as in `runCVE`: `ctx.Err()` returns the cause and writes nothing.
  - The envelope is `{data, meta{count, errors, warnings, hint}}`, with `hint` always `null`.
- **D25 Package `internal/iplookup`.** Files:
  - `doc.go`, which defines the terms address kind, source, source failure, record and contacted;
  - `inputs.go` (parse, expand, dedupe, order, cap);
  - `sources.go` (the per-address source fan-out, the latches, the AS-name and RDAP-bootstrap
    caches only);
  - `active.go` (the contact decision, the per-address Policy, the probes);
  - `record.go`, `fields.go`, `outcome.go`, `render.go`, `deadline.go`.
  - Concurrency: 32 addresses at a time in default mode, 16 under `--active`. Each address's
    sources run concurrently, behind their egress paces.
  - There are no per-prefix caches: Cymru and RDAP answer for the most specific route or
    registration, so a neighbour's answer can be wrong.
- **D26 Human render** (`internal/iplookup/render.go`), modelled on `internal/cve/render.go`.
  - It takes a `layout.Stream`.
  - The header line is the address, its input hostnames and its kind.
  - Then labelled sections: Owner, Registration, Names, Provider, Location, Exposure, Reverse IP,
    Not contacted, Ports, TLS, Web, Failures.
  - A section with no selected key is left out. A selected but empty value shows `none`.
  - Every third-party and target string goes through `sanitize.Text`.

**Critic findings dropped**

- Getting the certificate from the HTTPS GET on 443, 8443 and 9443 instead of a separate handshake.
  It would tie the TLS result to the GET succeeding, and the cost is one connection.
- Embedding an IANA RDAP bootstrap snapshot. The fetch is about 0.3 s, well inside 6 s, and a
  snapshot would need a refresh job.

## Files

- `internal/addrkind/addrkind.go`, `addrkind_test.go`: new (D10).
- `internal/ipsource/cymru.go`, `rdap.go`, `hackertarget.go` and their tests: new (D11).
- `internal/stages/dns/ipowner.go`, `internal/stages/rdap/rdap.go`,
  `internal/stages/httpsrc/httpsrc.go`, `internal/stages/reverseip/reverseip.go`: delegate to
  `ipsource` (D11).
- `internal/webpage/title.go`: new. `internal/stages/web/html.go` calls it (D21).
- `internal/provider/provider.go` (`SharedInfrastructure`, class constants) and
  `internal/provider/providers.yaml` (DigitalOcean and SoftLayer become `hyperscaler`) (D2).
- `internal/input/input.go`: `ParseHostname`, `BareHost` (D21).
- `internal/egress/egress.go`: `Options.SourceRates`, `Options.LocalResolverAddr`, `NewProbe`
  and `Probe` (D13, D15, D23).
- `internal/egress/tls.go`: `TargetTLS`, `Handshake`, `TLSResult` types (D15).
- `internal/egress/local.go`: new, `LocalResolver` (D23).
- `internal/egress/thirdparty.go`: the source limiter reads `SourceRates` (D13).
- `internal/batch/batch.go`: new. `internal/cve/outcome.go` wraps it (D19).
- `internal/iplookup/*`: new (D25).
- `internal/cli/ip.go`: new. `internal/cli/cve.go` (`readIDs` → `readLines`) and
  `internal/cli/help.go` (registration) (D24).
- `README.md`: Commands, Passive boundary (the hosts, TLS handshakes, InternetDB ports, local
  resolver note), Authorisation acknowledgement (recon only), Console and JSON, Terminal layout,
  Exit codes, Errors ("What stays stable"), and a new "IP lookup" section. The new section covers
  the record keys, the kinds, the sources, their paces and credits, the deadline rule, and the
  port lists.
- `CLAUDE.md`: the passive-boundary invariant names `nyx ip --active`'s TLS handshake. The
  architecture paragraph names `nyx ip` → `internal/iplookup`.

## Tests

Behaviour tests go in `internal/cli/ip_test.go`, through the harness:
- `SourceBaseURLs` point InternetDB, RIPEstat, the RDAP hosts, `data.iana.org` and HackerTarget at
  `httptest` fakes;
- `ResolverAddrs` points at the `egresstest` fake for Cymru, PTR and A/AAAA;
- `LocalResolverAddr` points at a second fake;
- `DialMap` maps probe address:port pairs to loopback TCP, TLS and HTTP servers;
- the harness canaries catch anything unexpected.

Every test calls `t.Parallel()` and uses `h.setenv`. Tests marked **[mutation]** are targets for a
mutation check in `/spec-develop`.

- **B1:**
  - no arguments, `-` with other arguments, and an empty stdin each exit 2;
  - a stdin never closed is `TIMEOUT` at the one-address deadline;
  - blank lines and whitespace are trimmed;
  - `--config` is an unknown flag (exit 2);
  - a `NYX_*` variable changes nothing;
  - no file is written in the working directory or the output directory.
- **B2:**
  - a URL and a `host:port` each give `INVALID_INPUT` with the bare-host hint;
  - an all-digits name is invalid;
  - a single-label name is invalid without `--active` (hint says add `--active`), and resolves
    through the local fake only under `--active` **[mutation]**: the public fake must see no query
    for it;
  - one invalid input among valid ones exits 7 and still returns the others;
  - all invalid inputs exit 2 with every problem listed.
- **B3:**
  - NXDOMAIN and NODATA give `NOT_FOUND`;
  - SERVFAIL gives `NETWORK_ERROR`, transient;
  - a resolver that never answers gives `TIMEOUT`;
  - under `--active` a public NXDOMAIN is retried through the local fake, and without `--active` it
    is not.
- **B4, B5:**
  - a /30 with host bits set expands to 4 addresses in order;
  - a hostname gives IPv4 then IPv6, each sorted;
  - a duplicate across a literal, a CIDR and two hostnames gives one record, at its first
    appearance, listing both hostnames;
  - `::ffff:1.2.3.4` is `1.2.3.4`.
- **B6:**
  - a /23 exits 2 with every canary and fake untouched;
  - hostnames that resolve to more than 256 addresses exit 2, and the fakes saw only DNS.
- **B7** **[mutation]:**
  - 10.0.0.1, 100.64.0.1, fd00::1, 169.254.1.1, 192.0.2.1, 224.0.0.1, 255.255.255.255, 0.0.0.0,
    2002::1 and 2001::1 each name their kind, and no HTTP fake and no public DNS fake sees them (or
    their reverse name);
  - each record has every selected key empty, no failures, and exit 0;
  - under `--active`, the PTR goes to the local fake only.
  - Unit tests in `addrkind` pin each registry row, the longest-prefix overrides (192.0.0.9 public,
    192.0.0.8 non-public) and IPv6 outside 2000::/3.
- **B8:** a full record from all the fakes, with the keys in the README order.
  - Each source is tested with a 404 or empty answer (answered, keys empty), a 429, a 500, a
    malformed or truncated body, and a hang until the deadline (`TIMEOUT`). Each gives its failure
    entry, and only that source's keys are `null`.
  - HackerTarget:
    - an IPv6 address is not asked and gives `null`, with no failure;
    - a shared (Cloudflare ASN) address is not asked;
    - 150 names give 100 plus `reverse_ip_count` 150.
  - Geolocation: `country` of `?` is `null`.
  - The RDAP referral is followed.
  - A source failing for one address in a batch leaves the other addresses whole.
- **B9** **[mutation]:** in default mode the TCP canary and the `DialMap` targets get no connection,
  and every HTTP request went to a named source host.
- **B10:**
  - a dedicated address is probed on the built-in ports and InternetDB's extra ports, capped at 64;
  - a Cloudflare-ASN address is not contacted, with its reason **[mutation]**;
  - an AWS-ASN (hyperscaler) and a DigitalOcean-ASN address are contacted;
  - a Cymru failure means not contacted ("owner unknown");
  - a non-public address that public DNS gave is not contacted **[mutation]**, while the same
    address as a literal is contacted, and one the local fake gave is contacted;
  - 0.0.0.0, 224.0.0.1, 255.255.255.255 and fe80::1 are never dialled **[mutation]**;
  - two hostnames on one address give two TLS entries with the right server names, and two web
    entries with the right Host;
  - a redirect is reported, not followed;
  - a non-TLS server on 443 is `not-tls`, and nothing listening is `closed`;
  - the banner is read and nothing is sent: the fake records zero bytes received;
  - `--fields ports` makes no TLS or GET;
  - active keys are absent without `--active`.
  - Egress unit tests for `Handshake`:
    - refused without Ack, on a port not in the Policy, and on an ineligible address
      **[mutation]**;
    - sends no application data;
    - returns names, issuer and expiry for a self-signed certificate;
    - a deadline in the middle of a handshake is `NoService{timeout}`.
  - Egress unit tests that `Clients` has no TLS client.
  - A probe-local failure (an injected egress error) is a `probe` failure.
- **B11:**
  - unit tests of the deadline rule: 1, 2 and 256 addresses, with and without `--active`, and the
    provisional count for hostnames and CIDRs;
  - InternetDB 429 latches: later addresses aren't asked, record rate-limited, and one warning;
  - an RDAP 429 latches that host only;
  - HackerTarget's `API count exceeded` and its 429 each give one warning with "resets daily", and
    quota failures on the rest;
  - paces: `SourceRates` is honoured, checked with an egress unit test using a fake clock or by
    timing two requests.
- **B12:**
  - all success exits 0;
  - quota failures alone exit 0 **[mutation]**;
  - one failed source exits 7 with the PARTIAL hint naming the failing address (not its CIDR or
    hostname) and the flags given (`--active`, `--fields`, `--timeout`, `--json`), transient;
  - all sources failing for the only address exits 1 with stdout empty;
  - all `NOT_FOUND` exits 3;
  - mixed codes exit 7;
  - more than 20 failing addresses: the hint points at `meta.errors`;
  - a signal in the middle of a lookup exits 130 with stdout empty, and nothing is left running (no
    secret exists to leak).
  - `internal/batch` keeps `nyx cve`'s outcome tests passing unchanged.
- **B13:**
  - `--fields asn` asks only the Cymru fake;
  - `--fields reverse_ip` asks Cymru and HackerTarget;
  - `--fields ""` asks nothing and returns only the always-present keys;
  - `all`;
  - an unknown name, and an active key without `--active`, each exit 2 with the valid names;
  - under `--active`, `--fields geo_country` still runs the shared check.
- **B14:**
  - the envelope's keys and their order are pinned;
  - `meta.hint` is always `null`;
  - every `meta.errors` entry has the five keys, with `input`/`address` as documented;
  - `count`.
- **B15:**
  - a plain golden file (not a terminal) and a terminal layout test, both through `layout.Stream`;
  - hostile text (escape sequences) in a banner, a title and an RDAP org is sanitised;
  - `error:` lines come after the records, and WARN goes to stderr.
- **B16:**
  - the root help lists `ip`, and `nyx help ip` shows the flags, the example and the field names;
  - the recon and `nyx cve` test suites pass unchanged;
  - the refactor commit (D11) passes recon's tests before `nyx ip` lands.

There is no state, so a re-run gives the same result for the same answers. A crash part-way leaves
nothing behind: no files are written and no key is used.

## Conventions

- CLAUDE.md hard invariants:
  - only `internal/egress` does network I/O. `boundary_test.go` covers the new packages
    automatically;
  - the passive boundary, which gains `nyx ip --active`'s TLS handshake (D15);
  - the stable interface (exit codes, error keys, envelope keys) now includes the `nyx ip` record
    and envelope keys.
- Australian English in docs and messages. US spellings are accepted for any input aliases.
- Code, comments, test names and file names never cite spec or decision numbers.
- The tests follow CLAUDE.md's Testing section: `t.Parallel()`, `h.setenv`, the harness canaries,
  no `os.Getenv`.
- Conventional commit prefixes. The D11 extraction lands first, as a `refactor:` commit.

# Implementation

## Develop

Built in layers, each tests-first, and each worker saw its new tests fail on an assertion (against a
stub) before writing code.

- **Pure helpers.** `internal/addrkind` (table written from the two IANA registries), `provider`
  (`SharedInfrastructure`, class constants; DigitalOcean and SoftLayer are `hyperscaler`, and the one
  provider test that pinned DigitalOcean's old class was updated), `input.ParseHostname` and `BareHost`,
  and `internal/webpage` (the page title, which the web stage now calls).
- **Egress.** `Options.SourceRates` (per source pattern, over `RatePerSource`), `Local()` with
  `LocalResolverAddr`, `NewProbe` and `Probe`, `TargetTLS.Handshake` with `TLSResult`. `Clients` is
  unchanged and a test pins that it has no TLS client. A D15-shaped Policy was confirmed to reach the
  loopback servers by hostname and by address without any Policy change.
  `egresstest` replies now set RecursionAvailable, which Go's resolver needs to read an empty NOERROR
  answer as "no addresses".
- **Extraction.** `internal/ipsource` (Cymru, the RDAP lookup with a shared `Bootstrap`, HackerTarget)
  and `internal/batch` (the generic outcome logic; `cve.Outcome` is a thin wrapper). `stages/dns`,
  `stages/rdap`, `stages/httpsrc` and `stages/reverseip` delegate; the recon and `nyx cve` suites pass
  unchanged. The refactor was not a separate commit: nothing has been committed.
- **`internal/iplookup`.** Pure core (inputs, record, field table, deadline, outcome, render) and a
  networked half (`Resolve`, `Lookup`, the sources behind a guard that latches a host on 429, and the
  active probe plan with one `egress.NewProbe` per contacted address).
- **`nyx ip`** (`internal/cli/ip.go`): flags, stdin through `readLines` (shared with `nyx cve`, whose
  messages are byte-for-byte unchanged), the three-phase deadline, one `egress.New` from `Deps.Egress`
  with the paces applied only to source keys the base options leave unset, signals as in `nyx cve`.
- **Docs.** README (Commands, Passive boundary, Authorisation, Console and JSON, Terminal layout, Exit
  codes, Errors and a new "IP lookup" section) and CLAUDE.md.
- **Tests.** About 90 behaviour tests in `internal/cli/ip_test.go`, `ip_active_test.go` and
  `ip_outcome_test.go` through the harness and fakes (`ip_world_test.go`), unit tests in each new
  package, and egress tests for the gates, SNI, "no application data", and the pace.

Deviations from the plan, and facts that differed:
- Decided where B7 and B12 disagreed: a non-public address is always a success. If its local PTR lookup
  fails the record is returned with a `ptr` failure, and the call can still exit 0.
- A dropped DNS query that runs into the call's deadline is `TIMEOUT`; any other resolver failure is
  `NETWORK_ERROR`.
- An answered-empty HackerTarget reply is `reverse_ip` `[]` and `reverse_ip_count` 0.
- `TLSCert.Issuer` is the RFC 2253 distinguished name, `Names` holds only the SANs (no CN), and
  `Handshake` bounds the dial by `ConnectTimeout` and dial plus handshake by `HTTPTimeout`.
- The banner is the unprompted bytes as text, untrimmed (a trailing `\r\n` is kept).
- A PTR name is decoded from DNS presentation form, and one holding a control character is left out.
- A request to a host that goes one at a time (InternetDB, the registries) holds the queue for at most a
  second, so one hanging answer does not make every address behind it time out. A 429 is still seen
  before the next request.
- The failure message of a HackerTarget quota does not say "resets daily"; the warning does.
- The one-line `--fields` help lists every name, as a test requires.

Mutation checks (each break was made by hand, the tests run, and the edit undone by hand; every one
made at least one test fail):
- a single-label name sent to a public resolver: `TestIP_SingleLabelNamesResolveOnlyThroughTheLocalResolver`, `TestResolve_SingleLabelNamesAreNeverSentPublicly`;
- a non-public address asking third parties: `TestIP_DefaultModeNeverContactsTheAddress` and four `TestIPActive_`/`TestIPOutcome_` tests;
- default mode probing: `TestIP_SingleLabelNamesResolveOnlyThroughTheLocalResolver`, `TestIPOutcome_PartialHintRetriesTheFailingAddressesWithTheFlagsGiven` and more;
- a shared address contacted: `TestIPActive_SharedProviderAddressIsNotContacted`;
- a non-public address from public DNS contacted: `TestIPActive_ANonPublicAddressFromPublicDNSIsNotContacted`;
- unspecified, multicast or broadcast, and IPv6 link-local, dialled: `TestIPActive_UnreachableKindsAreNeverDialled`;
- an unknown owner contacted: `TestIPActive_AFailedOwnerLookupMeansNotContacted`;
- quota failures counted against success: `TestIPOutcome_QuotaFailuresAloneExitZero`, `TestIPTime_HackerTargetQuotaLatches`;
- `Handshake` without the authorisation, port or eligibility gate: `TestHandshakeRefusals` and `TestHandshakeRefusalsOpenNoConnection` each time;
- `addrkind` with CGNAT public, or 192.0.0.9 not an override: `TestOf_RegistryRows`, `TestOf_LongestPrefixWins`.
The first run of "a non-public address asking third parties" did not compile (an unused variable), so it was redone with `|| true`.

Existing recon and `nyx cve` tests (`TestKeyed_*`, `TestGitHub_*`, `TestEmailThirdParties_*`,
`TestCVE_Pacing`) fail now and then in a full `internal/cli` run under load. The same tests fail on
the unmodified HEAD (4 failures in 12 runs there), and they pass alone.

## Known limitations

- **Address kinds (B7).** The `addrkind` table was written from knowledge of the registries on
  2026-11-21, with no network access to fetch them. Recent rows (`100:0:0:1::/64`, `3fff::/20`,
  `2001:1::3`) need checking against IANA. `ipv4-mapped` is listed but cannot occur, as addresses are
  unmapped first; the README says so.
- **Zoned IPv6 (B2, out of scope).** `fe80::1%eth0` is accepted with the zone dropped and reported as
  link-local, never contacted.
- **Probe outcomes (B10).** No test injects a local probe failure (there is no portable way), and none
  pins the `not-probed` outcome when the deadline comes first.
- **PARTIAL wording (B12).** An address with one failed source still has a record, so the message can
  read "3 of 3 inputs returned, 1 failed".
- **Render (B15).** A selected key whose source failed shows `unknown`, not `none`.
- **Pace (B11).** Batches are slow on InternetDB and the RDAP hosts, as each goes one request at a
  time at its pace.
- **Timing (B11).** The 6-second promise for one public address is not measured against live sources.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) went over the whole branch. Fixed:
- `batch`: the `TimeoutHint` knob is gone (both callers passed `HintTimeout`), and `nyx cve` uses
  `batch.HintTimeout` and `batch.Seconds` instead of its own copies.
- `cli`: one `lookupEnvelope`/`writeEnvelope` for both `nyx cve` and `nyx ip` (the envelope keys are
  defined once); `cveEnded` is `endedBy`; the unreachable deadline branch after `Resolve` (`ipFailed`)
  is gone; the egress defaults use `cmp.Or`; the `--fields` help line uses
  `iplookup.ChoosableFieldNames` instead of a hard-coded list of always-present keys.
- `iplookup`: `SourceHosts()` and `SourceRates()` own the source hosts and paces that `cli` wrote out
  again; `Config.Active` is gone (it is `Fields.Active()`); `Resolve` and `Plan.Addresses` share one
  address ordering (`canonical`); `contact` no longer takes the address twice; the explicit
  HackerTarget latch check and the unused `latchedError.host` are gone (the guard already refuses a
  latched host); `classify` parses a CIDR once; `serialHost` no longer builds a slice per request.
- `egress`: a rate limiter's wait that would pass the deadline now wraps `context.DeadlineExceeded`
  (one `wait` helper at the DNS, local, TCP, TLS and third-party sites), so `iplookup` no longer
  matches the limiter's error text. `egress.ProbePolicy` builds the one-address probe Policy that
  `iplookup` and an egress test each assembled field by field. `LocalResolver` returns plain slices,
  with empty meaning not found, instead of a `LocalAnswer` and a `notFound` flag that callers dropped
  or re-derived.
- `input.CleanName` replaces `ipsource.CleanName` and the `httpsrc.CleanName` forwarder; the recon
  stages call it directly.
- `webpage` owns `FirstText`, `Collapse` and `CutRunes`, which `TitleOf` had copied from the web
  stage; the web stage now calls them.
- `sanitize.Line` replaces the `spaces`/`clean` pair copied into the `iplookup` and `cve` renderers.

Skipped:
- One sentinel for a spent quota across `ipsource` and `run`, and moving the reverseip stage onto
  `ipsource.HackerTargetReverse`. Both change how recon stages abort or word errors (the stage's
  401/403 handling and its messages differ), which is outside this change.
- A shared generic `--fields` table for `nyx cve` and `nyx ip`, a shared retry-command builder (the
  two commands put `--json` in different places), and shared label/wrap helpers in `layout` for the
  two renderers. Each is a larger refactor of stable, tested output.
- A tokenizer-based title for `--active` GETs: the DOM walk keeps the "same title as the web stage"
  rule exact, and the body is capped.
- Minor items: the cap check repeated in `cli`, `Resolve` and `Plan.Addresses` (each guards a
  different caller); the unused JSON tags on `Record`; the defensive loop at the end of `Outcome`;
  test-only accessors on `Fields` and `Projected`; `inventory.Registration.Contains` for the RDAP
  range check (it would make `ipsource` depend on `inventory`); a shared SAN helper for the web stage;
  limiter wrapping in the HTTP dialler, where the error is classified as a result rather than
  returned.

# Verification

## Result

The implementation meets the goal and every behaviour, after the four corrections below. `make
test` (the cross-target vet and `go test -race ./...`) passes. Two live runs were made from this
machine on 2026-11-21: `nyx ip 193.0.6.139 --json` returned a whole record (every source answered,
HackerTarget included) in 3.3 s and exited 0, and `nyx ip 127.0.0.1 --active` scanned the built-in
ports of loopback, read the SSH banner, looked the PTR up locally and exited 0. Earlier live runs on
the same machine had public resolvers that dropped or SERVFAILed some Team Cymru queries; nyx
reported those as transient `cymru` failures and exited 7 at the 6 s deadline, as B3, B11 and B12
say it should.

- **B1 Inputs.** Met. Arguments, a lone `-`, trimming, blank lines, the three exit-2 cases, the
  stdin deadline (`TIMEOUT`), no `--config`, no `NYX_*` settings and no files are each tested
  through the harness.
- **B2 Hostnames and invalid inputs.** Met after a fix. The hostname rule, the single-label rule
  and its `--active` hint, and the bare-host hint for a URL or `host:port` were right. But a call
  that exited 2 at the 256-address cap dropped the invalid inputs from the error (`nyx ip foo_bar
  10.0.0.0/23` named only the cap), and so did the cap after hostnames resolved. Fixed in
  `internal/cli/ip.go` and `Plan.capError` in `internal/iplookup/inputs.go`; pinned by
  `TestIP_TheCapErrorListsTheInvalidInputsToo`.
- **B3 Resolving hostnames.** Met. Public A/AAAA, the local retry under `--active` only after
  NXDOMAIN or no addresses, single-label names only locally, and the `NOT_FOUND`, `NETWORK_ERROR`
  and `TIMEOUT` mappings are tested.
- **B4 CIDRs, B5 One record per address, B6 Cap.** Met, including the mapped-address, ordering,
  dedupe and both cap paths (literals before any request; hostnames after DNS only).
- **B7 Non-public addresses.** Met after a fix. The kinds table was checked row by row against
  IANA's live `iana-ipv4-special-registry-1.csv` and `iana-ipv6-special-registry-1.csv` (fetched
  2026-11-21), which resolves the "Address kinds" known limitation. Every row matched except one:
  192.88.99.2/32 (6a44 relay anycast, globally reachable `False`) is a live row inside the terminated
  192.88.99.0/24, and was missing, so 192.88.99.2 was reported `public` and sent to third parties. It
  is now kind `6a44-relay` (`internal/addrkind/addrkind.go`, its tests, and the README's kind table).
  The no-third-party, no-public-DNS and local-PTR-only rules are tested.
- **B8 The record of a public address.** Met. Keys and order are pinned; each source's 404 or empty
  answer, 429, 500, malformed body and hang is tested; HackerTarget's IPv6 and shared-address rules,
  the 100-name cap and count, RIPEstat's `?` country and the RDAP referral are tested.
- **B9 Default contact.** Met: the TCP canary and the `DialMap` targets see nothing in default mode,
  and the README names every host.
- **B10 `--active`.** Met. The contact decision (shared, hyperscaler, owner unknown, non-public from
  public DNS, the unreachable kinds, IPv6 link-local), the ports (built-in plus at most 64 of
  InternetDB's, lowest first), the per-hostname TLS and GET, redirects reported and not followed,
  `not-tls`, `closed`, no bytes sent, and `--fields ports` are tested. The "Probe outcomes" known
  limitation is narrower than it says: `TestRunProbe_AFailureOfThisMachineIsAProbeFailure` and
  `TestRunProbe_TheDeadlineLeavesPortsNotProbed` pin both cases at the unit level, with fake probe
  clients; only a harness-level test of them is missing.
- **B11 Time.** Met after a fix. The deadline rule, its three phases, the latches and the paces are
  tested. But HackerTarget waited for the Team Cymru AS-name lookup, which the shared check does not
  need (the provider is decided from the AS number alone), so a slow AS-name answer pushed
  HackerTarget past the deadline; in a live run it made HackerTarget a `TIMEOUT` failure. The
  AS-name lookup now runs beside HackerTarget (`publicSources` in `internal/iplookup/sources.go`);
  pinned by `TestSources_HackerTargetDoesNotWaitForTheHolderName`. The six-second promise for one
  public address held in the live run above (3.3 s); it is not measured by any test, which needs
  live sources.
- **B12 Outcome.** Met, including quota failures never counting, the retry hint with the given flags
  naming addresses not their CIDR or hostname, the one-code exit codes, mixed codes, the past-20 hint
  and signals. The PARTIAL message counts addresses and inputs together ("3 of 3 inputs returned, 1
  failed" when one address has a failed source), which B12 does not specify; left as is.
- **B13 `--fields`, B14 `--json`.** Met; the source dependencies, `""`, `all`, both exit-2 cases and
  the always-run shared check under `--active` are tested, and the envelope's keys, `meta.hint` and
  the error entries are pinned.
- **B15 Human mode.** Met after a fix. Sanitising, the golden layouts, `error:` lines after the
  records and `WARN` on stderr are tested. A selected key whose source failed reads `unknown` rather
  than D26's `none` (a known limitation, kept: it is more accurate, and B15 itself does not say).
  But a Team Cymru failure of the AS name alone made the provider, its class and the reverse-IP keys
  read `unknown` even though they were decided from the AS number, which was known; now only the AS
  name reads `unknown` then (`body.empty` in `internal/iplookup/render.go`, pinned by a new
  case in `TestRender_EmptyAndUnknownValues`).
- **B16 Help and README.** Met. Root help, `nyx help ip`, and every README section named are
  updated; the recon and `nyx cve` suites pass.
- **Conventions.** Met, except that D11's extraction did not land as its own `refactor:` commit
  before `nyx ip` (nothing had been committed); the whole change is committed together.

## Code review

`/code-review high --fix` went over every file of the change. Fixed, each checked against the spec
and kept:

- **Local PTR names (B7, B10).** `LocalResolver.PTR` in `internal/egress/local.go` threw away every
  valid name when this machine's resolver also returned a malformed one (Go's `LookupAddr` returns
  both), so the record had `ptr: null` and a `ptr` failure. It now keeps the valid names; pinned by
  `TestLocalPTRKeepsTheValidNames`.
- **`--active` help (B10, B16).** The flag and the long help said only public addresses are
  contacted; they now say non-public ones are too, as B10 and the README do. The two root-help
  goldens (`internal/cli/testdata/plain/help-help.txt`, `help-root.txt`) were updated for the new
  wording only.
- **Hostname de-duplication (B1, B5).** `Plan.Hostnames` used a scan per name, quadratic in the
  number of stdin lines; it now uses a set. No change in behaviour.
- **`Fields.Needs` (B10, B13).** It now calls `NeedsSharedCheck` instead of repeating its rule. No
  change in behaviour.

Reported but not fixed by the review, and handled here:

- **The call's error named addresses (B12, B16).** The PARTIAL and one-code errors listed failed
  addresses in `input`, where the README's Errors section says the inputs as given; `nyx ip
  example.com` whose only address failed gave `{"input":["93.184.216.34"]}`. Fixed by hand:
  `callInput` in `internal/iplookup/outcome.go` lists the inputs as given (the hostname or CIDR) in
  the `{"input":[…]}` shape every command's error has, and the `meta.errors` entries keep their
  `address`. The README now says which carries the address. Pinned by
  `TestOutcome_TheErrorListsTheInputsAsGiven` and the extra check in
  `TestOutcome_OneFailedSourceIsPartial`.

Left unfixed:

- **A reset during a TLS handshake reads `not-tls` (B10).** It is still a result and never a
  failure, which is what B10 asks, but the README lists `reset` among the TLS outcomes, and only a
  web request can produce it. `TestHandshakeResetIsTLSFailed` pins the current rule on purpose, so
  changing it is a decision for the user (see Follow-ups).
- **Three clean-ups:** the `squash` helper copied between the `cve` and `iplookup` renderers, the
  HackerTarget quota message written in three places, and `LiteralCount` worked out three times per
  call. Low value, and each reaches outside the new command; the Simplify pass skipped the same
  items.

After these fixes `make test` and `make lint` pass (0 issues).

# Follow-ups

1. Register the `sourceapp=nyx` identifier with RIPEstat: email stat@ripe.net with a contact
   address, as its terms ask of anyone regularly making more than 1000 requests a day. Only the
   project owner can do this.
2. Confirm HackerTarget's real daily allowance for unkeyed use (assumed about 20 from the
   `X-API-Quota` header): run `curl -sI 'https://api.hackertarget.com/reverseiplookup/?q=193.0.6.139'`
   and read `X-API-Quota`, then give the figure under "IP lookup" → "Sources" in `README.md`.
3. Decide whether a reset during a TLS handshake should read `reset` rather than `not-tls`. Either
   change `handshake` in `internal/egress/tls.go` and `TestHandshakeResetIsTLSFailed` in
   `internal/egress/handshake_test.go`, or drop `reset` from the TLS outcomes in `README.md` ("IP
   lookup" → "`--active`" → "TLS").
4. Check the new kind name `6a44-relay` for 192.88.99.2 (`internal/addrkind/addrkind.go` and the
   README's kind table). It was chosen during verification, as no name for it was decided.
5. Decide whether the PARTIAL message should count inputs only; it now counts an address with a
   failed source as well ("3 of 3 inputs returned, 1 failed"), in `Outcome` in
   `internal/iplookup/outcome.go`.
6. Optionally measure the six-second promise again on another connection: `time nyx ip 193.0.6.139
   --json` should exit 0 in under 6 s (it took 3.3 s here on 2026-11-21). No test can measure it.
