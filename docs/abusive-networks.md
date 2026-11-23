# Abusive networks

nyx flags an address that two sets of threat data name as abusive or criminal:

- **Spamhaus's Don't Route Or Peer (DROP) lists**: DROP (IPv4 netblocks) and DROPv6 (IPv6
  netblocks), which name netblocks that have been hijacked or are run by criminals, and ASN-DROP,
  which names the ASNs that are. nyx flags an address that a DROP or DROPv6 netblock holds, or whose
  origin AS ASN-DROP lists. Each entry has an SBL ID (Spamhaus's record of the listing) and the
  regional registry (RIR) that allocated it, and an ASN-DROP entry has the AS name, country and
  domain too.
- **ipapi.is's two lists of the most abusive on the internet**: its
  [Most Abusive Networks](https://ipapi.is/most-abusive-networks.html) (about 5,000 IP ranges) and its
  [Most Abusive ASNs](https://ipapi.is/most-abusive-asn.html) (about 1,000 ASNs). Each entry has a
  rank, a score tag, an abuse score (the percentage of the network's addresses seen behaving
  abusively), the organisation and its type.

The data is Spamhaus's and ipapi.is's, and nyx credits each as the source. Spamhaus's lists carry its
copyright line and a link to its terms, which are:

> (c) The Spamhaus Project SLU. Terms of use: <https://www.spamhaus.org/drop/terms/>

nyx shows the line the lists in use carry in the output of an update and on the Threat data tab of
`nyx setup`, and names Spamhaus wherever it describes a DROP match.

All five lists are built into the binary, and a check is a lookup in them, so a check sends no
request, and a match is information only: it never changes the scope, what is contacted, which
addresses are port-checked, or the ranking of candidates. nyx contacts Spamhaus and ipapi.is only
when you ask it to update the lists (see [Updating the threat data](#updating-the-threat-data)).

## What is matched

An address matches a DROP or DROPv6 entry when the listed CIDR holds it, a network entry of ipapi.is
when a listed range holds it, and an ASN-DROP or ASN entry when its origin AS is the listed one. An
IPv4-mapped IPv6 address is matched as its IPv4 address. A network of ipapi.is is written as a CIDR
when the range is exactly one, and otherwise as `start-end`, as `rdap_netblock` is. Only the first
origin AS Team Cymru gives is checked. Every matching entry is reported, the most specific range
first (ranges of one size by rank), then the AS. Spamhaus's SBL IDs, AS names and domains and
ipapi.is's organisation names, score tags and types are cleaned of anything that acts on a terminal,
as other third-party text is.

- **`nyx ip`** reports an address's matches in the `drop_networks`, `drop_asn`, `abusive_networks`
  and `abusive_asn` keys (see [IP lookup](ip.md)). It is triage context for an address that is often
  untrusted, such as one seen in a log.
- **Recon** checks the addresses of the engagement, which belong to the target, where a listed
  network is worth a look: the host may be compromised, shadow IT or on reallocated space, or at risk
  of being blocklisted. It checks every current address that an in-scope hostname resolves to
  (including a shared CDN or SaaS address and a wildcard-only name's), and every address inside an
  in-scope netblock that a current record other than DNS history names (a PTR answer, a resolution
  or a Shodan result). It never checks a candidate's address, an excluded address, or an address that
  only DNS history names.

## Findings

Each address checked that has a match is one `abusive-network` finding in `risk-abusive-network.csv`,
with `severity`, `ip`, `hostnames` (its in-scope names), `type`, then `drop_networks`, `drop_asn`,
`networks` and `asn`, and `drop_networks_updated`, `drop_asn_updated`, `networks_updated` and
`asns_updated` (the date of each list that matched). A `drop_networks` entry is
`<cidr> <SBL ID> (<RIR>)`, a `drop_asn` entry `AS<n> <AS name> <country> <domain> (<RIR>)`, a
`networks` or `asn` entry `<entry> <score tag> <abuse score>% <organisation> (<type>)` (the rank
left out), and entries are joined with `;`.

The finding's `type` and severity are those of the strongest match, in this order:

| Type | Severity | When |
|---|---|---|
| `drop-network` | high | a DROP or DROPv6 netblock holds the address |
| `drop-asn` | medium | ASN-DROP lists the address's origin AS |
| `network` | medium | an ipapi.is network entry holds the address |
| `asn` | low | only the address's origin AS is on ipapi.is's list |

It sends no request, so it is derived under `--passive` too, and it appears wherever other findings of
its severity do: the summary (high and medium), the `--json` findings and `changes.csv`. `nyx help
findings` lists the four types with the other finding severities.

The AS of an address outside the in-scope netblocks is the one the `ipowner` stage found. For an
address inside one, the `netblockowner` stage asks Team Cymru's origin service, through the public
resolvers, once for each covering /24 (IPv4) or /48 (IPv6) of the netblock addresses nyx knows, or
once for an in-scope netblock that is smaller: prefixes longer than those are filtered from the global
routing table, so the answer applies to every address in the unit. Team Cymru is a third party, so
this runs under `--passive`, and `--skip netblockowner` turns it off (the network matches are still
found). The AS learned this way is used only for this check: whether an address is shared provider
infrastructure, port-eligible, excluded, an origin candidate or part of an organisation candidate is
decided as before, and its owner in `ips.csv` still reads as an in-scope netblock.

When the data in use changes, from an update or a newer build, the next run's findings reflect it
with no request. An address that drops off the lists loses its finding (it stays on record, not
current), and a newly listed address gains one. One that stays listed keeps its finding with the
detail of the data now in use, at the type and severity of its strongest match: it is announced again
only if its severity rises, and a finding whose strongest match weakens (DROP drops the address but
ipapi.is still lists it) stays one current finding at the lower severity and is not announced again.
An engagement run before a build that has the check looks up those origins once on its first run. A
recon run uses the data in place when it started, through all its passes, and `nyx recon export`
reads no threat data and shows the findings as of the last run.

## The data in use

Each list is dated as precisely as its source dates it: a Spamhaus list to the second, as an RFC 3339
UTC timestamp (`2026-11-21T17:56:44Z`), and an ipapi.is list to the day (`2026-11-21`). The `nyx ip`
record, `risk-abusive-network.csv` and the update's `--json` envelope write them the same way.

The built-in copies are dated as follows. They are updated when a build is made (see
[Refreshing the built-in copies](#refreshing-the-built-in-copies)):

| List | Source | Built-in copy dated |
|---|---|---|
| DROP (`drop_v4`) | Spamhaus | 2026-11-21T17:56:44Z |
| DROPv6 (`drop_v6`) | Spamhaus | 2026-11-20T09:56:44Z |
| ASN-DROP (`asndrop`) | Spamhaus | 2026-11-23T08:56:44Z |
| Most Abusive Networks (`networks`) | ipapi.is | 2026-11-22 |
| Most Abusive ASNs (`asns`) | ipapi.is | 2026-11-22 |

For each list nyx uses whichever copy, built-in or downloaded, is dated later, and the downloaded one
when both have the same date. The lists of one source are used together: a downloaded copy is used
only when all of its lists parse, hold no control character, list no entry twice, have their date
(and, for Spamhaus, their final metadata line) and hold at least 90% of the entries they say they
have. Otherwise the whole source falls back to its built-in copy, and each recon run and each
`nyx ip` call that reads it warns once on stderr (in `meta.warnings` under `--json`; `--quiet` does
not suppress it) and names the command that replaces the copy. `nyx recon export` reads no threat
data, so it does not warn.

After more than 30 days since both the oldest date among a source's lists in use and the last time an
update found the source updated or already current, `nyx recon` (a run, not `export`) and `nyx ip`
print one line on stderr that gives that oldest date:

```
hint: Spamhaus DROP data is from 2026-10-01; run nyx setup --update-threat-data
hint: ipapi.is abuse data is from 2026-10-01; run nyx setup --update-threat-data
```

`nyx ip` prints a line only when a key it was asked for reads that source. The line comes after the
no-config hint, is not printed under `--quiet` or `--json`, and is not printed when the command
fails with a usage error. Under `--json` it is an entry in `meta.warnings` instead, whatever
`--quiet` says. A call with neither `XDG_CONFIG_HOME` nor `HOME` set has nowhere to look for a
downloaded copy: it uses the built-in data with no warning and no hint.

## Updating the threat data

`nyx setup --update-threat-data` brings all five lists up to date and exits. It never opens the
editor, and it reads no config file, so it runs with no terminal, with no config file and with an
invalid one. `--config` is accepted and ignored, and an argument exits 2. The Threat data tab of
`nyx setup` runs the same update when you press `u` (see [Setup](configuration.md#setup)).

An update sends at most one request per list, with no retry, and nothing to any target:

- one to `www.spamhaus.org` for each of `drop_v4.json`, `drop_v6.json` and `asndrop.json`, under
  `/drop/`;
- one to `ipapi.is` for each of its most-abusive networks and most-abusive ASNs pages.

Each request gives up after 30 seconds. A redirect is not followed, even to the same host: it fails
the source. Once one request of a source fails, the source's remaining requests are not sent. No
recon stage, `nyx ip`, `nyx cve` or key test sends anything to either host as a threat-data source.

- **A download is refused** when a row does not parse or lacks a required field (an unknown field is
  ignored), when any text holds a control character, when an entry is listed twice, when a Spamhaus
  file has no final metadata line, when a list holds fewer than 90% of the entries it says it has,
  when it is dated after the end of tomorrow (UTC), and when it has no entries or fewer than half the
  entries of the copy in use. A DROP or DROPv6 entry is its CIDR and SBL ID together, so one CIDR
  under two SBL IDs is two entries; an ASN-DROP entry is its ASN, and an ipapi.is entry its range or
  ASN. A list refused for shrinking names the rule and both counts, and says that a newer build of
  nyx is the remedy. A refused list fails its source, which keeps its previous copy.
- **Already current.** A list dated no later than the copy in use is reported as already current and
  left as it is. A source with no newer list is already current, which counts as a success. A
  downloaded copy that cannot be read is replaced even by a download no newer than the built-in one,
  and the warning then stops.
- **Per source.** Spamhaus's three lists are one source and ipapi.is's two are the other, and each
  is replaced as a whole or not at all. An update that a signal, a crash or quitting setup
  interrupts leaves each source with its previous copy or its complete new one, and a command that
  reads threat data while an update runs sees one or the other, never a mix. A download that passes
  the checks but cannot be stored (permission denied, a full disk) fails its source with
  `UNEXPECTED_ERROR` and the reason, and leaves the previous copy in place.
- **Once an hour.** Within an hour of the last time a source answered nyx with an HTTP response,
  whatever its status, an update sends nothing to that source. It says when the source was last
  contacted and when it can be updated next, and counts the source as skipped. A request that got no
  response (DNS, connect, TLS, a reset or a timeout) does not start the hour. When two updates run at
  once, the second waits for the first to finish with each source, then applies the rule to that
  source as the first left it. A recorded time in the future is replaced by the current time, so the
  source can be updated again at most an hour later.

### Output

For each list the update prints its source, its old and new date, its entry count and how many
entries were added and removed, one line each, then Spamhaus's copyright line and a link to its
terms. It goes to stdout, and `--quiet` does not suppress it:

```
spamhaus  drop_v4  2026-11-20T09:56:44Z -> 2026-11-21T17:56:44Z  1752 entries (+5, -2)
spamhaus  drop_v6  already current
spamhaus  asndrop  skipped: last contacted <time>; can be updated after <time>
ipapi.is  networks failed: <reason>
Spamhaus DROP data (c) 2026 The Spamhaus Project SLU; terms: https://www.spamhaus.org/drop/terms/
```

A list that was not replaced says that it is already current, that it was skipped (with when it can
next be updated) or that it failed (with the reason). The copyright line and the link are those the
list in use carries.

**Exit codes.** The update exits 0 when every source updated, was already current or was skipped, 7
(`PARTIAL`) when one source failed, whatever the other did, and 1 when both failed, with their shared
error code, or `UPSTREAM_ERROR` when the codes differ (stdout is then empty, and the error gives each
source's reason). A signal exits 130, 143 or 129, with each source's previous copy intact. A source
that fails has one of these error codes:

| Code | When |
|---|---|
| `NETWORK_ERROR` | no response: DNS, connect, TLS, a reset |
| `TIMEOUT` | a request gave up after its 30 seconds |
| `RATE_LIMITED` | the source answered 429 |
| `UPSTREAM_ERROR` | any other answer, a redirect, a body cut short or a refused download |
| `UNEXPECTED_ERROR` | a download that cannot be stored |

The error is transient when any failure was a network failure, a timeout or a 429, and its hint says
when each failed source can next be updated. With neither `XDG_CONFIG_HOME` nor `HOME` set the update
exits 2 and says why (`INVALID_INPUT`).

**`--json`.** On exit 0 or 7 the update writes one envelope, with every key always present:

```json
{"data":{"sources":[{"source":"spamhaus","outcome":"updated","last_contacted":"2026-11-23T01:02:03Z","next_update":null,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/","error":null}],"lists":[{"list":"drop_v4","source":"spamhaus","old_updated":"2026-11-20T09:56:44Z","new_updated":"2026-11-21T17:56:44Z","old_entries":1750,"entries":1752,"added":5,"removed":3}]},"meta":{"errors":[],"warnings":[],"hint":null}}
```

- A **source** has `source` (`spamhaus` or `ipapi.is`), `outcome` (`updated`, `current`, `skipped` or
  `failed`), `last_contacted` and `next_update` (RFC 3339 or `null`; `next_update` is set when
  skipped, and when failed after a response), `copyright` and `terms` (`null` for ipapi.is), and
  `error` (`null`, or the five-key error of [Exit codes and errors](exit-codes.md#errors)).
- A **list** has `list` (`drop_v4`, `drop_v6`, `asndrop`, `networks` or `asns`), `source`,
  `old_updated` and `new_updated`, `old_entries` and `entries`, and `added` and `removed`. The `old_*`
  keys describe the copy in use before the update and the others the copy in use after it, so they
  are equal unless the list was replaced.
- `meta.errors` holds the failed sources' errors. The keys of the envelope are a stable interface.

### Where the downloaded copy is kept

The downloaded copy is kept beside the default config file, in the `threat-data` directory of
`$XDG_CONFIG_HOME/nyx/` or else `~/.config/nyx/`, whatever `--config` a command is given. One update
therefore applies to every engagement and to `nyx ip`, and nyx reads no new environment variable.
Deleting the `threat-data` directory restores the built-in data. The directory is created readable
only by you, and holds, for Spamhaus, `spamhaus.jsonl` (the three lists exactly as Spamhaus serves
them), `spamhaus.state.json` (when the source last answered and was last checked) and
`spamhaus.lock`, and for ipapi.is `ipapi.json` (its two lists, parsed), `ipapi.state.json` and
`ipapi.lock`. Each file is written to a temporary file beside it and renamed into place. An update
that is interrupted may leave a `.spamhaus-*.tmp` or `.ipapi-*.tmp` file behind, which nothing reads
and the next update of that source removes.

## Refreshing the built-in copies

Refreshing the built-in copies is a maintainer's task, done when a build is made, not by a user:
`make threat-data` fetches the five lists with `curl` (three requests to `www.spamhaus.org` and two
to `ipapi.is`), and a tool (`internal/threatdata/refresh`) applies the same checks as an update. It
prints what was added, removed and changed (a rank that alone moved is left out), and replaces each
source's copy, `internal/spamhaus/builtin.jsonl` and `internal/abusive/snapshot.json`, as a whole or
not at all. A list dated no later than the built-in copy is left as it is, and a source that fails
leaves its file as it was while the other is still written. A maintainer who has reviewed a list that
shrank to under half its entries can let it through with `make threat-data ALLOW_SHRINK=1`, which
lifts only that rule. Review the diff, update the five dates in the table above, and commit. A test
fails if this page does not give the built-in copies' dates.
