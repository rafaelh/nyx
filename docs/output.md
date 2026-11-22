# Output files and export

## Output files

Everything is in `<output-dir>/<engagement>/`:

| File | Contents |
|---|---|
| `scope.csv` | Inputs and the netblocks and roots in scope, and where each came from |
| `candidates.csv` | Related domains, hostnames, netblocks, autonomous systems and organisations found but not in scope, ranked by how many independent sources support each (see [Ranked candidates](candidates.md)); pass one as an input to promote it |
| `excluded.csv` | Excluded items and the reason |
| `subdomains.txt` | In-scope hostnames |
| `resolutions.csv` | DNS records for in-scope names (A, AAAA and CNAME, the NS, SOA, TXT and CAA records of each root, and the SRV records of the listed service names, see below), with a `source` column: `resolve` (nyx's own lookup), `shodan` (reported by Shodan only) or `resolve;shodan`, then `self_hosted`: `yes` or `no` on an NS row of nyx's own lookup and blank otherwise (see [Shared name servers and mail hosts](dns.md#shared-name-servers-and-mail-hosts)). Records only Shodan reports decide nothing: they never make a name resolved or an address contacted, port-checked or probed. Historical addresses of a hostname behind a CDN or WAF are rows of type `A-historical` or `AAAA-historical`, source `dnshistory`, with the `historical_first_seen` and `historical_last_seen` columns (the last two before `current`; blank on every other row). A historical address is never a current one: it is not probed, port-checked or used to detect wildcards (see [Origin exposure](web.md#origin-exposure)). |
| `unresolved.txt` | In-scope names that did not resolve |
| `wildcard-excluded.txt` | Names dropped because their domain answers every name (wildcard DNS) |
| `ips.csv` | Addresses with ASN, owner, hosting provider, service (or, where the provider publishes no service, region), scope, port eligibility and hostnames, then the `registrant`, `registrant_netblock` and `registry` the `rdap` stage found, then `srv_ports`, the ports SRV records advertise for the address's in-scope hostnames (reported only; never connected to). A published range names the provider even when the owner lookup failed, and takes precedence over the ASN. Cloudflare and Fastly addresses are shared infrastructure and are not port-checked. DigitalOcean addresses and Linode addresses are customers' own machines, except that an address whose origin AS is a CDN's (Linode's list holds some of Akamai's edge space) stays shared, so an in-scope hostname that resolves to one of the others is port-checked: DigitalOcean addresses were skipped as shared hosting before its list was fetched, so the next active run may handshake addresses it previously skipped. An address two providers' lists cover shows both, joined with `;`, and is shared if either is. |
| `provider-hosts.csv` | Names that point at shared cloud or SaaS providers, with the evidence |
| `web-services.csv` | Web services found: status, title, server, technologies, redirects, TLS details (see [TLS detail](web.md#tls-detail)), web posture evidence (see [Web posture](web.md#web-posture)) and web identifiers (see [Web identifiers](web.md#web-identifiers)) |
| `urls.csv` | URLs from crawling, the scripts of crawled pages (see [JavaScript endpoints](web.md#javascript-endpoints)) and web archives, with status and source |
| `open-ports.csv` | TCP ports that nyx found open, and ports Shodan reports (see [Shodan per address](sources.md#shodan-per-address)), with the banner, the `source` (`nyx`, `shodan` or `nyx;shodan`), `confirmed` (`yes` when nyx completed a handshake), `shodan_last_seen` (empty on a row only nyx saw), and `product` and `version` where the banner is a recognised SSH, FTP or SMTP banner (see [End-of-life software](end-of-life.md)) |
| `email-posture.csv` | SPF, DMARC and MX results per root domain, then `mta_sts`: `present` when exactly one TXT record at `_mta-sts.<root>` begins `v=STSv1`, `absent` otherwise, and empty for a root without a mail host, then `mx_self_hosted`, the mail hosts the organisation runs itself, joined with `;` (see [Shared name servers and mail hosts](dns.md#shared-name-servers-and-mail-hosts)) |
| `third-parties.csv` | Organisations a root depends on, with the `root`, the `mechanism` (`ns`, `txt-verification`, `spf`, `dmarc`, `mx`, `cname` or `srv`), the `domain` (as written for `spf` and `dmarc`, the registrable domain for `ns`, `mx` and `srv`, the platform's name suffix for `cname`), the `provider` (when known) and the `depth` (0 for a domain the root's own records name, 1 for one named by a record that one includes, and so on; always 0 for the other mechanisms, and 0 on a row that is no longer current, whose depth is not kept) |
| `code-mentions.csv` | Files in public GitHub repositories that mention an in-scope root, from the `github` stage: `repository`, `path`, `url`, the in-scope `hostnames` the match names (`;`-joined) and the `root` searched for. A match that is no longer current keeps only its `url` (see [GitHub code search](sources.md#github-code-search)) |
| `storage-unattributed.csv` | Guessed cloud-storage buckets that nothing in scope references |
| `risk-takeover.csv` | Subdomain takeover findings |
| `risk-storage.csv` | Cloud-storage findings: buckets that exist, are public or are listable |
| `risk-sensitive-paths.csv` | Sensitive paths that answered with their expected signature |
| `risk-email.csv` | SPF, DMARC and MTA-STS weaknesses (`mta-sts-missing`, low: a root with a mail host that does not publish exactly one MTA-STS policy record) |
| `risk-ports.csv` | Open ports on the risky-port list, with `confirmed` (`no` for a port only Shodan reports, which is one severity step lower) |
| `risk-certificates.csv` | Expired, soon-to-expire and self-signed certificates, certificates that do not name the host, and services that negotiate only TLS 1.0 or 1.1 (see [TLS detail](web.md#tls-detail)) |
| `risk-web-posture.csv` | Low findings from web responses: missing HSTS, cookies without `Secure`, directory listings and disclosed versions |
| `risk-eol-software.csv` | Web technologies and banners whose version is past the end of security support (`eol`, medium) or within `eol_warn_days` of it (`eol-approaching`, low), with `product`, `version`, `end_date`, `seen` (`web` or `banner`) and `confirmed`; a distribution build or a version only Shodan reports is one step lower (see [End-of-life software](end-of-life.md)) |
| `risk-origin-exposure.csv` | One row per hostname behind a CDN or WAF and address that may be its origin server: the `provider`, the `address`, `found_by` (`historical`, `sibling-certificate`, `sibling-title`, joined with `;`), `confirmed_by` (`title` or `status-body-certificate`) and `confirmed` (`yes` or `no`). Confirmed rows are medium and possible origins low (see [Origin exposure](web.md#origin-exposure)) |
| `risk-abusive-network.csv` | One row per checked address that ipapi.is's most-abusive lists hold: `ip`, its in-scope `hostnames`, `type` (`network`, medium, or `asn`, low), the `networks` and `asn` entries with their score tag, abuse score, organisation and type, and the `networks_updated` and `asns_updated` dates of the lists (see [Abusive networks](abusive-networks.md)) |
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
  reported together. `--json` changes only the format of an error (see [Errors](exit-codes.md#errors)), not one
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
