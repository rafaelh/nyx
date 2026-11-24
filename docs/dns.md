# DNS and third parties

## Root DNS records and third parties

For each in-scope input root the `dnsroot` procedure asks the public resolvers for its NS, SOA, TXT
and CAA records, one job per type, so a type that keeps failing does not block the others. It runs
under `--passive`. Zone transfers are never attempted. Each answer is a row in `resolutions.csv`: a
CAA value is written `<flags> <tag> "<value>"`, and an SOA value is the primary name server and
the administrative mailbox as an email address (`john\.doe.example.com` is `john.doe@example.com`).

- A name server (or SOA primary) inside the scope is a hostname, resolved, probed and port-checked
  like any other. A name server outside it is a `third-parties.csv` row with mechanism `ns`, and is
  never a candidate or contacted. Its A and AAAA records are looked up, unless it is on a known
  provider's domain, only to say whether the organisation runs it itself (the `self_hosted` column
  of its NS row in `resolutions.csv`; see [Shared name servers and mail hosts](#shared-name-servers-and-mail-hosts)).
  The server is not resolved, probed or port-checked because of that lookup, and a lookup that
  fails is skipped, not retried. An engagement from before this lookup repeats its NS job once.
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

The `dnsroot` procedure also asks each in-scope root for these SRV names, as one more job per root
(a SERVFAIL or timeout on any of them fails that job, which is retried on the next run):
`_sip._tls`, `_sip._tcp`, `_sipfederationtls._tcp`, `_autodiscover._tcp`, `_ldap._tcp`,
`_kerberos._tcp`, `_xmpp-server._tcp`, `_xmpp-client._tcp`, `_caldav._tcp`, `_carddav._tcp`,
`_imaps._tcp`, `_submission._tcp`, `_matrix._tcp` and `_minecraft._tcp`. An engagement that already
holds the four record types runs only this job.

- Each answer is a row in `resolutions.csv` with type `SRV`, the service name (such as
  `_sip._tls.example.com`) as the name and `priority weight port target` as the value. A service name is
  not a hostname: it is never resolved or tested for wildcard DNS. A target of `.` (a service that is
  not offered) records nothing.
- A target inside the scope is a hostname, resolved, probed and port-checked like any other. Any
  other target is a `third-parties.csv` row with mechanism `srv` and the target's registrable
  domain, and is never a candidate or contacted.
- The ports the answers advertise are reported, not connected to: the `srv_ports` column of
  `ips.csv` lists, `;`-joined, the ports SRV records give for the address's in-scope hostnames. The
  `ports` procedure still checks only the configured port list.
- An SRV target that a root added later brings into scope becomes a hostname only after
  `--redo dnsroot` (its third-party row hides itself at once).

The permutations procedure also always tries a few well-known labels, such as `autodiscover`, directly
under each root, even when the wordlist lacks them (see the well-known labels in
[Built-in lists and per-run limits](lists-and-limits.md)).

The `+` line for a new third party reads `third-party <platform> via <mechanism> on <root>` (the
platform is the provider, else the domain),
and the row it announces is in `third-parties.csv` and in `nyx recon export`, with the `provider`,
`mechanism` and `root`. The prefix list and the name-server provider names are in the embedded
`providers.yaml`.

### Mail and SaaS dependencies

The `email` procedure (it runs under `--passive`, and only asks DNS) adds third parties to the same file
from the records it already reads for each in-scope root:

- `spf`: every domain the SPF walk follows (`include:` and a `redirect=` that the record's own `all`
  does not make unreachable) and every domain named by `a:`, `mx:` or `exists:` at any level, with the
  `depth` it was named at. Arguments with macros are skipped, and an include that has no SPF record is
  still listed. A SERVFAIL on any include fails the root's email job, which is retried on the next
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

For a root with at least one MX host that is not a null MX, the `email` procedure also asks for the TXT
records at `_mta-sts.<root>` (the root's own name, with no fallback to the organisational domain).
A timeout or SERVFAIL fails the job, as for SPF and DMARC. The policy file over HTTPS is never
fetched. A missing record (or more than one) is the low finding `mta-sts-missing` in `risk-email.csv`. The lookup is part
of the email job, so an engagement from an earlier version runs its email jobs once more.

## Shared name servers and mail hosts

A name server or mail host that an organisation runs itself is a strong sign that the other domains
it serves belong to the same owner. The `nsreverse` procedure finds them. It needs `keys.securitytrails`
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
  cap is part of the job, so changing it asks every server again.
- **Quota.** A rejected key (401 or 403) or a 429 stops the procedure for the run, and the jobs that
  remain are made on the next run.
- **Refresh.** Each server is asked once per engagement; new results arrive only with
  `--redo nsreverse`. The job is keyed by the server and the cap, not by the scope, so a name
  server that a root you promote later brings into scope is asked once it is self-hosted by either
  test, and a server whose addresses change is not asked again before `--redo nsreverse`. Name
  servers and mail hosts already on record have their addresses looked up the next time `dnsroot`
  and `email` run their jobs, which an engagement from before repeats once.
