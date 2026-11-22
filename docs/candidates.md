# Ranked candidates

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
(see [Web identifiers](web.md#pivoting-on-them)). Shared infrastructure is a family of two sources,
`shared-ns` and `shared-mx` (see [Shared name servers and mail hosts](dns.md#shared-name-servers-and-mail-hosts)),
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
