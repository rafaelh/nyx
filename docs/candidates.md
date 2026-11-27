# Ranked candidates

`candidates.csv` lists the roots, hostnames, netblocks, autonomous systems and organisations that were found but are not in scope.
While a netblock is in scope, each candidate hostname and root is looked up through the public
resolvers, and a hostname served from an in-scope netblock enters scope by its address and leaves
this file (see [Names on in-scope addresses](sources.md#names-on-in-scope-addresses)). A candidate
root whose own name enters scope that way stays listed as a root.
Each row says how well supported it is, so you can tell which are worth promoting to scope:

| Column | Meaning |
|---|---|
| `type` | `root`, `hostname`, `netblock`, `asn` or `organisation` |
| `value` | The candidate |
| `sources` | The distinct procedures or mechanisms that found it, joined with `;` (listed below) |
| `evidence_count` | The number of distinct pairs of a source and the item that linked the candidate: the address, root, name server, netblock, service or organisation the source was asked about, or for `spf` the name whose SPF record named it |
| `confidence` | `low`, `medium` or `high` |

The `sources` values are the procedures and mechanisms that can find a candidate. Each belongs to one
family: certificate transparency (`crtsh`, `certspotter`, `censys`, `ct-org`), web archive
(`wayback`, `commoncrawl`), passive DNS (`virustotal`, `securitytrails`, `shodan`, `shodan-dns`, `shodan-host`,
`chaos`, `urlscan`, `hackertarget`, and `otx` and `anubis`, which no longer run but whose stored
results still count), registrant (`whoisxml`, `org-asn`, `rdap`) and reverse IP (`reverseip`).
`httpprobe`, `rdns`, `crawl`, `spf` and `in-netblock` are each a family of their own, and so is any other source.
An `in-netblock` candidate is the registrable domain of a hostname in scope by its address (see
[Names on in-scope addresses](sources.md#names-on-in-scope-addresses)), with that hostname as its item.
The web identifier family is `identifier-pivot`; the `sources` value is `identifier-pivot:<id>`, with
the identifier that found the candidate, so each is a source of its own but they are one family. Shared infrastructure is a family of two sources,
`shared-ns` and `shared-mx`,
so a root found by both is still one family.

An `spf` candidate is a range an organisation's SPF record authorises to send its mail. Each
`ip4:` and `ip6:` term with no qualifier or with `+`, in the SPF record of an input root, of an
in-scope name below one, or of an in-scope domain such a record includes or redirects to, is a
`netblock` candidate (a single address as a /32 or /128), with the name whose record named it as
its item. These give none: a term qualified `-`, `~` or `?`; a term after `all`, which is never
evaluated; a range wider than /16 (IPv4) or /32
(IPv6); a range that is not public, or that holds a special-purpose block; a range (not a single
address) whose first and last addresses are both known shared provider addresses, which is the
provider's sending pool; a name with more than one `v=spf1` record; and any term of an included
record whose domain is outside scope, which is never asked. Nothing in an `spf` candidate is
contacted or looked up until you give it as `--cidr`.

A hostname or root under a domain that a known DNS, mail or SaaS provider operates
(`login.microsoftonline.com`, `acme.zendesk.com`) is not listed and not counted: it is the
provider's name or a tenant's, never a domain to bring into scope, and the dependency is in
`third-parties.csv`. `httpprobe` takes no candidate from a certificate that does not name the host
when the host is on shared provider infrastructure: that certificate is the provider's own, and
the names on it are its other customers'. A certificate that names the host, and the certificate
of an address, give all their names.

A netblock candidate that an in-scope netblock contains is not listed, and not counted in the
summary, whichever source found it: give a wider range as `--cidr` and the candidates inside it
leave `candidates.csv` on the next run, without `--redo`.

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

Confidence is worked out again on every run from the jobs that currently support the candidate.
After `--redo` of a procedure whose results no longer support a candidate, it drops. Rows are sorted by
confidence (high first), then by evidence count (most first), then by value. A row that is not
current sorts last and shows the confidence it last had.

The summary lists up to 20 `high` candidates with the input that promotes each (a root or hostname
as a positional domain, a netblock as `--cidr`, an autonomous system as `--asn`, an organisation as
`--org`), then `and N more in candidates.csv`, which counts
the high candidates beyond the 20 listed. The medium and low ones are in `candidates.csv` only.
