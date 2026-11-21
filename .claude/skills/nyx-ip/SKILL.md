---
name: nyx-ip
description: >-
  Look up who runs an IP address and what is known about it, using the nyx CLI's `ip` subcommand.
  Use when you need the ASN, owning organisation, netblock, reverse DNS, hosting or CDN provider,
  location, known open ports, CPEs or CVEs, or co-hosted hostnames for one or more IPv4/IPv6
  addresses, hostnames or CIDRs.
metadata:
  version: 1.0
---

`nyx` is a passive-first reconnaissance CLI. Its `ip` subcommand returns one record per address,
covering:

- **Ownership**: ASN, AS name and prefix, RDAP netblock, organisation and registry
- **Naming**: PTR, and hostnames seen on the address
- **Infrastructure**: shared-infrastructure provider (CDN, cloud, hosting) and its class
- **Location**: country and city
- **Known exposure**: open ports, tags, CPEs and CVEs from Shodan InternetDB, and reverse-IP
  hostnames

By default it contacts only third parties and DNS resolvers, never the address itself. It needs no
API key and writes no files. `--active` also connects to the address (ports, TLS, web) as a member
of the public would. Only pass it when the user has authorised contact with the target.

Run `nyx ip help` for the inputs, flags, fields and exit codes. Use `--json` when you will parse the
output.
