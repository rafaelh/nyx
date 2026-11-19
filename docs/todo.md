
- Add:
  - Standalone IP enumeration as `ip` subcommand. Should take one or more IPs and return a table of
    results for a human, or json output for an agent. example usage: `nyx ip --json 8.8.8.8 1.1.1.1`.
    Internal IP addresses and invalid IP addresses should be caught by default.
  - Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
    print DMARC with any issues.
  - merge in CVE functionality as a `cve` lookup subcommand. Cache?
- Add the capability to define an internal scope of assets, IPs, domains, etc to identify automatically.
  If a domain has been reconned recently, should it resolve from those files?


# internal/cloudstorage, internal/config, internal/dnsname, internal/egress, and internal/engagement
One table driving all settings in config: the biggest maintenance win, since each integer setting is listed in five places, but it's a redesign of `Load`. Flag help order is fixed, so the table would need to cover every flag, not just the integers.

Altitude items that are design changes reaching well outside these packages:
- the script allowlist versus the crawler's anchor workaround;
- giving each request kind its own check in targetHTTP.do;
- bucket URLs worked out in both cloudstorage and the storage stage;
- CandidateExempt plumbing that serves one stage;
- API-key placement repeated at every call site instead of once per source;
- a shared redaction walker with cli/export;
- keeping the SRV/MX writer next to its parser in dnsname;
- exporting ErrHTTPTimeout.




Too big for a cleanup pass:

Prepared statements and fewer SQL statements per observation in the store.
Reusing HTTP connections, which would need rate limiting reworked.
Encoding observation attributes to JSON only once.
Making how a finding is announced a property of the finding kind, and replacing the hard-coded "asn" stage name.
