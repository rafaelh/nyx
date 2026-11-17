
- Add:
  - Standalone IP enumeration as `ip` subcommand. Should take one or more IPs and return a table of
    results for a human, or json output for an agent. example usage: `nyx ip --json 8.8.8.8 1.1.1.1`.
    Internal IP addresses and invalid IP addresses should be caught by default.
  - Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
    print DMARC with any issues.
  - merge in CVE functionality as a `cve` lookup subcommand. Cache?
- Add the capability to define an internal scope of assets, IPs, domains, etc to identify automatically.
  If a domain has been reconned recently, should it resolve from those files?







Would change behaviour:



Too big for a cleanup pass:

Prepared statements and fewer SQL statements per observation in the store.
Reusing HTTP connections, which would need rate limiting reworked.
Encoding observation attributes to JSON only once.
Making how a finding is announced a property of the finding kind, and replacing the hard-coded "asn" stage name.
