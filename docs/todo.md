
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



# internal/eol, internal/fault, internal/findings, internal/input, internal/inventory, and internal/kinds

Kinds that are classified against the scope decide their placement and category by switching on kind names (kinds/visibility.go). Moving that onto the kinds themselves is a redesign, not a cleanup. The review also found that placement and category use different rules for organisations. As a result, nyx recon export can report an organisation as a candidate that candidates.csv doesn't list. That may be a bug: worth running /code-review on it.

A per-category table for finding keys, parsing and found text: a larger refactor, and the stored key strings must stay byte-for-byte the same.

Renaming input.NormaliseHost to dnsname.Normalise: it touches about 30 files outside the scope.

Shared test scope builder in testkit: it would change test helpers in several packages outside the scope.

Efficiency changes left alone:
A non-JSON fast path for encoding finding attributes: it risks changing stored values.
Caching the inventory's CNAME chains and per-scope results: these touch shared infrastructure for about 5–10 ms per stage.
Speeding up indexRegistrants: it runs once per inventory.
Decoding each web service's attributes only once: a small gain at about 3 ms per 5k services.
Storage reading CNAMEs that the inventory already indexes, and the finding kind building its found line outside the Found hook: both need new seams in other packages.
