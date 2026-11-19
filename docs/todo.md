
- Add:
  - Standalone IP enumeration as `ip` subcommand. Should take one or more IPs and return a table of
    results for a human, or json output for an agent. example usage: `nyx ip --json 8.8.8.8 1.1.1.1`.
    Internal IP addresses and invalid IP addresses should be caught by default.
  - Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
    print DMARC with any issues.
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


# internal/orgname, internal/origin, internal/output, internal/palette, internal/provider, and internal/report

Skip rewriting output files whose bytes haven't changed. This is the biggest win the reviews found: up to about 33 fsyncs per pass. Comparing with the file on disk would stop the render-mid-file crash test from reaching its fault point. Doing it safely needs the runner to keep state between passes, so it should be its own change.

Fixes in packages outside these six:

Caching the per-address hostname lookup that is computed three times per render (inventory).
Letting a caller tokenise an organisation name once instead of on every match (orgname callers in scope and stages).
Shared hash, atomic-write and test-fixture helpers.
A copied test helper that strips escapes.
Larger redesigns:

Giving each record kind its own key decoder.
Redaction by reflection.
Presorted output rows.
One place for the "excluded" counting rule.
Taking source names from stage data instead of hard-coding them.
Giving the provider data its own "fronts a site" rule.
Several of these would change what users see, and two would actually fix bugs:

A no-longer-current DNS claim writes a blank row to resolutions.csv.
Historical addresses and code mentions that are no longer current skip the showing rule, so they stay listed after their host or root is excluded.
/code-review is the better place to chase those.

Merging every Classify test into one table. The tests read well as separate named behaviours, so I only removed the exact duplicates.


# internal/run, internal/sanitize, internal/scope, internal/shellquote, internal/store, internal/testkit, and internal/thirdparty

Larger redesigns:
Turning the findings derivation into an ordinary deriver with hooks.
Making which entities the files list a single Visibility rule; today changes.go copies the rules from output.
Moving the stage-specific View queries out to the stages that use them.
Separating the egress policy from the scope build, and giving finding display its own Kind.Found instead of the special case in foundFields.
Removing BuildScope's dependence on the asn stage's name.
Moving the candidate roll-up rules into internal/candidates.
Diffing SaveShown instead of rewriting every row.
Caching each stage's completed checks between passes, and refreshing changed records incrementally.
Would change behaviour: sorting OpenPorts with AddrPort.Compare would change the order from text to numeric.
