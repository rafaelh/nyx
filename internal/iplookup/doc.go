// Package iplookup is what nyx ip does with an address, apart from asking the network: it parses
// and orders the inputs, decides the deadline, owns the record an address gets and the table of
// its keys, decides how a batch ends and lays the records out for a person. The sources are asked
// by the files that fan out per address (sources.go and active.go), through egress; the command
// (internal/cli) owns the flags, the worker pool and the writing.
//
// The keys of the record and the envelope around it are a stable interface: adding one is
// compatible, and renaming, removing or retyping one is a breaking change.
//
// # Terms
//
// An address kind is what addrkind says an address is: public, or the name of a non-public kind
// (private, loopback, link-local and so on). Every record has its address's kind. A non-public
// address is sent to no third party and to no public resolver.
//
// A source is where a part of a record comes from. There are seven, named in the order the record
// lists them (see Sources): cymru (the origin AS and its holder), rdap (the registered netblock and
// its registrant), ptr (the address's reverse names), ripestat (geolocation), internetdb (open
// ports, names, tags, CPEs and CVE IDs), hackertarget (the other names on the address) and probe
// (the connections --active makes to the address itself). The provider is not a source: it is
// decided from the built-in provider data and the AS number, so it comes with cymru.
//
// A source failure is a source that did not answer for an address: it failed, timed out, was
// rate-limited, or was not asked because it had already refused earlier in the call. It is a
// [Failure] in the record's failures, with its source, an error code, a message, whether a retry
// may succeed (transient) and whether it is a spent quota (quota: only HackerTarget's, which resets
// daily). A source that answered that it knows nothing about the address (a 404 or an empty reply)
// has answered, and its keys are empty. What a probe finds (nothing listening, not TLS, a reset)
// is a result in the record, never a source failure; only a local failure to probe is one.
//
// A record is the one answer for one distinct address: its keys, in a fixed order, and the inputs
// that gave it. A single value that is unknown, or comes from a source that failed, is null. A
// list that has no entries is [] and a list from a source that failed is null. [Fields] selects
// which keys a call returns and which sources that needs, and [Projected] is a record cut down to
// them, which is what --json writes.
//
// An address is contacted when --active sent it anything (a TCP handshake, a TLS handshake or an
// HTTP request). A record that was not contacted says why in not_contacted.
//
// # Inputs
//
// [ParseInputs] classifies the arguments into a [Plan]: literal addresses, CIDRs, hostnames and
// invalid inputs, in the order given. Everything here is pure: the plan says which hostnames to
// resolve, [Plan.LiteralCount] says whether the literal addresses and CIDRs alone pass the cap
// (before any CIDR is expanded), and once the hostnames are resolved [Plan.Addresses] gives every
// distinct address once, at its first appearance, with the hostnames that gave it and how it was
// found (as a literal, in a CIDR, from a public resolver or from this machine's resolver).
//
// # The end of a call
//
// [Deadline] is the call's default deadline from the number of addresses, and
// [Plan.ProvisionalCount] the number to use before the hostnames resolve. [Outcome] turns the
// result of every input and every address into the records to return, the meta.errors entries
// and the error the call ends with, through internal/batch so that it ends as nyx cve does. A
// quota failure is listed in its record and ignored by everything else. [Render] lays records out
// for a person.
package iplookup
