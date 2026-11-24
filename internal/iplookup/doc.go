// Package iplookup implements nyx ip input planning, source lookups, records, field selection,
// outcomes and human formatting. Network operations go through egress; internal/cli owns flags,
// worker scheduling and output writing. Record and envelope keys are stable interfaces.
//
// # Records and sources
//
// Each distinct address has one record with its kind, contributing inputs and selected fields.
// Non-public addresses are never sent to third parties or public DNS. Unknown scalar values are
// null. Empty successful lists are []; lists from failed sources are null.
//
// Sources are ordered as cymru (origin AS), rdap (registration), ptr (reverse names), ripestat
// (location), internetdb (services and vulnerability data), hackertarget (other hostnames) and
// probe (--active target contact). Provider labels come from built-in data using the AS number.
// Abuse and DROP matches use embedded or separately downloaded lists without network requests.
// Network matches always answer for public addresses; ASN matches depend on Cymru.
//
// A Failure records a source that failed, timed out, was rate-limited or was skipped after an
// earlier refusal. Empty replies and 404s count as answers. HackerTarget quota failures remain
// in records but do not affect batch success. Remote probe outcomes, including closed ports and
// non-TLS services, are results; local probe failures are source failures. contacted means
// --active sent traffic; not_contacted explains skipped contact.
//
// # Inputs and outcomes
//
// ParseInputs builds a Plan without I/O. LiteralCount checks the cap before expanding CIDRs.
// After DNS resolution, Addresses deduplicates addresses in first-appearance order and retains
// hostnames and how each address was found. Active mode may use the local resolver.
//
// Fields determines selected keys and required sources; Projected supplies JSON output.
// Deadline and ProvisionalCount choose default timing. Outcome combines input and address
// results through internal/batch, matching CVE command outcome rules. Render formats records
// for people.
package iplookup
