---
name: nyx-cve
description: >-
  Look up CVEs by ID in the NVD using the nyx CLI's `cve` subcommand. Use when you need the
  description, status, publication dates, CVSS score, severity and vector, CWE weaknesses,
  affected products (CPEs) or references for one or more CVE IDs.
metadata:
  version: 1.0
---

`nyx` is a passive-first reconnaissance CLI. Its `cve` subcommand looks each CVE ID up in the NVD
and returns one record per ID, covering:

- **Identity**: ID, NVD status, published and last-modified dates, and description
- **Severity**: one CVSS score (the highest version present, preferring the NVD's own) with its
  severity, vector and source
- **Weaknesses**: CWE values
- **Affected products and references**: counted by default; `--fields all` (or naming them) lists
  them, and `--match` and `--limit` narrow the lists

It contacts only the NVD, needs no engagement and writes no files. It works without an API key but
is paced to the NVD's rate limit, which is ten times faster when `NVD_API_KEY` is set.

Run `nyx cve help` for the inputs, flags, fields and exit codes. Use `--json` when you will parse
the output.
