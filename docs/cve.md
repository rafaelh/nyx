# CVE lookup

`nyx cve` looks CVEs up in the NVD by CVE ID and returns one record for each ID the NVD holds. By
default a record has every field but the two long lists, the affected products and the references,
and in their place the number of entries in each, so a record is as short for CVE-2021-44228 as for
a CVE with one entry in each list. Ask for the lists, or for part of them, when you need them.

```sh
nyx cve CVE-2021-44228 CVE-2024-3094 --json
nyx cve - --json < ids.txt
nyx cve CVE-2021-44228 --fields id,cvss_score,cvss_severity --json
nyx cve CVE-2021-44228 --fields affected_products --match log4j --limit 10 --json
```

- **IDs.** Pass one or more as arguments, or a lone `-` to read them from stdin, one per line, with
  blank lines ignored. `-` alongside other arguments exits 2, and so does a bare `nyx cve` or a `-`
  with no IDs on stdin, with the hint `nyx --help`. Case and surrounding whitespace are tidied
  (`cve-2021-44228` is `CVE-2021-44228`), an ID given twice is looked up and returned once, and
  records come back in argument order. Every ID is checked against `CVE-YYYY-NNNN` (four or more
  digits) before the first request. A malformed one becomes an `INVALID_INPUT` entry and the others
  are still looked up.
- **The record.** These are the keys, in this order, and `--fields all` returns every one. A key with
  no value is `null`, and an empty list is `[]`. A rejected CVE is a record with the status
  `Rejected`, not a not-found.

  | Key | Meaning |
  |---|---|
  | `id` | The CVE ID |
  | `status` | The NVD's status: `Analyzed`, `Modified`, `Awaiting Analysis`, `Rejected` and the like |
  | `published`, `last_modified` | RFC 3339 in UTC, to the second |
  | `description` | The first English description, trimmed, else the first in any language |
  | `cvss_version`, `cvss_score`, `cvss_severity`, `cvss_vector`, `cvss_source` | One CVSS score: the highest version present (4.0, 3.1, 3.0, then 2.0), and within it the NVD's own (`Primary`) score over anyone else's. The severity is upper case |
  | `weaknesses` | The English CWE values, de-duplicated in order (`NVD-CWE-Other` and `NVD-CWE-noinfo` are kept) |
  | `affected_products_count`, `references_count` | How many entries the list after it has, as an object: `{"total":n}`, with `"matched":m` added under `--match` and `"omitted":k` under `--limit` when its list is shown too (see below). Every value is a number, and which keys there are depends on the flags, never on the data |
  | `affected_products` | Each vulnerable CPE match, once: `cpe`, `vendor`, `product`, `version` (from the CPE, unescaped, `null` for `*` or `-`) and the four `version_start_*`/`version_end_*` bounds |
  | `references` | Each reference's `url` and `tags` |

- **`--fields a,b,c`** returns only those keys, plus `id`, in both modes; `all` returns every key,
  both lists and both counts included, and `--fields ""` returns `id` alone. An unknown name exits 2
  with the valid names in the hint. Without `--fields` a record has every key but
  `affected_products` and `references`. A count can be named like any field, and naming a list
  brings its count with it, so a list is never shown without its numbers.
- **How to see the lists.** When the default or `--fields` leaves out a list that at least one
  record has entries in (matching entries, under `--match`), the call says once how to see it,
  naming only the lists that have some: `use --fields affected_products,references (or --fields all)
  to list them`. Under `--json` it is `meta.hint`. In human mode a list shown only as its count has
  the flag that lists it after its heading,
  `Affected Products (--fields affected_products to show)`, in the muted colour, and nothing is
  written to stderr; a list left out with its count has no section to say it in. Nothing is said when nothing was left out, or what was left out has no
  entries.
- **`--limit N`** shows at most the first N entries of each list that is shown, in the NVD's order,
  and says how many were left out: `"omitted":k` in the count under `--json` (`0` when none were),
  and a line `k more not shown` after the list in human mode, only when k is above 0. By default
  there is no limit. N must be a positive whole number and `--limit` may be given once; anything
  else exits 2, and so does `--limit` when `--fields` shows neither `affected_products` nor
  `references`. It limits entries, never records: every ID given is still returned.
- **`--match TEXT`** keeps only the entries of the lists whose text contains TEXT, ignoring case.
  For an affected product that is the line human mode shows (vendor, product, version and the
  version bounds, such as `apache log4j (>= 2.0.1, < 2.3.1)`, and not the fixed `cpe:2.3:<part>:`
  start of its CPE), and for a reference it is the URL or any one of its tags. The match is made
  against the NVD's text as `--json` writes it. Surrounding whitespace in TEXT is trimmed; an empty
  TEXT or a second `--match` exits 2, and so does `--match` when `--fields` shows neither list nor
  either count. The default shows the counts, so `nyx cve CVE-2021-44228 --match log4j` says how
  many entries match. With `--match` a count has both `"matched":m` and `"total":n` (`3 of 163` in
  human mode), and the match comes before `--limit`, so a limit and the number left out refer to the
  matching entries. `--match` never removes a record: a list with no matching entry says that
  nothing matched (`No affected products match.`), which is not the NVD listing none.
- **`--json`** prints one compact object,
  `{"data":[…],"meta":{"count":n,"errors":[…],"warnings":[…],"hint":…}}`. `meta.errors`,
  `meta.warnings` and `meta.hint` are always present: `[]` when there are no errors or warnings, and
  `null` when there is no hint. Each `meta.errors` entry has the five keys of
  the error (see [Errors](exit-codes.md#errors)), with the argument exactly as given in `input`. The NVD's text
  is written as the NVD sent it.
- **Without `--json`** each record is laid out for reading: its ID and a severity badge, then a
  section each for the status and dates, the description, the CVSS score, the weaknesses, the
  affected products and the references, as `--fields` selects them. A list's section has its number
  in the heading, `Affected Products (163)`, or `Affected Products (3 of 163 match)` under
  `--match`; where only the count is shown, the section is that number alone, `163 listed` or
  `3 of 163 match`. The dates are the day and a 12-hour time in the local time zone (`TZ`), then
  the moment in UTC as `--json` writes it: `2021-12-10 9:15 PM (UTC 2021-12-10T10:15:09Z)`.
  Records are separated by a
  blank line, and text is wrapped to `COLUMNS` (default 100, at least 60). The NVD's text is
  stripped of anything that would act on a terminal. On a terminal the layout is the one in
  [Terminal layout](console-and-json.md#terminal-layout): a header bar, headings, and labels with no colon.
- **The key.** `keys.nvd` in the config file. `nyx cve` takes `--config` and reads the
  configuration as recon does: an unreadable or invalid config file exits 2, and a missing default
  file is fine. `NVD_API_KEY` and `NYX_KEYS_NVD` are not read. The key never appears in any output.
- **Pacing.** Requests are paced to the NVD's rate limit with a sliding window: 50 per rolling 30
  seconds with a key and 5 without, with at most 4 in flight. A batch longer than that waits for the
  window, within the deadline.
- **`--timeout`** (default `60s`) is the deadline for the whole call. A network error, a 502, 503 or
  504, and a rate-limit answer (a 429, or a 403 that does not name the API key) are retried up to
  twice, after the NVD's `Retry-After` when it gives one in seconds, else after a backoff of about
  1s, then 2s. A wait that would pass the deadline fails that ID at once, marked transient, with the
  wait in its hint: `RATE_LIMITED` when it was for the window or for a rate-limit retry, `TIMEOUT`
  otherwise. A request still in flight at the deadline is `TIMEOUT`. A stdin that is not closed by
  the deadline is `TIMEOUT` too.
- **A refused key** is `AUTH_FAILED` (exit 1), however the NVD says so: a 401, or a 403 or 404 whose
  `message` header or body names the API key. The first refusal stops the batch: the IDs not yet
  sent fail with the same error. A 404 that does not name the key is `UPSTREAM_ERROR` (the NVD
  answers 404 to a parameter it refuses), never `NOT_FOUND`: an ID the NVD does not hold is a 200
  with no results.
- **Contact.** `nyx cve` contacts only `services.nvd.nist.gov`, keeps no state and writes no files,
  so the same call gives the same result.

**The outcome** of a call depends on how many IDs succeeded:

| Outcome | Exit | stdout |
|---|---|---|
| Every ID succeeded | 0 | The records |
| Some succeeded | 7 | The records and the failures |
| None succeeded, all with one error code | That code's: 3 when all are `NOT_FOUND`, 1 for `AUTH_FAILED` or `RATE_LIMITED`, 2 when every ID is malformed | Empty. The one error covers every ID: its `input` is `{"id":[…]}`, the IDs as given |
| None succeeded, with different codes | 7 | No records, and the failures |

On exit 7 the `PARTIAL` error counts what succeeded and what did not (`3 of 5 IDs returned, 2
failed`, or `none of 3 IDs returned`), its `input` lists the IDs that failed as given, and it is
transient when any failure is. In human mode one `error: <input>: <message> (<CODE>)` line follows
for each ID that failed. The hint is the command to run for the IDs worth retrying (the transient
failures), with the flags you gave, after the longest known wait: `after 25s, run: nyx cve
CVE-2024-3094 --json`. When none is worth retrying it lists the IDs to check. Past 20 IDs it points
at the failures instead of listing them. A single-code error that is transient carries the same
command, listing every ID however many, as its failures are not written; when the code is `TIMEOUT`
it adds `, or raise --timeout`. One that is not transient keeps its code's hint, such as `check the
ID; the NVD lists only published CVEs` or `check keys.nvd in <config file>`.

**Differences from the `cve` tool.** The default record leaves out the affected products and the
references, which the `cve` tool returns, and has a count of each (see above). A 404 is never "not
found" (see above). The `--api-key` flag and the `NVD_API_KEY` variable are gone: the key comes
only from `keys.nvd`. Colours are nyx's palette.

**A deliberate break.** Leaving the two lists out of the default record broke the promise that
every record has every key (see [Errors](exit-codes.md#errors), "What stays stable"). It was made once, on
purpose, in the change that added `--limit` and `--match`: ask for `--fields all` to get the
previous record, with a count in front of each list.
