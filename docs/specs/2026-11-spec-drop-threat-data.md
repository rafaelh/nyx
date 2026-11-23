# Spec: Spamhaus DROP threat data

## Goal

nyx flags addresses that Spamhaus's Don't Route Or Peer (DROP) lists name (netblocks and ASNs
hijacked or run by criminals), alongside ipapi.is's abuse lists, in `nyx recon` and `nyx ip`. These
lists change daily, and a stale copy both gives false flags and misses new ones. A copy built into a
binary is only as fresh as the build. So a user can bring both threat-data sources (Spamhaus and
ipapi.is) up to date without a new build, with one command or from `nyx setup`, and nyx tells them
when the data in use is old.

Done when:

- an engagement address that a DROP or DROPv6 entry holds gets a high finding;
- `nyx ip` reports the DROP entries for an address;
- after an update, the next recon run or `nyx ip` call uses the new lists, with no new build;
- a run whose threat data is more than 30 days old says so, and names the command that updates it.

## Behaviours

### The data

- **B1 Built in.** nyx ships a copy of DROP (IPv4), DROPv6 and ASN-DROP alongside ipapi.is's two
  lists, five lists in all. Checking an address against them sends no request.
- **B2 Credit.** Spamhaus is named as the source wherever a DROP match is described: the `nyx ip`
  record's documentation, the CSV's documentation, and the finding types in `nyx help findings`.
  `docs/abusive-networks.md`, the setup tab (B25) and the update's output (B19) show Spamhaus's
  copyright line and a link to its terms.
- **B3 Dates.** Each list is dated as precisely as its source dates it, and written the same way in
  the `nyx ip` record, the CSV and the update's envelope:
  - a Spamhaus list to the second (from its timestamp), as an RFC 3339 UTC timestamp;
  - an ipapi.is list to the day, as `YYYY-MM-DD`.
- **B4 Information only.** A DROP match, like an ipapi.is match, changes only the finding and the
  record. It never changes the scope, what is contacted, which addresses are port-checked, or the
  ranking of candidates.

### Matching

- **B5 Matching.**
  - An address matches a DROP or DROPv6 entry when the listed CIDR holds it.
  - It matches an ASN-DROP entry when its origin AS (the first one Team Cymru gives, as today) is
    the listed one.
  - An IPv4-mapped IPv6 address is matched as its IPv4 address, as it already is for ipapi.is.
  - Every matching entry is reported, the most specific CIDR first.
  - Spamhaus's text (SBL ID, RIR, AS name, country, domain) is cleaned of anything that acts on a
    terminal, as other third-party text is.

### `nyx ip`

- **B6 Record keys.** The `nyx ip` record gains two keys, both in the default selection:
  - the DROP network entries that hold the address, each with its CIDR, SBL ID, RIR and the list's
    date;
  - the ASN-DROP entry of the address's origin AS (at most one), with its ASN, AS name, country,
    domain, RIR and the list's date.

  They follow the rules of `abusive_networks` and `abusive_asn`:
  - The network key needs no request and is `[]` when nothing holds the address. While it is
    selected, it counts as a source that always answers.
  - The ASN key asks Team Cymru. It is `[]` when the AS is known and not listed, and when Team
    Cymru found no owner. It is `null`, and the call exits 7, when Team Cymru failed.
  - Both keys are `null` for a non-public address.

  An empty field in a Spamhaus row is an empty string. Both keys join the stable interface.

### Recon

- **B7 Severity.** Each checked address with any match is still one `abusive-network` finding. Its
  type and severity are those of its strongest match, in this order:
  1. `drop-network`, high: a DROP or DROPv6 entry holds the address;
  2. `drop-asn`, medium: ASN-DROP lists the address's origin AS;
  3. `network`, medium (as today);
  4. `asn`, low (as today).
- **B8 CSV.** `risk-abusive-network.csv` lists the DROP network entries and the ASN-DROP entry
  alongside the ipapi.is ones, with the date of each DROP list that matched.
- **B9 Help.** `nyx help findings` lists `drop-network` and `drop-asn` with the other finding
  types and their severities.
- **B10 Addresses checked.** The same addresses are checked as today (see
  `docs/abusive-networks.md`). The origin AS that recon already finds for each address is checked
  against ASN-DROP as it is against ipapi.is's ASN list. This includes the AS from the
  `netblockowner` lookups.
- **B11 After a change of data.** When the data in use changes, from an update or a newer build, the
  next run's findings reflect it, with no request:
  - a finding that rises in severity is announced again;
  - a finding whose strongest match weakens (for example, DROP drops the address but ipapi.is still
    lists it) stays one current finding at the lower type and severity, and is not announced;
  - a finding with no match left is no longer current.

  A recon run uses the data in place when it started, through all its passes. `nyx recon export`
  reads no threat data, and shows the findings as of the last run.

### Updating

- **B12 Command.** `nyx setup --update-threat-data` updates the five lists and exits. It never opens
  the editor, and it reads no config file, so it still runs:
  - when stdin and stdout are not terminals;
  - when there is no config file;
  - when the config file is invalid.

  `--config` is accepted and ignored. Given an argument, it exits 2, as setup does today.
  `nyx setup --help` lists the flag.
- **B13 Requests.** An update sends at most one request per list, with no retries, and nothing to
  any target: one to `www.spamhaus.org` for each of `drop_v4.json`, `drop_v6.json` and
  `asndrop.json`, and one to `ipapi.is` for each of its most-abusive networks and ASNs pages.
  - Once one of a source's requests fails, that source's remaining requests are not sent.
  - A redirect fails that source. (amended by D6)
  - Each request gives up after 30 seconds.
  - The hosts are listed under Passive boundary.
- **B14 Nothing else contacts them.** No recon stage, `nyx ip`, `nyx cve` or key test sends anything
  to Spamhaus or ipapi.is as a threat-data source. Only an update does, and only when the user asks
  for one.
- **B15 Validation.** A download is refused, and its source fails and keeps its previous copy, when
  any of these is true:
  - a row doesn't parse, or lacks a required field (an unknown field in a row is ignored);
  - any text holds a control character;
  - an entry is listed twice (a DROP or DROPv6 entry is its CIDR and SBL ID together, so one CIDR
    under two SBL IDs is two entries; an ASN-DROP entry is its ASN; an ipapi.is entry is its range
    or ASN) (amended by D2);
  - a Spamhaus file has no final metadata row;
  - a list holds fewer than 90% of the entries it says it has;
  - a list has no entries, or fewer than half the entries of the copy in use;
  - a list is dated after the end of tomorrow, UTC.

  A list refused for shrinking names the rule and both counts, and says that a newer build of nyx
  is the remedy.
- **B16 Already current.** A list dated no later than the copy in use is reported as already current
  and left as it is. If none of a source's lists is newer, the source is already current, which
  counts as a success. The exception is B24: an unreadable downloaded copy is always replaced.
- **B17 Per source.** Each source is replaced as a whole or not at all. Spamhaus's three lists are
  one source, and ipapi.is's two lists are the other.
  - An update interrupted by a signal, a crash or quitting setup leaves each source with either its
    previous copy or its complete new one.
  - A command that reads threat data while an update runs sees each source's previous copy or its
    complete new one, never a mix.
  - A download that passes validation but can't be stored (permission denied, disk full) fails its
    source with `UNEXPECTED_ERROR` and the reason, and leaves the previous copy in place.
- **B18 Rate limit.** Within an hour of the last time a source sent nyx an HTTP response, whatever its
  status, an update sends nothing to that source. It reports when the source was last contacted
  and when it can be updated next, and the source counts as skipped.
  - A request that got no response (DNS, connect, TLS, reset, timeout) does not start the hour.
  - When two updates run at once (in two terminals, or the command and setup), the second waits for
    the first to finish with each source, then applies this rule to that source as the first left
    it: skipped when the first got a response, and otherwise it sends its own requests. Each update
    sends a source at most one request per list. (amended by D5)
  - A recorded time in the future is replaced by the current time when an update reads it, so the
    source can be updated again at most an hour later.
- **B19 Output.** For each list, the update prints its source, its old and new date, its entry
  count, and how many entries were added and removed. A list that wasn't replaced instead says it
  is already current, skipped (with when it can next be updated) or failed (with the reason). The
  output ends with Spamhaus's copyright line and terms link. It goes to stdout, and `--quiet` does
  not suppress it.
- **B20 Outcome.** The update exits:
  - 0 when every source updated, was already current, or was skipped;
  - 7 (`PARTIAL`) when one source failed, whatever the other did;
  - 1 when both failed, with their shared error code, or `UPSTREAM_ERROR` when the codes differ.
    Stdout is then empty, and the error gives each source's reason;
  - 130, 143 or 129 on a signal.

  A failure's error code is:
  - `NETWORK_ERROR` for a network failure;
  - `TIMEOUT` when a request gives up after its 30 seconds;
  - `RATE_LIMITED` for a 429;
  - `UPSTREAM_ERROR` for any other answer or a refused download;
  - `UNEXPECTED_ERROR` for a download that can't be stored (B17).

  The error is transient when any failure was a network failure, a timeout or a 429. Its hint says
  when each failed source can next be updated. `docs/exit-codes.md` lists the update's codes.
- **B21 `--json`.** Under `--json`, on exit 0 or 7, the update writes one envelope.
  - For each list it gives the source, the old and new date, the entry counts, and the counts added
    and removed.
  - For each source it gives the outcome: updated, already current, skipped (with when it can next
    be updated) or failed (with the error code and reason).
  - The Spamhaus source also gives Spamhaus's copyright line and terms link. (amended by D9)

  The envelope's keys join the stable interface.

### Where the downloaded copy lives

- **B22 Location.** The downloaded copy is kept beside the default config file, in the
  `threat-data` directory of `$XDG_CONFIG_HOME/nyx/` or else `~/.config/nyx/`, whatever `--config`
  a command is given (amended by D8). One
  update therefore applies to every engagement and to `nyx ip`, and nyx reads no new environment
  variable.
  - With neither variable set, the update exits 2 and says why. Recon and `nyx ip` then use the
    built-in data, with no warning and no stale hint.
  - `docs/abusive-networks.md` names the location, and says that deleting the `threat-data`
    directory restores the built-in data (amended by D8).
- **B23 Precedence.** For each list, nyx uses whichever copy, built-in or downloaded, is dated later.
  When both have the same date, the downloaded one is used.
- **B24 Unreadable copy.** A downloaded source is used only when all of its lists:
  - parse;
  - hold no control character;
  - list no entry twice (an entry as B15 defines it);
  - have their final metadata row (Spamhaus) or their date and stated count (ipapi.is, whose
    downloaded copy is kept parsed, as the built-in one is);
  - hold at least 90% of the entries they say they have. (amended by D2, D7)

  Otherwise the whole source falls back to the built-in copy. Each command that reads threat data
  (recon runs and `nyx ip`, not `nyx recon export`) then warns once on stderr. Under `--json` the
  warning is an entry in `meta.warnings`. `--quiet` doesn't suppress it. An update replaces the bad
  copy with what it downloads, even when the download is no newer than the built-in copy, and the
  warning then stops.

### Setup

- **B25 Threat data tab.** `nyx setup` gains a Threat data tab. It lists the five lists, each with
  its source, its date, its entry count, and whether the copy in use is built in or downloaded. The
  tab also shows Spamhaus's copyright line and terms link.
- **B26 Updating from setup.** `u` on the tab runs the same update as B12 to B18.
  - While it runs, the tab shows it as in progress.
  - When it ends, each list shows its result in place, including when a skipped source can next be
    updated and the reason a source failed.
  - Quitting during an update abandons it, as B17 describes.
  - An update isn't an unsaved change: it writes no config, and quitting after it doesn't ask to
    save.
  - The update's result doesn't change setup's exit code.

### Staleness

- **B27 Stale hint.** A source is stale when more than 30 days have passed since both:
  - the oldest date among the source's lists in use;
  - its last successful check, meaning an update that found the source updated or already current.

  For each stale source, `nyx recon` (a run, not `export`) and `nyx ip` print one line on stderr
  that gives that oldest date, for example:
  `hint: Spamhaus DROP data is from 2026-10-01; run nyx setup --update-threat-data`.
  - `nyx ip` prints it only when a selected key reads that source.
  - Under `--json`, the notice is an entry in `meta.warnings` for both recon and `nyx ip`.
  - Under `--quiet` alone, nothing is printed.
  - It isn't printed on a usage error, and it comes after the no-config hint.

### Maintainer refresh

- **B28 `make threat-data`.** `make abusive-data` is renamed `make threat-data`.
  - It refreshes the built-in copies of all five lists with the same checks as B15, except that a
    maintainer who has reviewed a shrunken list can let it through with `ALLOW_SHRINK=1`, which
    `docs/abusive-networks.md` describes (amended by D26).
  - It leaves a list dated no later than the built-in copy as it is.
  - It prints what was added, removed and changed.
  - It replaces each source's copy as a whole or not at all.

  The docs give each built-in list's date, and a test fails if they don't.
- **B29 Docs.** Every statement this change makes untrue is brought in line, and in particular:
  - `docs/abusive-networks.md` and `docs/passive-boundary.md` describe DROP, the credit, the update
    and its hosts. "nyx never contacts ipapi.is" becomes: nyx contacts Spamhaus and ipapi.is only
    when the user asks for an update.
  - The `nyx ip` page says what it reads (the downloaded threat data, when present), and that its
    result depends on the threat data in use. Its sources table names both copies.
  - The setup page and `nyx setup --help` describe the update as setup's one non-interactive use,
    with its own exit codes, and the files it writes besides the config.
  - The contributor notes name `make threat-data`.

## Out of scope

- Following a redirect, even to the same host (D6).
- Asking Spamhaus or ipapi.is anything from recon, `nyx ip`, `nyx cve` or a key test (B14).
- Raw HTML for the downloaded ipapi.is copy (D7).
- A notice that DROP data is in use at all: the credit appears only where B2 says.

# Design

## External facts

- **Spamhaus DROP files** (*confirmed live*, fetched 2026-11-23 with
  `for f in drop_v4.json drop_v6.json asndrop.json; do curl -sS -D $f.headers -o $f https://www.spamhaus.org/drop/$f; done`):
  - Each is JSON lines: one object per line, then a final metadata line
    `{"type":"metadata","timestamp":<unix seconds>,"size":<bytes of the data lines>,"records":<data lines>,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`.
    `records` equalled the number of data lines in all three.
  - `drop_v4.json` / `drop_v6.json` rows: `{"cidr","sblid","rir"}`. 1,752 IPv4 rows (prefixes /12 to
    /32), 90 IPv6 rows (/29 to /48). All CIDRs are canonical (host bits zero). Ranges nest (78
    overlapping pairs in IPv4).
  - `rir` can be JSON `null` (2 IPv4 rows today). RIRs seen: afrinic, apnic, arin, lacnic, ripencc.
  - `62.60.226.0/24` is listed twice, under SBL697779 and SBL671779. An SBL ID can cover several
    CIDRs, both IPv4 and IPv6 (SBL300238 has one of each).
  - `asndrop.json` rows: `{"asn","rir","domain","cc","asname"}`, 459 rows, all fields present, no
    repeated ASN. Text is UTF-8, and can be non-ASCII (`América_Latina_Educacional_Adm._e_Serviços_LTDA`).
  - Timestamps differ per list: v4 2026-11-21T17:56:44Z, v6 2026-11-20T09:56:44Z, ASN
    2026-11-23T03:26:44Z.
  - Served `200` directly from `www.spamhaus.org`, with no redirect. Content-Type `text/json`,
    `cache-control: public, max-age=3600`, behind Cloudflare. Sizes are 107 KB, 6 KB and 41 KB.
- **Spamhaus terms** (*confirmed live*, `curl -sSL https://www.spamhaus.org/drop/terms/`):
  - The metadata's terms URL redirects to `https://www.spamhaus.org/blocklists/drop-fair-use-policy/`.
  - §3.1: copyright and database right, and no licence is granted.
  - §3.2: the Spamhaus name may not be used in marketing or commercial materials.
  - §4.2: check regularly for the latest version.
  - The user chose to embed the lists anyway (D1).
- **ipapi.is pages** (*confirmed live*, fetched 2026-11-23 with
  `curl -sS -o networks.html https://ipapi.is/most-abusive-networks.html; curl -sS -o asns.html https://ipapi.is/most-abusive-asn.html`):
  - Both answer `200` with no redirect; the pages are 2.44 MB and 0.48 MB of HTML.
  - Today's `internal/abusive/refresh` parses both (dated 2026-11-22), in about 0.1 s.
  - There is no `Retry-After` or caching header beyond `Last-Modified` and an `ETag`.
- **egress** (*codebase*):
  - It never follows a redirect: the 3xx comes back as a response (`internal/egress/egress.go:184`).
  - It never retries.
  - The body cap is 10 MiB, reported as `Truncated`, not as an error (`internal/egress/thirdparty.go:22`).
  - A nil error means a response arrived. A failed body read after the headers is also an error.
  - `scrub` drops error wrapping, so a timeout is detected from the request's own context, as
    `internal/cve/client.go` does.
  - `ThirdPartyRequest.Timeout` caps at 120 s.
- **Config path** (*codebase*): `config.DefaultConfigPath(env)` gives `$XDG_CONFIG_HOME/nyx/config.yaml`,
  else `$HOME/.config/nyx/config.yaml`, else "" (`internal/config/config.go:291`).

## Decisions

- **D1 Licence.** The built-in copy includes Spamhaus's three lists, as B1 says (user). The
  credit of B2 is the mitigation. See Follow-ups.
- **D2 What one entry is** (user). A DROP/DROPv6 entry is its (CIDR, SBL ID) pair. An ASN-DROP
  entry is its ASN. An ipapi.is entry is its range or ASN, as today. Only an identical pair is
  "listed twice". Both of today's 62.60.226.0/24 rows are entries, and both are reported.
- **D3 `nyx ip` keys** (user). They come after `abusive_asn` in the field order and are in the
  default selection (`AllFields`).
  - `drop_networks: [{"cidr","sbl_id","rir","updated"}]` has no source, so `Sourceless()` makes it
    a source that always answers.
  - `drop_asn: [{"asn","as_name","country","domain","rir","updated"}]` has the source `SourceCymru`
    and shares the origin lookup with `abusive_asn`: `[]` when the AS is unknown or not listed, and
    `null` when the origin lookup failed.
  - Both are `null` for a non-public address. `updated` is RFC 3339 UTC to the second. A
    null or missing field is `""`.
- **D4 Update envelope** (user). Every key is always present:
  `{"data":{"sources":[...],"lists":[...]},"meta":{"errors":[...],"warnings":[...],"hint":null}}`.
  - A source is `{"source","outcome","last_contacted","next_update","copyright","terms","error"}`:
    - `source` is `spamhaus` or `ipapi.is`.
    - `outcome` is `updated`, `current`, `skipped` or `failed`.
    - `last_contacted` and `next_update` are RFC 3339 or null. `next_update` is set when skipped,
      and when failed after a response.
    - `copyright` and `terms` are null for ipapi.is.
    - `error` is null, or the five-key JSON error (`code`, `message`, `hint`, `input`, `transient`),
      as in `meta.errors`.
  - A list is `{"list","source","old_updated","new_updated","old_entries","entries","added","removed"}`.
    - The list names are `drop_v4`, `drop_v6`, `asndrop`, `networks` and `asns`.
    - The `old_*` keys describe the copy in use before the update, and the others the copy in use
      after it. They are equal unless the list was replaced.
    - Spamhaus dates are RFC 3339 and ipapi.is dates are `YYYY-MM-DD`.
  - `meta.errors` holds the failed sources' errors.
- **D5 Two updates at once** (user). After taking the source's lock, an update applies B18's hour
  rule from the state the other left. The lock is a `flock` on `<dir>/<source>.lock`, taken with
  `LOCK_NB` and retried every 100 ms until the context ends, so a signal or quitting setup still
  ends the wait. A blocking `flock` can't be cancelled, so the lock polls.
- **D6 Redirects** (user). Any 3xx fails the source with `UPSTREAM_ERROR` ("redirected to <Location>,
  which nyx does not follow"). It counts as a response for B18.
- **D7 ipapi.is downloaded copy** (user). It is stored parsed, in the format of the built-in
  `internal/abusive/snapshot.json`. That format gains `"stated"` (the count the page states) in each
  list, the built-in included, so the 90% check of B24 applies to it.
- **D8 Location** (user). The directory is `filepath.Join(filepath.Dir(config.DefaultConfigPath(env)), "threat-data")`.
  It is "" when that path is "". It is created with mode 0700, and its files have mode 0600.
- **D9 Credit in JSON** (user). The Spamhaus source object carries `copyright` and `terms`.
  At run time (the envelope, the human output and the setup tab), both come from the metadata of
  the `drop_v4` list in use. They are checked for control characters (D12), sanitised, and fall back
  to the built-in copy's when that row lacks them. Only the docs use a fixed string (D25).
- **D10 Packages.**
  - `internal/abusive` stays the ipapi.is package. It gains `ParsePages` (moved from
    `internal/abusive/refresh`, still pure: `golang.org/x/net/html` is already in `go.mod`) and the
    `stated` counts.
    - `ParsePages` loses today's `previous` parameter and its "older than the snapshot's" refusal
      (refresh.go:237). Comparing dates is the shared acceptance rules' job, and B16 calls an
      older list current, not refused.
    - `ParsePages` keeps the future-date check, and `Validate` keeps its rank ≥ 1, score 0–100
      and order rules. These count as "a row doesn't parse" (B15).
  - New `internal/spamhaus` is pure, with no I/O. It holds the three lists: parsing the raw files
    and the bundle (D11), validation, matching (D14), and the embedded built-in `builtin.jsonl`.
  - New `internal/threatdata` holds the five lists in use. It has:
    - `Dir(env)`;
    - `Load(dir, now) Set`, with precedence (B23), the fallback and warnings (B24) and staleness
      (B27);
    - the acceptance rules shared with the maintainer tool (B15, B16): shrink, future date and
      already current;
    - `Update(ctx, Options) Result`, which works through an `egress.ThirdPartyHTTP` and does file
      I/O but no network I/O itself.
  - The lock is about ten lines in `internal/threatdata`, beside the engagement's. `boundary_test.go`'s
    `unixAllowed` gains `/internal/threatdata`: `Flock`, `LOCK_EX`, `LOCK_NB` and `EWOULDBLOCK`.
    `CLAUDE.md`'s line "flock in `internal/engagement`" changes to name both packages.
  - `internal/abusive/refresh` moves to `internal/threatdata/refresh`.
- **D11 Files and formats.** The files in `<dir>` are:
  - `spamhaus.jsonl`: the bundle, also the format of `internal/spamhaus/builtin.jsonl`. For each
    list in the order v4, v6, asndrop, it holds a marker line `{"list":"drop_v4"}` followed by the
    file's lines exactly as Spamhaus served them, metadata line included. It is one file, so a
    rename replaces the source as a whole (B17), and a refresh's diff is per entry.
  - `ipapi.json`: D7's format. `Load` ignores unknown fields in it, so a file written by a newer
    nyx stays readable (B15 ignores unknown fields too). The built-in file's test stays strict.
  - `<source>.state.json`: `{"last_response":RFC3339|null,"last_checked":RFC3339|null}`.
  - `<source>.lock`.

  Every write goes to a temporary file in `<dir>`, `.<source>-*.tmp`, which is fsynced (unless
  `Deps.NoFsync`) and renamed. A reader opens each file once, so it sees one whole version (B17),
  and never reads a `.tmp` file.
  - A crash, a signal or quitting setup can leave a temporary file behind. The next update of that
    source removes `.<source>-*.tmp` while it holds the lock, which is safe because only the
    lock's holder writes them.
- **D12 Parsing a Spamhaus list** (shared by the update, `Load` and the maintainer tool).
  - Each non-empty line is one JSON object, and unknown fields are ignored.
  - The last line must be `type == "metadata"`, with a `timestamp` > 0 and `records` ≥ 0.
    `copyright` and `terms` are optional.
  - DROP rows require `cidr` and `sblid`. The CIDR must parse, be canonical
    (`p == p.Masked()`), and be of the list's family.
  - ASN-DROP rows require `asn` in 1..4294967295.
  - `rir`, `asname`, `cc` and `domain` are optional: null or absent is `""`.
  - Any C0/C1 control character in any string, the metadata's included, refuses the list. Other
    text is sanitised when matched, as `abusive` does.
- **D13 Dates.**
  - A Spamhaus list's date is its metadata timestamp, and an ipapi.is list's is its `YYYY-MM-DD`.
    Precedence and "newer" compare within one list.
  - "After the end of tomorrow, UTC" means a Spamhaus timestamp at or after 00:00 UTC two days
    from now, or an ipapi.is date later than tomorrow's UTC date.
  - For B27, an ipapi.is date counts as 00:00 UTC of that day. The hint prints the oldest date as
    its UTC `YYYY-MM-DD`.
- **D14 Matching.**
  - A lookup unmaps the address and scans the list of its family; there are under 2,000 prefixes.
  - It keeps every prefix that holds the address and sorts them by length, longest first, with
    ties in file order (a stable sort).
  - ASN-DROP is a map. The origin AS is the same one `abusive_asn` and the recon deriver use today.
- **D15 Update, per source.** The two sources run concurrently, and each source's lists run in
  order. For each source:
  1. Create `<dir>` and take the lock (D5). Remove stale temporary files (D11). Write the state
     back unchanged, to prove `<dir>` is writable before anything is sent. A failure here is
     `UNEXPECTED_ERROR` and sends nothing, so an unwritable directory never sends requests that
     can't be recorded.
  2. Read the state.
     - A `last_response` or `last_checked` in the future becomes now, and is written back at once.
       The fix persists, so the source can be updated at most an hour later (B18), and a future
       `last_checked` can't hide the B27 hint.
     - If `last_response` is less than an hour ago, the source is `skipped`.
  3. Read the copy in use: the precedence winner per list. An unreadable downloaded source counts
     as absent and must be replaced (B24).
  4. Request each list in turn:
     - As soon as `Do` returns a response (nil error), write `last_response = now` to the state,
       before checking anything else. egress reads the whole body inside `Do`, so this is the
       earliest point, and the `threat-after-response` fault point sits there.
     - Check the list as it arrives against the format rules (D12 or `abusive.ParsePages`), the
       stated-count rule and the future-date rule.
     - Any failure, a refused list included, stops the source, and its remaining lists are not
       requested (B13).
  5. Sort the lists:
     - A list dated no later than the copy in use is `current`.
     - A newer list, or every list when the downloaded copy was unreadable, must pass the shrink
       rule against the copy in use.
  6. If nothing is newer and nothing was forced, the source is `current`: write
     `last_checked = now` and leave the data file alone.
  7. Otherwise, write a new data file and then `last_checked`. Each list in it is:
     - the download, when that list is newer or forced;
     - else the previous downloaded list, when it is readable;
     - else the download.

  A failure to write the state or the data file is `UNEXPECTED_ERROR` (B17). `Options` carries the
  directory, the client, `Now`, `NoFsync`, the request timeout (30 s; tests shorten it) and the
  built-in copies. An `internal/fault` point `threat-before-rename` sits between the temporary
  file's fsync and its rename.
- **D16 HTTP.**
  - The client is `egress.New(base).Clients(false, []string{"www.spamhaus.org", "ipapi.is"}).ThirdParty`.
    `base` is `Deps.Egress`, with the default rate per source: three requests in a row wait at most
    2 s. There is no `Policy` and no keys.
  - Each request is a GET with `ThirdPartyRequest.Timeout` set to the request timeout (30 s), as
    `internal/cve/client.go:158` does. Without it, egress applies its own `HTTPTimeout` (15 s
    default, 1 s in the harness, thirdparty.go:109-113). It also runs under a
    `context.WithTimeout(ctx, timeout)` of the same length, so the deadline can be read.
  - Errors map to codes as follows:
    - An error with that deadline passed and the parent alive is `TIMEOUT`.
    - Any other error is `NETWORK_ERROR`, a request with no response, which doesn't start the hour.
    - 3xx is `UPSTREAM_ERROR` (D6).
    - 429 is `RATE_LIMITED`.
    - Any other status but 200 is `UPSTREAM_ERROR` ("HTTP n").
    - `Truncated`, or a list that is refused, is `UPSTREAM_ERROR` with the reason.
  - A body read that fails after the headers is counted as no response, as egress can't tell
    them apart.
- **D17 Outcome (B20).** `internal/cli` builds it from `Result`:
  - No failure exits 0.
  - One failed source is `PARTIAL`.
  - Both failed gives their code when they share one, else `UPSTREAM_ERROR`, and stdout stays
    empty (`endLookup`'s pattern).
  - Each failed source is a `clierr.Target` with `Input` set to the source name.
  - The error is transient when any code is `NETWORK_ERROR`, `TIMEOUT` or `RATE_LIMITED`.
  - The hint names each failed source and when it can next be updated: `last_response` + 1 h, or
    "now" when it got no response.
- **D18 Human output (B19).** One line per list, written to stdout even under `--quiet` and
  sanitised, in the shape
  `spamhaus  drop_v4  2026-11-20T09:56:44Z -> 2026-11-21T17:56:44Z  1752 entries (+5, -2)`.
  - A list that wasn't replaced instead ends with `already current`, `skipped: last contacted <t>;
    can be updated after <t>`, or `failed: <reason>`.
  - The last line is `Spamhaus DROP data <copyright>; terms: <terms>`.
- **D19 The flag.**
  - `--update-threat-data` is a bool on `nyx setup`. `runSetup` branches right after
    `inv.problems()` and the argument check.
  - An empty `threatdata.Dir` exits 2 with "nowhere to keep threat data: neither XDG_CONFIG_HOME
    nor HOME is set".
  - It neither reads `--config` nor checks the TTY.
  - The help annotation and `nyx setup --help` list it. The command's `Long` text (setup.go:31-34,
    "edits only the config file") is reworded to name the update and the files it writes (B29).
- **D20 Loading.**
  - `runRecon` calls `threatdata.Load(dir, d.Clock())` once, before the runner, and passes
    `Abusive` and `Drop` through `run.Config` into `findings.Input`. So a run uses the data it
    started with (B11), and `nyx recon export` never loads it.
  - `nyx ip` loads only the sources its selected keys read: `abusive_*` reads ipapi.is, and
    `drop_*` reads Spamhaus.
  - One test override replaces `Deps.Abusive`: `Deps.ThreatBuiltIn` (`threatdata.BuiltIn`, holding
    the ipapi.is snapshot and the Spamhaus lists; nil means the embedded ones).
    - It replaces only the built-in copies, so `Load` still runs. Precedence, the B24 warning and
      the B27 staleness apply in every test.
    - Tests of downloaded copies write files into the harness's `XDG_CONFIG_HOME` temp directory.
    - `run.Config` and `iplookup.Config` take the loaded `Abusive` and `Drop`.
- **D21 Warnings and hints.**
  - B24's warning is a `warning` event through the command's emitter, so it prints under `--quiet`
    and goes to `meta.warnings` under `--json`. It is raised once per source per command:
    "the downloaded <source> data in <dir> is unreadable (<reason>), so nyx uses its built-in copy;
    run nyx setup --update-threat-data to replace it".
  - B27's notice follows the no-config hint's rules:
    - The text is `hint: Spamhaus DROP data is from <date>; run nyx setup --update-threat-data`, or
      `hint: ipapi.is abuse data is from <date>; …`.
    - It is written by `invocation` right after `writeNoConfigHint`, before any error line.
    - It is skipped under `--quiet`, under `--json` and on `INVALID_INPUT`.
    - Under `--json`, the same text without `hint: ` is added to the warnings collector at load
      time, whatever `--quiet` says.
  - With an empty `Dir` there is neither a warning nor a hint (B22).
- **D22 Findings and CSV.**
  - `findings.table` gains `{AbusiveNetwork, "drop-network", High, "… Spamhaus DROP …"}` and
    `{AbusiveNetwork, "drop-asn", Medium, "… Spamhaus ASN-DROP …"}`, and the rows for `network`
    and `asn` are reworded (they no longer say only "a snapshot built into nyx").
  - `abusiveFinding` takes the DROP matches too, and its type is the first of the B7 order that
    has a match.
  - New stored attributes: `drop_networks`, `drop_asn`, `drop_networks_updated` and
    `drop_asn_updated`.
  - `entry` and `org` take the CIDR and SBL ID for `drop-network`, and `AS<n>` and the AS name for
    `drop-asn`.
  - The found line is "address X in Spamhaus DROP network N (SBL…)".
  - The CSV columns are `severity, ip, hostnames, type, drop_networks, drop_asn, networks, asn,
    drop_networks_updated, drop_asn_updated, networks_updated, asns_updated`.
    - A DROP cell entry is `<cidr> <sblid> (<rir>)`.
    - An ASN-DROP entry is `AS<n> <asname> <cc> <domain> (<rir>)`.
    - Entries are joined with `;`.
- **D23 Setup tab.**
  - The new tab `tabThreat` comes after Skip.
  - `setup.Backend` gains `ThreatData() []ThreatList` and `UpdateThreatData(ctx) ThreatResult`.
    `ThreatList` holds the source, list, date, entries, built-in or downloaded, and a note. The
    update runs in a `tea.Cmd` under `m.base`, so `quit()` cancels it.
  - `u` is ignored while an update runs, and the tab then shows "updating…". The result replaces
    each row's status.
  - It is not counted by `changes()`, and its result is never part of `runSetup`'s return.
  - The tab has no 15 s key-test timeout: the per-request 30 s bounds it.
  - With an empty `Dir` (only reachable with `--config`), the tab says why, and `u` shows the
    reason.
  - The credit line sits at the foot of the tab.
- **D24 `make threat-data`.**
  - It replaces `abusive-data` in the Makefile's `.PHONY` and its comment.
  - `ALLOW_SHRINK=1` passes `-allow-shrink`, which lifts only the shrink rule, for a maintainer who
    has reviewed the diff (D26).
  - `curl -fsS --retry 3` fetches the five URLs into a temp directory. Then
    `go run ./internal/threatdata/refresh -dir <tmp> -spamhaus internal/spamhaus/builtin.jsonl -ipapi internal/abusive/snapshot.json`
    runs.
  - The tool applies D12 and D15's rules against the built-in copy and leaves a list that is not
    newer as it is.
  - It prints what was added, removed and changed. For DROP, "changed" means `rir` changed under
    one (CIDR, SBL ID). For ASN-DROP, it means any field changed. ipapi.is keeps today's rule.
  - It writes each source's file atomically on its own, and exits 1 naming any source that failed
    after writing the others.
- **D25 Credit text.** `docs/abusive-networks.md` gives the fixed text `(c) The Spamhaus Project
  SLU` and `https://www.spamhaus.org/drop/terms/`. The run-time places take theirs from the
  metadata (D9). README's credits list adds Spamhaus.
- **D27 File stem of ipapi.is** (settled while writing tests). ipapi.is's per-source files use the stem `ipapi`: `ipapi.json`, `ipapi.state.json`, `ipapi.lock`, `.ipapi-*.tmp`; Spamhaus's use `spamhaus`. (D11 says `<source>`; the source's name `ipapi.is` is not a good file stem.)
- **D26 Shrink override** (user). Only the maintainer tool can lift the shrink rule, with
  `-allow-shrink` (`make threat-data ALLOW_SHRINK=1`). A user's update can't, and B15's remedy (a
  newer build) stays.

## Files

- `internal/spamhaus/` (new): `spamhaus.go` (types, parse, bundle, validate, match) and
  `builtin.jsonl`, plus tests.
- `internal/abusive/abusive.go`: `stated`, and `ParsePages` with the HTML helpers moved from
  `refresh/refresh.go`. The `snapshot.json` regenerated by `make threat-data`.
- `internal/threatdata/` (new): `threatdata.go` (Dir, Set, Load, precedence, staleness),
  `accept.go` (shared rules), `update.go` (Update, state, lock use) and `refresh/` (moved tool).
- `internal/egress/boundary_test.go`: `unixAllowed` gains `/internal/threatdata`.
- `internal/fault`: the points `threat-after-response` and `threat-before-rename`.
- `internal/findings/{abusive.go,table.go,records.go}`: DROP matches, types, columns and the found
  line.
- `internal/run/runner.go`, `internal/run/derive.go`: `Config.Drop` into `findings.Input`.
- `internal/iplookup/{fields.go,record.go,sources.go,render.go,lookup.go,doc.go}`: the two keys and
  `Config.Drop`.
- `internal/cli/cli.go` (`Deps.ThreatBuiltIn` in place of `Deps.Abusive`, the stale hint beside
  `writeNoConfigHint`), `harness_test.go` (`h.abusive` becomes a built-in override), `recon.go`
  (Load), `ip.go` (Load per selected source), `setup.go` (the flag, its branch and `Long`), a new
  `threat.go` (the update's run, output, envelope and outcome), `setup_info.go` (the Backend's
  threat methods) and `help.go` (annotations).
- `internal/setup/{model.go,tabs.go,view.go,backend.go,dialogs.go}`: the Threat data tab.
- `Makefile`: `threat-data`.
- Docs: `docs/abusive-networks.md` (DROP, credit, update, location, five dates), `docs/passive-boundary.md`
  (hosts; "contacts Spamhaus and ipapi.is only when the user asks for an update"), `docs/ip.md`
  (keys, sources table naming both copies, reads the downloaded copy, result depends on it),
  `docs/configuration.md#setup` (the flag as setup's one non-interactive use, its exit codes, the
  files it writes), `docs/exit-codes.md` (the update's codes; the rows for exit 1, 2 and 7),
  `docs/output.md` (`risk-abusive-network.csv` columns), `README.md` (credit), `CLAUDE.md` (the
  `make threat-data` line, the package list, and the flock allowlist line).

## Tests

Behaviours marked **[mutation]** are where a bug does the most harm: contacting a host, losing
data, or the rate limit. Run a mutation check on them in `/spec-develop`.

**Dates in tests.**
- The harness clock is fixed at 2026-11-01, but the built-in lists are dated later (ipapi.is
  2026-11-21, Spamhaus 2026-11-20 to 23), and each `make threat-data` moves them. A fake download
  dated after the built-in copy would then be "after the end of tomorrow".
- So the cli tests of updating, precedence and staleness either:
  - set the clock relative to the built-in copy's dates, read from it, as `eol_test.go:185` does;
    or
  - set `Deps.ThreatBuiltIn` to fixed old lists.
- No test hard-codes a built-in date.

- **B1**: `spamhaus` and `abusive` built-in copies parse and validate. `nyx ip` with every key
  and recon send nothing to either host: canary fake servers on both hosts through `SourceBaseURLs`
  count zero requests.
- **B2**: doc tests cover `docs/ip.md`, `docs/output.md` and `nyx help findings`, which name
  Spamhaus. `docs/abusive-networks.md` has the copyright line and the terms link. A setup view
  test checks the tab's credit. An update-output test checks the last line.
- **B3**: the `nyx ip` JSON gives a DROP `updated` in RFC 3339 and an ipapi.is one in
  `YYYY-MM-DD`. The CSV and envelope give the same strings.
- **B4 [mutation]**: extend `TestAbusiveRecon_InformationOnly` with an address DROP holds. The
  scope, the requests sent, port eligibility and `candidate_rank` are the same as without DROP.
- **B5**: spamhaus unit tests cover:
  - containment at each boundary, IPv6, and an IPv4-mapped address;
  - nested CIDRs reported longest first;
  - one CIDR under two SBL IDs, both in file order;
  - an ASN match;
  - control-free but terminal-acting text sanitised (escape sequences can't occur, so test
    sanitise's other rules).
- **B6**: `nyx ip` tests cover:
  - the default keys, with `[]` when nothing matches;
  - `drop_asn` `[]` for an unknown AS;
  - `null` and exit 7 on a Cymru failure;
  - `null` for a private address;
  - only `drop_networks` selected, where the address still answers;
  - a null `rir` encoded as `""`;
  - key order in `--help`.
- **B7**: findings unit tests cover every combination of the four match kinds, giving type and
  severity, and that it is one finding per address.
- **B8**: a risk-file test checks the columns and the cell text.
- **B9**: `nyx help findings` lists `drop-network high` and `drop-asn medium`.
- **B10**: the netblockowner AS is checked against ASN-DROP; extend
  `TestAbusive_NetblockOwnerAppliesToTheUnit`.
- **B11**: three recon tests:
  - Run 1, then write a downloaded copy into the harness dir, then run 2 with no request. A rise
    to `drop-network` is announced, a weakening to `network` keeps one current finding and is not
    announced, and a finding with no match is not current.
  - A fake stage rewrites the downloaded copy mid-run, and the findings use the copy loaded at the
    start.
  - `nyx recon export` with an unreadable copy prints no warning and the last run's findings.
- **B12**: the update runs with stdin and stdout not TTYs, with no config file, and with an
  invalid config file. `--config /nonexistent` is ignored, an argument exits 2, and
  `nyx setup --help` lists the flag.
- **B13 [mutation]**, with fake servers:
  - exactly five requests, one per URL, and no retry after a 500;
  - a failing `drop_v4` stops `drop_v6` and `asndrop` while ipapi.is is still asked;
  - a 301 to the same host and a 302 to another host each fail the source;
  - a server that stalls past a shortened request timeout gives `TIMEOUT`. The test sets that
    timeout above the harness's 1 s `HTTPTimeout`, for example 1.5 s against a 3 s stall, so a
    request that doesn't set `ThirdPartyRequest.Timeout` fails it with `NETWORK_ERROR`;
  - a refused `drop_v4` (a malformed row) means `drop_v6` and `asndrop` are not requested;
  - the harness's target canaries see nothing.
- **B14 [mutation]**: recon (all stages), `nyx ip` (all keys), `nyx cve` and every key test send
  nothing to `www.spamhaus.org` or `ipapi.is`, and counting fakes stand in for both hosts.
  `TestAbusiveDocs_NoCommandContactsIpapi` (abusive_docs_test.go:115) checks the stages'
  `Sources()`, the `nyx ip` hosts and egress's files. Extend its loops, and keycheck's sources, to
  both hosts, which `threatdata` exports as constants.
- **B15 [mutation]**: a table test with one case per refusal:
  - a malformed row;
  - a missing `cidr`, `sblid` or `asn`;
  - a non-canonical or wrong-family CIDR;
  - a control character in a row and in the metadata;
  - an identical pair twice (while the same CIDR under two SBL IDs passes);
  - no metadata line;
  - 89% of `records`;
  - zero entries;
  - under half the entries in use;
  - a date just at and just before the end of tomorrow.

  An unknown field passes. Each refused case leaves the data file's bytes and mode unchanged, and
  the shrink message names the rule, both counts and "a newer build of nyx".
- **B16**:
  - Same and older dates give `current`: the data file is unchanged and `last_checked` is set.
  - With one newer list of three, the source is `updated`, the other lists keep their previous
    downloaded text, and `current` is reported for them.
  - An unreadable copy is replaced by a download no newer than the built-in copy.
- **B17 [mutation]**:
  - `crash_test.go` fault points `threat-after-response` and `threat-before-rename` (new
    `internal/fault` points) kill the update child. The previous file is intact and no temporary
    file is left that `Load` reads.
  - A `Load` loop that runs during repeated updates always sees one whole version.
  - A read-only `<dir>` gives `UNEXPECTED_ERROR` with the reason and sends no request (D15 step 1), and the previous copy is intact.
  - A rename failure after validation, injected at `threat-before-rename` as an error rather than
    a kill, gives `UNEXPECTED_ERROR`. The previous copy is intact, and `last_response` is recorded.
  - A stale `.spamhaus-x.tmp` is removed by the next update, and `Load` never reads one.
  - Quitting setup during an update (a model test with a blocking fake) cancels it.
- **B18 [mutation]**:
  - Within the hour, zero requests are sent, and the update reports `skipped` with
    `last_contacted` and `next_update`.
  - A 500 starts the hour, but a refused connection and a DNS failure don't.
  - A future `last_response` is rewritten to now on disk. Within the hour every update is skipped,
    and an hour later one is allowed, however far ahead the recorded time was.
  - A future `last_checked` is clamped the same way, and can't hide the stale hint for more than
    30 days.
  - Two updates on one directory, run concurrently in-process: the second waits on the lock,
    then is skipped, and the server counts one request per list.
  - The lock wait ends on a cancelled context.
- **B19**: a golden test of the human output for updated, current, skipped and failed lists and
  the credit line, printed under `--quiet` too.
- **B20**:
  - The exit matrix: all succeeded is 0. One failed (each other outcome) is 7. Both failed with
    `NETWORK_ERROR` is 1 with that code. Both failed with different codes is 1 with
    `UPSTREAM_ERROR`, an empty stdout, and both reasons in the error.
  - The transient flag and the hint times are set.
  - A child-process test (under `TestChildProcesses`) checks SIGINT, SIGTERM and SIGHUP give 130,
    143 and 129, with the previous copy intact.
- **B21**: envelope key tests on exit 0 and 7, covering every key, the outcome values and the
  credit keys. Exit 1 writes no envelope.
- **B22**: the directory follows `XDG_CONFIG_HOME`, then `HOME`, and ignores `--config`. With
  neither set, the update exits 2 with the reason, and recon and `nyx ip` use the built-in copy
  with no warning or hint. A doc test checks the location sentence.
- **B23**: per list, the later copy wins, and an equal date picks the downloaded copy. A
  downloaded v4 that is newer than the built-in copy and a v6 that is older mix correctly.
- **B24**: there is one case per unreadable kind, and each one makes the whole source built-in.
  - The warning is printed once on stderr. It goes to `meta.warnings` under `--json` and still
    prints under `--quiet`.
  - Export doesn't warn.
  - After an update replaces the copy, the warning stops.
- **B25**: a setup view test with fake `ThreatData` shows five rows with source, date, count and
  provenance, and the credit.
- **B26**:
  - In model tests, `u` starts a single update: a second `u` is ignored while it runs. The tab
    shows "updating…", then each row's result, including the skip time and a failure reason.
  - `q` after an update quits with no dialog, and `q` during one cancels the context.
  - One cli-level setup test presses `u` against fake servers and exits 0.
- **B27**:
  - The staleness matrix: each date older than 30 days on its own is not stale; both are.
  - The exact hint text.
  - For `nyx ip`, the hint appears only when a selected key reads the source.
  - Under `--json`, recon and `nyx ip` add it to `meta.warnings`, including with `--quiet`.
  - `--quiet` alone prints nothing, and a usage error prints no hint.
  - In recon, the order is the no-config hint, then the stale hint, then the error.
- **B28**: refresh-tool tests reuse the B15 table through the shared rules.
  - `-allow-shrink` lets through a list that would otherwise be refused for shrinking, and only
    that rule.
  - A list that is not newer is left as it is.
  - The added, removed and changed text.
  - A failed source leaves its file and the other's is written.
  - `TestAbusiveDocs_GiveTheSnapshotDates` becomes a five-date test.
  - The Makefile target test names `threat-data`.
- **B29**: doc tests check the passive-boundary sentence and hosts, the setup page's
  non-interactive use, exit codes and files, the `nyx ip` page's sources table and its dependence
  on the threat data, and `CLAUDE.md`'s `make threat-data`.

## Conventions

- `CLAUDE.md`: Australian English. Only `internal/egress` does network I/O (the update reaches the
  network through egress). The `unix` allowlist. Every test calls `t.Parallel()`, and env comes
  only through `h.setenv`. Stable-interface rules for the new `nyx ip` keys and the update envelope.
  Atomic writes. `clierr` and `cli.Execute` own exit codes.
- Specs workflow: `.claude/skills/spec-*`.

# Follow-ups

- Run `make threat-data` before the release, review the diff, and put the five dates in
  `docs/abusive-networks.md`.
- Licence: Spamhaus's terms grant no licence to redistribute the lists (D1). Consider asking
  Spamhaus to confirm that shipping a dated copy inside an open-source binary, with credit, is
  acceptable.

# Implementation

## Develop

Base commit: cd8a75ece876fb39c67e3f3a00be5b9bd04d43ef

Frozen test files (staged, 206 new tests failing on assertions at freeze; no build errors or panics):

- internal/abusive/abusive_test.go
- internal/cli/abusive_docs_test.go
- internal/cli/abusive_recon_test.go
- internal/cli/crash_test.go
- internal/cli/harness_test.go
- internal/cli/ip_abusive_test.go
- internal/cli/ip_world_test.go
- internal/egress/boundary_test.go
- internal/findings/abusive_test.go
- internal/findings/findings_test.go
- internal/iplookup/fields_test.go
- internal/iplookup/render_test.go
- internal/setup/colour_test.go
- internal/setup/helpers_test.go
- internal/setup/view_test.go
- internal/abusive/parsepages_test.go
- internal/abusive/testdata/asns.html
- internal/abusive/testdata/networks.html
- internal/cli/threat_contact_test.go
- internal/cli/threat_crash_test.go
- internal/cli/threat_docs_test.go
- internal/cli/threat_envelope_test.go
- internal/cli/threat_helpers_test.go
- internal/cli/threat_hint_test.go
- internal/cli/threat_ip_test.go
- internal/cli/threat_recon_test.go
- internal/cli/threat_setup_test.go
- internal/cli/threat_update_helpers_test.go
- internal/cli/threat_update_test.go
- internal/fault/fault_test.go
- internal/iplookup/drop_test.go
- internal/run/derive_test.go
- internal/setup/threat_test.go
- internal/spamhaus/spamhaus_test.go
- internal/threatdata/accept_test.go
- internal/threatdata/helpers_test.go
- internal/threatdata/refresh/refresh_test.go
- internal/threatdata/refresh/testdata/asns.html
- internal/threatdata/refresh/testdata/networks.html
- internal/threatdata/threatdata_test.go
- internal/threatdata/update_test.go

How it was built:

- `internal/spamhaus` (new, pure) parses, validates, bundles and matches the three lists; `internal/abusive` gained `stated`, `ParsePages` (moved from the refresh tool, without its `previous` check), `ParseNetworksPage`/`ParseASNsPage`, `ParseLenient` and `ValidateCounts`.
- `internal/threatdata` (new) holds `Dir`, `Load` (precedence, fallback, warnings, staleness), the shared acceptance rules and `Update` (state file, polled flock, temp + fsync + rename, two fault points). `internal/fault` gained `Inject`/`Err` for error injection.
- `internal/findings`, `internal/iplookup` and `internal/run` carry `Drop`; `internal/setup` has the Threat data tab; `internal/cli` loads the data once per command, writes the stale hint, and has the update (`threat.go`) and the Backend methods.
- `internal/threatdata/refresh` replaces `internal/abusive/refresh`; `make threat-data` replaces `make abusive-data` and was run (ipapi.is lists now carry `stated`; the ASN-DROP list's timestamp moved).
- Docs, README and CLAUDE.md updated.

Deviations and decisions made while building:

- **D27** (added): ipapi.is's per-source files use the stem `ipapi`.
- Spamhaus text: any `unicode.IsControl` character (C0, DEL, C1) in a field the parser reads refuses the list; unknown fields are ignored whole; an empty `sblid` or `cidr` counts as missing; an IPv4-mapped prefix in either list is the wrong family; a metadata line without a numeric `records` is refused.
- The shrink and zero-entry rules apply after all of a source's lists arrive (D15 step 5), so those refusals don't stop the source's later requests.
- A cancelled lock wait or request fails the source with `UNEXPECTED_ERROR` ("cancelled"); an update cancelled after its last answer stores nothing.
- `Load` ignores a future `last_checked` (so it can't hide the stale notice); `Update` rewrites it as now.
- The DROP CSV cell leaves out a blank RIR, AS name, country or domain, so there are no `()` or double spaces (D22's literal format would print them).
- The update's human output pads its columns, so `drop_v4` is followed by three spaces, not D18's two.
- `nyx ip` loads both sources once and drops the notices of a source no selected key reads; the output is the same as not loading it.
- `internal/cli/ip_outcome_test.go` (not a frozen file) lists the two new `nyx ip` section headings; goldens `record-plain.txt`, `help-findings.txt`, the help goldens and the two new update goldens were regenerated and read.
- Two tests were added to the frozen `internal/setup/threat_test.go` (additions only), and non-frozen test files were added beside the code: `internal/spamhaus/decisions_test.go`, `internal/threatdata/extra_test.go`, `internal/findings/drop_blank_test.go`, `internal/iplookup/drop_render_test.go`, `internal/cli/threat_backend_test.go`.
- External facts matched `## External facts`. The ASN-DROP list had moved to 2026-11-23T08:56:44Z by the time `make threat-data` ran; drop_v4 and drop_v6 were unchanged.

## Known limitations

- **B5/D12**: a control character inside an *unknown* Spamhaus field is not refused (unknown fields are ignored whole).
- **B27**: "no stale hint on a usage error" can't be told from the load order: every `INVALID_INPUT` that recon or `nyx ip` can produce exits before the data is loaded, so the rule is untested as a rule.
- **B11**: "a run uses the data in place when it started, through all its passes" is pinned through the final findings only, not each pass's derivation.
- **B13**: TIMEOUT through the command (as opposed to `threatdata.Update`) isn't tested, as the 30 s timeout can't be shortened through `Deps`.
- **B28**: if only one ipapi.is page is newer and the kept list is an old file with no `stated`, the refresh tool writes `stated: 0` for it. It doesn't occur with the current data.
