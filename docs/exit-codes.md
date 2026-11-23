# Exit codes and errors

## Exit codes

Every command uses the same exit codes:

| Code | Meaning | Error codes |
|---|---|---|
| 0 | Success: the run did all its work and no check failed. A `not-configured` stage, work a per-run cap deferred and a result a page cap truncated do not stop it being a success | none |
| 1 | System error: the arguments were fine and something else went wrong, including an engagement locked by another run | `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED`, `UPSTREAM_ERROR`, `AUTH_FAILED`, `LOCKED`, `UNEXPECTED_ERROR` (for `nyx setup --update-threat-data`, when both sources failed: their shared code, or `UPSTREAM_ERROR`) |
| 2 | Usage error: a bad flag, setting, config file, input or file named on the command line, an output directory that is not a nyx engagement, or the netblock limit; for `nyx setup`, an argument, no `--config` and no default config path (and, for `--update-threat-data`, neither `XDG_CONFIG_HOME` nor `HOME`, so nowhere to keep threat data), no terminal on stdin or stdout (it names the file and says to edit it by hand), or a config file that cannot be read or parsed or holds an unknown key; for `nyx cve`, no IDs, or only malformed ones; for `nyx ip`, no inputs, only invalid ones, or more than 256 addresses (when hostnames gave them, only their DNS lookups were sent). Nothing was created or contacted, except that the netblock limit is found once a run has started | `INVALID_INPUT` |
| 3 | Not found: an engagement that does not exist, no CVE ID the NVD holds, or for `nyx ip` only names that do not resolve | `NOT_FOUND` |
| 7 | Partial result: a recon run the deadline ended, or in which any check failed; a `nyx cve` batch in which some IDs failed, or every ID failed with different error codes; the same for a `nyx ip` call and its inputs (a quota failure never counts, see [IP lookup](ip.md)); a threat-data update in which one source failed | `PARTIAL` |
| 130, 143, 129 | Interrupted by SIGINT, SIGTERM or SIGHUP | `INTERRUPTED` |

**Exit codes of the threat-data update.** `nyx setup --update-threat-data` exits 0 when every source
updated, was already current or was skipped (a source that answered within the last hour is not
asked), 7 (`PARTIAL`) when one source failed, whatever the other did, and 1 when both failed, with
their shared error code or `UPSTREAM_ERROR` when the codes differ, an empty stdout and each source's
reason in the error. It exits 2 for an argument, or when there is nowhere to keep threat data, and
130, 143 or 129 on a signal. A source's failure is `NETWORK_ERROR`, `TIMEOUT` (a request gave up after
30 seconds), `RATE_LIMITED` (a 429), `UPSTREAM_ERROR` (any other answer, a redirect or a refused
download) or `UNEXPECTED_ERROR` (a download that could not be stored), and the error is transient
when any failure was a network failure, a timeout or a 429 (see
[Abusive networks](abusive-networks.md#updating-the-threat-data)).

**Exit 7 for recon.** A recon run exits 7 when the deadline ended it (see [Deadline](commands.md#deadline)) or
when any check failed in it. Exit 0 no longer covers failed checks. The summary or envelope has been
written to stdout, and the files are current, before the error that follows it on stderr. A failed
check is one that returned a transient error, one a stage abandoned when it stopped for the run on
a 401, 403, 429 or spent quota, and one that panicked (a panic inside one check is that check's
failure: the run carries on, and the check is retried on the next run).

- **The error** names each stage with failed checks and how many (`16 checks failed: crtsh 2,
  shodan 14`). Its hint is your own invocation, shell-quoted, with `--redo` and its value left out
  and every other argument kept: run it to retry the failed checks. The error is marked
  transient unless every failure was a key the source refused (a 401 or 403 from a keyed source, and
  a 401 from GitHub, which answers 403 for a rate limit): waiting does not cure those, so fix or
  remove the key.
- **Not partial.** These do not make a run partial: a `not-configured` stage, work a per-run cap
  deferred, a result truncated by a page cap, and failures recorded by earlier runs for stages that
  did not run this time.
- **The deadline's error** is the `PARTIAL` of the [Deadline](commands.md#deadline) section, with the failed
  checks of the run named in it as well.

**Several outcomes.** One is reported, the first of these that applies: a signal (130, 143 or 129),
a fatal error (exit 1), the netblock limit (exit 2), the deadline (exit 7), failed checks (exit 7).
A signal that arrives while a deadline run is writing its files leaves `INTERRUPTED` and an empty
stdout; one that arrives after the result is written leaves exit 7 standing.

**Engagement problems** get the code of their kind:

- An engagement locked by another run exits 1 with `LOCKED`, marked transient: wait for the other
  run to finish, or use another `-e`.
- An output directory that is not a nyx engagement (one that holds files and no `.nyx`, such as
  the Python version's) exits 2 naming the directory, with a hint to choose another `-e` or move it
  away. Nothing is written into it.
- `nyx recon -e <name>` with no inputs, for an engagement that does not exist, exits 3 with
  `NOT_FOUND` and creates nothing. The hint lists up to ten engagements in the output directory and
  says how many more there are, or says there are none and how to start one. When the call has other
  problems, they are reported alone, as exit 2.
- `nyx recon export` follows the same rules: an engagement that does not exist exits 3 with that
  hint, a directory that is not a nyx engagement exits 2, and a failure to write the export exits 1.

Any other failure to open, read or write an engagement is `UNEXPECTED_ERROR` (exit 1), which
prints its stack trace to stderr only with `--debug`.

A signal ends the command with its own code. recon saves the work completed so far, as it does for
any interruption; run the same command again to continue. A second signal exits at once with the
first one's code.

### Errors

Every non-zero exit writes one error to stderr. stdout is empty on every exit but 0 and 7: a recon
run that exits 7 has written its summary, or its envelope under `--json`, first, and a `nyx cve`
batch or `nyx ip` call its records (none, in human mode, when no ID succeeded). The error is never
sent through the log formatter.

```
error: invalid domain "co.uk": it is a public suffix, not a registrable domain (INVALID_INPUT)
hint: nyx recon --help
```

A `hint:` line follows when there is a next step, and `retry: may succeed after a wait` when the
error is transient. A partial result from several targets adds one `error: <input>: <message>
(<CODE>)` line for each target that failed. `input` is `null` for the `PARTIAL` error of a recon run;
for `nyx cve` it is `{"id":[…]}`, the IDs that failed as given, and for `nyx ip` it is
`{"input":[…]}`, the inputs as given that failed or gave a failed address (the hostname or CIDR, not
the address), with `"address":"<address>"` as well in a `meta.errors` entry that is one address's. Under `--json`, even when the arguments fail to parse,
the error is one compact line of JSON with exactly the keys `error`, `code`, `hint`, `input` and
`transient`, in that order; `hint` and `input` are `null` when there is nothing to say, and `input`
maps each failing argument to the list of its values as given:

```json
{"error":"invalid domain \"co.uk\": it is a public suffix, not a registrable domain","code":"INVALID_INPUT","hint":"nyx recon --help","input":{"domain":["co.uk"]},"transient":false}
```

Checks of values and combinations report every problem they find in one error. API keys are masked
in the error as everywhere else.

**What stays stable.** The exit codes, the error codes, the five keys of the error, the keys of
the recon `--json` envelope (see [The `--json` envelope](console-and-json.md#the---json-envelope)), and the keys of the
CVE record and of the `nyx cve` envelope (see [CVE lookup](cve.md)), and the keys of the
`nyx ip` record and of its envelope (see [IP lookup](ip.md)), and the keys of the threat-data update's
envelope (see [Abusive networks](abusive-networks.md#updating-the-threat-data)) are an interface: a
new one may be added, but renaming, removing or retyping one is a breaking change. The wording of
messages and hints may change. The one exception so far is that the default `nyx cve` record no
longer has the lists `affected_products` and `references`, only their counts: that was a deliberate
break, made once when `--limit` and `--match` were added, and `--fields all` still returns them.

## Departures from `docs/agent-tools`

The guidance in `docs/agent-tools` is followed, except in these eleven ways:

1. recon has no default `--timeout`: a run takes as long as it needs unless you give a deadline.
2. `nyx recon export` writes JSON lines with no envelope, cap or paging.
3. API keys come only from the config file (`keys.<source>`), never from the environment.
4. A stage whose key is missing is `not-configured`, not a usage error.
5. `--authorized` is accepted as an alias of `--authorised`.
6. `--quiet` with `--debug` is rejected (exit 2).
7. SIGHUP exits 129.
8. recon can finish slightly after its deadline, when writing the files takes longer than the
   reserve (see [Deadline](commands.md#deadline)).
9. recon's requests are paced by token buckets, not a sliding window (`nyx cve` uses a sliding
   window).
10. A failed recon request is not retried within the run: its check is retried on the next run.
    The exceptions are GitHub's rate limit (see [GitHub code search](sources.md#github-code-search)) and an
    overloaded Common Crawl index (see [Passive boundary](passive-boundary.md#passive-boundary)). `nyx cve` retries
    within the call.
11. recon's HTTP connections are not reused.
