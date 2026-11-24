# Commands and engagements

## Commands

- **`nyx recon [domain...] [flags]`** runs an engagement: everything below. **`nyx recon export`**
  writes what an engagement holds as JSON lines (see [Exporting an engagement](output.md#exporting-an-engagement)).
- **`nyx setup`** opens a full-screen terminal editor for the config file: your API keys, the output
  directory and the common settings (see [Setup](configuration.md#setup)). It needs a terminal.
  `nyx setup --update-threat-data` instead updates the threat data that recon and `nyx ip` check
  addresses against, needs no terminal, and exits.
- **`nyx cve <CVE-ID>... [flags]`** looks CVEs up in the NVD by CVE ID (see [CVE lookup](cve.md)).
  It needs no engagement and no authorisation, and writes no files.
- **`nyx ip <input>... [flags]`** looks up who runs an IP address, where it is, what it is called and
  what is exposed on it, for each address, hostname or CIDR given (see [IP lookup](ip.md)). It
  needs no engagement and no key, writes no files, and by default sends nothing to the address.
  `nyx ip --active` also connects to it. Recon and `nyx cve` behave as they did before.
- **`nyx completion bash|zsh`** prints a script that tab-completes nyx in that shell: the
  commands, the flags, the help topics, and the values a flag takes from a fixed list (the procedures
  for `--redo` and `--skip`, without the procedures `--skip` refuses; the fields for `--fields`, ip's
  active-only fields once `--active` is on the line; the kinds for `--kind`). Load it from your
  shell's startup file with `source <(nyx completion zsh)` (zsh, after `compinit`) or
  `source <(nyx completion bash)` (bash, with the bash-completion package), or save it as
  `"${fpath[1]}/_nyx"` or `~/.local/share/bash-completion/completions/nyx`. The script asks nyx
  for each completion, so it stays current when nyx is upgraded. Answering one reads no file and
  contacts nothing; file and directory names are completed by the shell. Any other shell, or no
  shell, exits 2. It is set up once, so the root help leaves it out: `nyx setup --help` and setup's
  Settings tab say how to turn it on, and `nyx help completion` is its own help.
- **`--timeout <duration>`** is a recon flag: `nyx recon example.com --json --timeout 30m` stops by
  that deadline and exits 7, and a re-run carries on (see [Deadline](#deadline)). `export` makes no
  network calls and takes no `--timeout`. `nyx cve` and `nyx ip` take their own `--timeout`, the
  deadline for the whole call (see [CVE lookup](cve.md) and [IP lookup](ip.md)).
- **Help.** `nyx --help`, `nyx help` and a bare `nyx` print the whole reference: examples, every
  command but `completion` with its everyday flags and one example, the valid values of each fixed-set flag (the
  procedures, the export kinds) and the exit codes. The recon example in `nyx --help` and in
  `nyx recon --help` passes `--json` and `--timeout`, and the root help lists `--timeout` among
  recon's everyday flags. `nyx help <command>` (or `nyx <command> --help`, or `nyx <command> help`)
  is one command's full help; recon's tuning settings are listed only there. `help` reads as
  `--help` only as a command's first argument: `nyx recon export help` and `nyx recon help export`
  are export's help, but `help` after an argument or a bare `--` is an argument like any other. The root help also lists
  cve's and ip's flags and the field names `--fields` accepts. `nyx help procedures` and
  `nyx help findings` are the two help topics. Help goes to stdout and exits 0.
- **Shared flags.** Every command takes `--json` (`-J`), `--quiet` (`-q`) and `--debug`, before or
  after its name (`nyx --json recon example.com` runs recon). `--json` implies `--quiet`, and
  `--quiet` with `--debug` exits 2. None of them is a setting. Any other flag goes after the
  command: one placed before it exits 2 with the same call, the command moved first, as the hint.
- **Flags are spelt in full.** An abbreviation (`--pass` for `--passive`) is an unknown flag;
  `--authorized` is the one alias.
- **Prompts and stdin.** Only `nyx setup` asks anything, in its full-screen editor, and the editor
  needs a terminal for stdin and stdout (`nyx setup --update-threat-data` asks nothing). No command loads a `.env` file or reads a setting or key from the
  environment (see [Configuration](configuration.md#configuration)). Otherwise only `nyx cve` and `nyx ip`, given a lone `-`, read stdin.
- **Version.** `nyx --version` prints the version; every HTTP request nyx makes carries
  `nyx/<version>` (`nyx/devel` for a build with no version) as its User-Agent.

## Inputs and engagements

- **Inputs:** positional domains, `-d <file>` (one root domain per line, `#` comments allowed),
  `--org <name>`, `--asn <AS123|123>`, `--cidr <netblock>`. The last three are repeatable. An ASN's
  announced netblocks become in scope.
- **Exclusions:** `-x <hostname|*.wildcard|CIDR>` (repeatable) and `--exclude-file <file>`. An
  excluded host, or any host that resolves into an excluded CIDR, is recorded as excluded and its
  addresses are never contacted.
- **Engagement name:** `-e <name>`, or derived from the first input: the first positional domain,
  else the first line of the domains file, else the first `--org`, `--asn` or `--cidr`. The
  derivation depends on the order of your inputs. Either way, the name is lowercased and sanitised.
- **Re-runs:** inputs and exclusions are added to those already stored for the engagement. Nothing
  is removed because you left it out of a later run.
- **Resume:** a re-run performs only the jobs not yet done. Jobs that failed (a transient
  error, not a negative result) are retried on later runs, and a run in which any job failed exits 7
  (see [Exit codes](exit-codes.md#exit-codes)). An interrupted run resumes the same way, and so does one that a
  deadline stopped (see [Deadline](#deadline)).
- **`--redo <procedure>`:** performs every job of one procedure again. `nyx help procedures` lists the procedures
  in run order, with whom each contacts, the key it needs and what it does.
- **`--skip <procedure>`:** turns a procedure off (repeatable; the `skip` setting does the same). A skipped procedure is shown as `not-configured (skipped)`,
  whatever else would stop it, and does nothing: results it found earlier stay in the files. The flag
  replaces the setting for that run, and `--skip none` runs every procedure. An unknown procedure, a procedure
  also given to `--redo`, and `resolve`, `wildcard`, `ipowner` and `providerranges` (other procedures'
  safety depends on them) exit with code 2.

## Large netblocks

If the in-scope IPv4 address count (ASN-expanded netblocks included) exceeds `netblock_limit`,
nyx stops before contacting any address in them, writes the output files and exits 2 with an
`INVALID_INPUT` error that gives the total. Its hint is your own call with
`--allow-large-netblocks` added (and any `--redo` left out), which proceeds. The approval is
remembered with the engagement.

## Deadline

`--timeout <duration>` gives a recon run a deadline: `--timeout 30m`, `--timeout 2h`, `--timeout
1m30s`. It is a flag only, with no default and no config key (a `timeout:` key in the config file is
an unknown key). A value that is not a positive
duration (`0`, `-5s`, `abc`, and `30` with no unit) exits 2. `nyx recon export` makes no network
calls and takes no `--timeout`. Without the flag a run takes as long as it needs.

- **The reserve.** nyx aims to exit by the deadline, so the work stops before it. The reserve is a
  tenth of the timeout, at least 2 seconds, at most 60 seconds and never more than half the timeout:
  jobs get 27 seconds of a 30-second timeout, 9 minutes of 10, and 1 hour 59 minutes of 2 hours.
  When the reserve before the deadline is reached, recon stops starting jobs and cancels the
  ones in flight. It then writes the output files and the summary or envelope, in time to exit by
  the deadline.
- **The late finish.** If writing takes longer than the reserve, recon finishes writing and exits
  after the deadline, with current files, rather than stopping part-way. A run that finishes its
  work before the deadline is unaffected and exits as it would without `--timeout`.
- **A cancelled job** is neither done nor failed. Nothing is recorded for it, no failure and no
  completion, so it runs on the next run, and the evidence earlier runs recorded stays current.
- **Exit 7.** A run the deadline ended prints its summary or envelope and exits 7 with a `PARTIAL`
  error. Its message says the deadline stopped the run, how many jobs completed in this run, how
  many were cancelled and in which procedures (`the deadline (--timeout 30m) stopped the run: 412
  jobs completed, 6 cancelled (permutations 2, crawl 4)`), and then names the procedures with failed
  jobs, if any (`; failed jobs: crtsh 2, shodan 14`). A job is completed when it ran and
  finished in this run, whether it succeeded or failed; a job a procedure abandoned without running it
  is failed but not completed. The same counts are `meta.deadline_exceeded`, `meta.jobs_completed`
  and `meta.jobs_cancelled` in the envelope, and the human summary ends with `Stopped by the
  deadline: N jobs completed, M cancelled`. The error has one of two hints:
  - **To carry on.** The hint is your own invocation, shell-quoted, with `--redo` and its value left
    out and every other argument kept, `--timeout` included. Run it to do the cancelled jobs and
    the rest. The error is marked transient.
  - **To raise the deadline.** When no job succeeded in this run (the timeout was too small to
    start one, or every job started was cancelled or failed) the hint says to raise `--timeout`:
    `raise --timeout: no job succeeded within 30m`. Running the same command again would make no
    progress, so the error is not marked transient.
- **Long jobs.** A single permutations job (one per root: about 4,900 lookups, at the default
  50 a second) or crawl job (one per service) can take minutes, and the deadline cancels a job
  that has not finished. A short `--timeout` may therefore never finish one: a run that stops at one
  makes no progress past it on the next. Give such a run a longer `--timeout` (or none).
