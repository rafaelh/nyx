# Configuration and setup

## Configuration

- **Config file:** `$XDG_CONFIG_HOME/nyx/config.yaml`, which defaults to
  `~/.config/nyx/config.yaml`. Use `--config <file>` to choose another. Unknown keys are
  rejected. `key_tests` is nyx setup's record of key tests (see [Setup](#setup)), which every other
  command accepts and ignores. `nyx setup` edits keys and the common settings for you (see [Setup](#setup)).
- **The file is the only source.** No setting or key is read from the environment: `NYX_*`
  variables and `NVD_API_KEY` are ignored, and no command loads a `.env` file. The environment is
  read only to find the config file and expand a leading `~` in a path (`XDG_CONFIG_HOME`, `HOME`),
  and for the terminal (`TERM`, `COLORTERM`, `NO_COLOR`, `COLUMNS`).
- **Precedence:** flags override the file.
- **API keys:** set only as `keys.<source>` in the file. There are no key flags, so keys never
  appear in shell history or process lists. Keys are redacted from all output and files.
- **The NVD key:** `nyx cve` reads its key from `keys.nvd` in the file.
  `keys.nvd` is a valid key for every command.
- **Keyed sources:** `securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys`, `chaos` and
  `github`. A procedure whose key is missing is shown as `not-configured (no key)`, unless its source
  has no free plan that does its work: `whoisxml`, `censys`, and the Shodan searches (`shodan`,
  `shodan-dns` and `identifier-pivot`) are then left out of the run's output, the console and the
  `--json` envelope's `not_configured` alike. `shodan-host` works on a free Shodan key, so it is
  still shown. `keys.shodan` also turns on
  `shodan-dns`, which lists each in-scope root's subdomains and their A, AAAA, CNAME, MX and NS records; it costs
  one Shodan query credit per result page, for each root. `keys.censys` is a Censys personal access
  token and searches certificates for names under each root. `keys.chaos` is a ProjectDiscovery
  Chaos key. A 401, 403 or 429 stops that procedure for the run (`shodan-host` too), and so does a 402 (spent query credits) for the Shodan searches. Each of these three follows result pages
  up to `shodan_dns.max_pages`, `censys.max_pages` or `chaos.max_pages` (default 10; raising one
  repeats the procedure's jobs, and reaching one is a warning). Chaos answers with the
  whole list in one page, so its cap is not reached. `certspotter` takes an
  optional key: it runs without one, and sends `keys.certspotter` when it is set. `keys.github` is a
  GitHub personal access token for the `github` procedure (see [GitHub code search](sources.md#github-code-search)),
  which reads up to `github.max_results` results per root (`--github-max-results`, default 500, from
  1 to 1000; changing it repeats the procedure's jobs). A 401, or a 403 or 429 whose rate limit does not
  lift within 60 seconds, stops that procedure for the run. The other sources need no key.
- **Reverse IP.** `keys.securitytrails` also adds SecurityTrails to the `reverseip` procedure (see
  [Reverse IP](sources.md#reverse-ip)). A rejected key (401 or 403) stops the whole procedure, its HackerTarget
  lookups included, until the key is fixed or removed; a 429 stops it for the run. `reverseip.max_domains`
  (`--reverseip-max-domains`, default 100, at least 1) is how many registrable domains one address may
  return before it is treated as shared hosting.
- **Shared name servers.** `keys.securitytrails` also turns on `nsreverse`. A rejected key (401 or
  403) or a 429 stops it for the run. `nsreverse.max_domains` (`--nsreverse-max-domains`, default
  1000, at least 1) is how many domains one server may host before it is treated as shared hosting.
- **Origin exposure.** `keys.securitytrails` also turns on `dnshistory`. `dnshistory.max_hosts` (`--dnshistory-max-hosts`, default
  200, at least 1) caps the hostnames it asks about in one run, and `origincheck.max_candidates`
  (`--origincheck-max-candidates`, default 5, at least 1) caps the candidate origins kept, and
  checked, for each hostname.
- **Shodan per address.** `keys.shodan` also turns on `shodan-host` (see
  [Shodan per address](sources.md#shodan-per-address)). `shodan.max_hosts` (`--shodan-max-hosts`, default 500,
  at least 1) caps the addresses it looks up in one run.
- **JavaScript endpoints.** `jsparse.max_scripts` (`--jsparse-max-scripts`, default 50, at least 1)
  caps the script files `jsparse` reads per origin.
- **Web identifiers.** `keys.shodan` also turns on `identifier-pivot`. `identifier_pivot.max_queries` (`--identifier-pivot-max-queries`,
  default 50, at least 1) caps the Shodan searches it sends in one run.
- **Names on in-scope addresses.** `in_netblock.enabled` (`--no-in-netblock` turns it off; default
  `true`) looks up candidate names and brings into scope those served from an in-scope netblock (see
  [Names on in-scope addresses](sources.md#names-on-in-scope-addresses)).
  `in_netblock.max_lookups` (`--in-netblock-max-lookups`, default 1,000, at least 1) caps the
  candidates looked up in one run.
  `in_netblock.max_names_per_address` (`--in-netblock-max-names-per-address`, default 100, at least 1)
  is how many looked-up names one in-scope address may serve before it is treated as shared hosting.
- **Name guessing.** `permutations.enabled` (`--no-permutations` turns it off; default `true`)
  turns on the wordlist, variant and learned-name guessing (see
  [Name guessing](sources.md#name-guessing)). `permutations.max_per_seed` (`--permutations-max`,
  default 200, at least 1) caps the variants of one found name, and `permutations.max_names`
  (`--permutations-max-names`, default 200,000, at least 1) the wordlist and variant names tried in
  one run. `learned_names.max_names` (`--learned-names-max-names`, default 50,000, at least 1) caps
  the learned names tried in one run, separately. Names over a cap are deferred to the next run.
- **End-of-life software.** `eol_warn_days` (`--eol-warn-days`, default 90, at least 0) is how many
  days before the end of a release cycle's security support the low `eol-approaching` finding is
  reported; 0 turns it off.
- **Settings:** all settings and their defaults are listed by `nyx recon --help`.

Example `config.yaml` (a leading `~/` in `output_dir`, `wordlist` or `sensitive_paths` is your home
directory):

```yaml
output_dir: ~/engagements
concurrency: 10
keys:
  securitytrails: your-securitytrails-key
  shodan: your-shodan-key
  virustotal: your-virustotal-key
  whoisxml: your-whoisxml-key
```

## Setup

`nyx setup` is a full-screen terminal editor for one config file: the one `--config` names, or the
default (`$XDG_CONFIG_HOME/nyx/config.yaml`, else `~/.config/nyx/config.yaml`). Use it once after
installing, and again to add, rotate or remove a key. `nyx recon` and `nyx cve` then use what it
saved. The editor takes no arguments. `nyx setup --update-threat-data` is setup's one use without the
editor (see below). ↑ and ↓ move between rows, ← and → (or Tab) between the tabs, and
the bottom of the screen lists the keys each tab offers.

- **Keys tab.** Lists `nvd`, `github`, `chaos`, `virustotal`, `certspotter`, `securitytrails`,
  `shodan`, `whoisxml` and `censys`, from the most a free account allows to the least, with what each
  turns on (Cert Spotter also works without one). A
  key of 12 or more characters is shown as `••••` and its last 4 characters; a shorter one shows only
  `set`; an unset one shows `not set`. A key is never shown in full, in an error or after setup exits.
  Enter types or pastes a key (one `•` per character), `x` or Delete clears it, and an entry that is
  empty after trimming is a clear. Keys for sources nyx does not know are kept as they are and not
  listed.
- **Settings tab.** `output_dir`, `concurrency`, `rate.per_host`, `rate.per_source`, `rate.dns`,
  `wordlist` and `sensitive_paths`, each with its value in the file or its default. A value is
  checked as you enter it, with the same rules and messages `nyx recon` gives for the file, and an
  invalid one is not accepted. An empty value clears the setting, so its default applies. A relative
  `output_dir`, `wordlist` or `sensitive_paths` is saved as an absolute path, against the directory
  you ran setup from; `~/` and `~` are kept as typed. An unset `output_dir`, and any relative path
  already in the file, is shown as resolving against the directory nyx is later run from. When
  `SHELL` is bash or zsh, the tab ends with the line to add to `~/.bashrc` or `~/.zshrc` for tab
  completion (see [Commands](commands.md#commands)); `nyx setup --help` gives both.
- **Skip tab.** Lists the procedures that can be skipped, each with its one-line description (as in
  `nyx help procedures`). A procedure that runs is marked `[x]`; toggling it off adds it to the `skip`
  setting and shows it muted. Procedures that cannot be skipped are not offered. An entry in the file that
  is unknown or cannot be skipped is listed with its message and can be removed on its own.
- **Threat data tab.** Lists the five lists the abusive-network check reads (Spamhaus's DROP,
  DROPv6 and ASN-DROP, and ipapi.is's most-abusive networks and ASNs), each with its source, its date,
  its entry count and whether the copy in use is built in or downloaded, and gives Spamhaus's
  copyright line and a link to its terms. `u` runs the same update as `nyx setup --update-threat-data`
  (see [Abusive networks](abusive-networks.md#updating-the-threat-data)). The tab shows it as in
  progress, then each list's result in place: updated, already current, skipped (with when it can
  next be updated) or failed (with the reason). An update is not an unsaved change: it writes no
  config, quitting after it does not ask to save, quitting during it abandons it (each source keeps
  its previous copy or gets its complete new one), and its result does not change setup's exit code.
- **Testing a key.** `t` tests the key on the selected row, saved or not: one authenticated request
  to that source, never to a target (the hosts are listed under [Passive boundary](passive-boundary.md#passive-boundary)).
  It shows `accepted`, `rejected`, or `could not check: <reason>` for a rate limit, exhausted credits,
  a network failure or any other answer, and gives up after 15 seconds. Editing or clearing the key
  removes the result. A key test may spend a query: VirusTotal and Censys count it against their
  quota.
- **Key records.** An `accepted` or `rejected` result is an unsaved change, and saving writes it
  under `key_tests.<source>` with the day (`result`, `date` and `key`, the first 8 hex digits of the
  key's SHA-256, never the key). A key entered and saved without being tested is recorded as
  `not tested`, as is a key in the file with no record the next time setup saves anything. The Keys
  tab shows the recorded result beside the key, and nothing once the record is 90 days old, so an
  old test is not taken for a recent one. `could not check` changes no record. A key changed by hand
  no longer matches its record and shows `not tested`; clearing a key removes its record.
- **Saving.** Edits are held until `ctrl+s`. Quitting (`q`, `esc` or `ctrl+c`) with unsaved
  changes asks whether to save, discard or go back; quitting with none writes nothing. A save changes
  only the values you edited and the key records, and keeps every other setting, comment and their
  order (blank lines are lost). It creates the file and any missing directories, readable only by you, and tightens a
  broader file's permissions; if the path is a symlink, the file it points to is updated. A crash
  during a save leaves the old file or the new one. If a save fails, setup stays open with your
  edits and the reason. If the file changed on disk since setup read it, saving offers to reload
  (discarding your edits) or overwrite.
- **A file that cannot be edited.** A missing file opens at the defaults and is created on save. A
  file that cannot be read or parsed, or holds an unknown key, exits 2 with the problems `nyx recon`
  reports for it; one that parses but holds an invalid value opens with that value marked, and saving
  is blocked until it is fixed or cleared.
- **Updating the threat data without the editor.** `nyx setup --update-threat-data` updates the five
  lists and exits. It never opens the editor, needs no terminal on stdin or stdout, and reads no
  config file, so it runs with no config file and with an invalid one; `--config` is accepted and
  ignored, and an argument exits 2. It sends at most one request per list to `www.spamhaus.org` and
  `ipapi.is`, and nothing to a target, and prints each list's old and new date, its entry count and
  what was added and removed, which `--quiet` does not suppress. It writes the downloaded copy, and
  nothing else, to the `threat-data` directory beside the default config file, in
  `$XDG_CONFIG_HOME/nyx/` or else `~/.config/nyx/`, whatever `--config` is given: `spamhaus.jsonl`
  and `ipapi.json` with, for each source, a `.state.json` file (when it last answered) and a `.lock`
  file. Deleting the directory restores the built-in data. With neither `XDG_CONFIG_HOME` nor `HOME`
  set it exits 2 and says why. The update exits 0 when every source updated, was already current or
  was skipped (it sends a source nothing within an hour of its last answer), 7 when one source
  failed, 1 when both failed, and 130, 143 or 129 on a signal; with `--json` it writes one envelope
  on exit 0 or 7. The details are on [Abusive networks](abusive-networks.md#updating-the-threat-data).
- **What it ignores.** The environment: what setup shows and saves is what nyx reads, as no setting
  or key comes from anywhere else.
- **Exit codes.** For the editor, 0 after a save, a discard or no change. It exits 2, before drawing anything, when
  there is no `--config` and no default path (neither `XDG_CONFIG_HOME` nor `HOME` is set), when it
  is given an argument, when stdin or stdout is not a terminal (error code `INVALID_INPUT`, with the
  file's path and a hint to edit it by hand), and when the file cannot be read, parsed or holds an
  unknown key. SIGTERM and SIGHUP exit 143 and 129 with the file as it was, or fully saved when a
  save was already under way. The terminal is restored on every exit. `nyx setup --help` works when
  piped.
- **The hint.** When no config file exists at the default path and `--config` is not given,
  `nyx recon` (a run, not `nyx recon export`) and `nyx cve` print one line on stderr, `hint: no config
  file at <path>; run nyx setup to store API keys and settings`. It is not printed under `--json`
  or `--quiet`, or when the command fails with a usage error, and it changes nothing else about the
  call.
