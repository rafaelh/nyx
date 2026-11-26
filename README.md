# nyx recon

A reconnaissance tool for gaining a rapid understanding of a new attack surface, such as a newly
acquired company. Give it domains, organisations, ASNs or netblocks, and it records the hosts, IPs,
web services, URLs and open ports it can find, plus a severity-ranked list of obvious exposures
(dangling CNAMEs, public cloud storage, weak email policy, risky open ports, sensitive paths,
expiring certificates). It is a single Go binary for macOS and Linux, with no external tools to
install. Windows is not supported.

## Install

```sh
go install github.com/rafaelh/nyx/cmd/nyx@latest
```

Go 1.21 or later is enough when `GOTOOLCHAIN=auto`, the upstream default. If `go env GOTOOLCHAIN`
says `local`, run `GOTOOLCHAIN=auto go install ...` instead. Set `CGO_ENABLED=0` for a fully static
Linux binary. From a clone, `make build` builds
`./nyx`, `make dist` builds all four platforms and `make test` runs the tests.

For tab completion, add `source <(nyx completion zsh)` to `~/.zshrc` (or
`source <(nyx completion bash)` to `~/.bashrc`); see [Commands](docs/commands.md#commands).

## Quick start

```sh
nyx setup                              # store API keys and settings in the config file
nyx recon example.com --passive        # third-party sources only; nothing at the target is contacted
nyx recon example.com --authorised     # all procedures; confirms you are authorised to test the scope
nyx recon -e example-com               # re-run or resume an existing engagement by name
nyx cve CVE-2021-44228                 # look a CVE up in the NVD
nyx ip 1.1.1.1                         # who runs an address, and what is known about it
```

Results are written to `./<engagement>/` (this is configurable). `nyx --help` prints all the
sub-commands and flags to modify them. `nyx` is agent friendly, but you probably don't want your
agent running full recon passes that take 35 mins or more.

## Documentation

- [Commands and engagements](docs/commands.md): commands, inputs, re-runs and resume, `--redo` and
  `--skip`, large netblocks, `--timeout`
- [Configuration and setup](docs/configuration.md): the config file, API keys, settings, `nyx setup`
- [Passive boundary and authorisation](docs/passive-boundary.md): what targets and third parties
  receive, `--passive`, `--authorised`
- [Third-party sources](docs/sources.md): RDAP, Shodan per address, reverse IP, GitHub code search
- [Abusive networks](docs/abusive-networks.md): Spamhaus DROP and ipapi.is data, and `nyx setup --update-threat-data`
- [Ranked candidates](docs/candidates.md)
- [Console and JSON](docs/console-and-json.md): the log, the summary, terminal layout, the `--json`
  envelope
- [Output files and export](docs/output.md): the CSV and TXT files, `changes.csv`,
  `nyx recon export`
- [Migrating from the Python version](docs/migrating.md)

# Credits

Data on abusive networks is available thanks to:

- Spamhaus’s [Don’t Route Or Peer Lists (DROP)](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) Project, (c) The Spamhaus Project SLU ([terms](https://www.spamhaus.org/drop/terms/)).
- ipapi.is [Most Abusive Networks on the Internet](https://ipapi.is/most-abusive-networks.html)

- 110,000 subdomains from the Top 1 Million subdomains, Daniel Miessler's [SecLists](https://github.com/danielmiessler/SecLists)
