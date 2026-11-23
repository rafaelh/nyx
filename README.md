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

## Quick start

```sh
nyx setup                              # store API keys and settings in the config file
nyx recon example.com --passive        # third-party sources only; nothing at the target is contacted
nyx recon example.com --authorised     # all stages; confirms you are authorised to test the scope
nyx recon -e example-com               # re-run or resume an existing engagement by name
nyx cve CVE-2021-44228                 # look a CVE up in the NVD
nyx ip 1.1.1.1                         # who runs an address, and what is known about it
```

Results are written to `<output-dir>/<engagement>/` (`output_dir` defaults to `.`). `nyx --help`
prints the whole reference.

## Documentation

- [Commands and engagements](docs/commands.md): commands, inputs, re-runs and resume, `--redo` and
  `--skip`, large netblocks, `--timeout`
- [Configuration and setup](docs/configuration.md): the config file, API keys, settings, `nyx setup`
- [Passive boundary and authorisation](docs/passive-boundary.md): what targets and third parties
  receive, `--passive`, `--authorised`
- [DNS and third parties](docs/dns.md): root records, SRV names, mail and SaaS dependencies,
  shared name servers and mail hosts
- [Web services](docs/web.md): web posture, TLS detail, JavaScript endpoints, web identifiers,
  origin exposure
- [Third-party sources](docs/sources.md): RDAP, Shodan per address, reverse IP, GitHub code search
- [End-of-life software](docs/end-of-life.md)
- [Abusive networks](docs/abusive-networks.md)
- [Built-in lists and per-run limits](docs/lists-and-limits.md)
- [Ranked candidates](docs/candidates.md)
- [Console and JSON](docs/console-and-json.md): the log, the summary, terminal layout, the `--json`
  envelope
- [Output files and export](docs/output.md): the CSV and TXT files, `changes.csv`,
  `nyx recon export`
- [CVE lookup](docs/cve.md): `nyx cve`
- [IP lookup](docs/ip.md): `nyx ip`
- [Exit codes and errors](docs/exit-codes.md)
- [Migrating from the Python version](docs/migrating.md)

# Credits

Data on abusive networks is available thanks to:

- SpamHaus’s [Don’t Route Or Peer Lists (DROP)](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) Project.
- ipapis.is [Most Abusive Networks on the Internet](https://ipapi.is/most-abusive-networks.html)
