# CLAUDE.md

nyx is a passive-first reconnaissance CLI: a single static Go binary for macOS, Linux, and WSL
(Windows is not supported). The user-facing behaviour contract (flags, output files, exit codes, the
passive boundary) is the user guide in `docs/*.md` (all but `docs/todo.md` and `docs/release-preparation.md`, which are for maintainers; `README.md` is a short
introduction that links to each page). The domain vocabulary (engagement, scope input, stage, check,
observation, record, record kind, shown, evidence, finding) is defined in the doc comments of the
packages that own each term.

## Commands

```sh
make build                      # ./nyx (CGO_ENABLED=0, -trimpath)
make test                       # go vet for all 4 GOOS/GOARCH targets, then go test -race ./...
make dist                       # dist/nyx-{darwin,linux}-{amd64,arm64}
go test ./internal/cli/ -run 'TestPorts_' -count=1   # one package, tests matching a regex
make lint                       # golangci-lint pinned in tools/go.mod; config in .golangci.yml
make vuln                       # govulncheck pinned in tools/go.mod (contacts vuln.go.dev)
make eol-data                   # refresh internal/eol/data from endoflife.date (needs curl, jq); review the diff
make threat-data                # refresh the built-in threat data (internal/spamhaus/builtin.jsonl from spamhaus.org, internal/abusive/snapshot.json from ipapi.is; needs curl); review the diff and update the five dates in docs/abusive-networks.md. ALLOW_SHRINK=1 lets through a list you reviewed that shrank to under half
make release-prep               # update deps, eol-data and threat-data, then lint, vuln and test; leaves changes to review
make release VERSION=vX.Y.Z     # tag, dist, verify the version stamp, push the tag and gh release create (docs/release-preparation.md)
```

- While iterating, run targeted tests without `-race`: the race detector roughly triples the cost.
  `make test` and CI keep it.
- Don't export `CGO_ENABLED=0` globally: `-race` needs cgo on Linux.
- `go.mod` pins a recent toolchain. With `GOTOOLCHAIN=local` and an older Go, builds fail.
- The `.claude/hooks/go-check.sh` PostToolUse hook runs `gofmt -w`, `go vet` and golangci-lint
  (new issues only) on each edited `.go` file. Exit 2 means it found something to fix. gofmt
  rewrites the file in place, so its contents may differ from what you just wrote.
- When running the binary by hand, use an `--output-dir` outside the repo. `output_dir` defaults
  to `.`, and `/output/` is gitignored.

## Hard invariants (enforced by tests)

- **Only `internal/egress` does network I/O.** `internal/egress/boundary_test.go` checks the
  non-test files of every package, for all four targets, and fails if any of them imports `net`,
  `net/http`, `crypto/tls`, `syscall` or `github.com/miekg/dns`. Uses of `golang.org/x/sys/unix`
  are limited to an allowlist: signals in `internal/cli`, flock in `internal/engagement` and `internal/threatdata`. No
  first-party package may import `os/exec`. Stages get `egress.Clients` and egress's own result
  types, never `net/*` types. Test files may use `net` (fake servers);
  `internal/egress/egresstest` is the fake DNS server.
- **Key tests contact sources only.** `nyx setup`'s key test sends one request to the tested
  source's host and never to a target; `keycheck.Run` builds its egress client with that one host.
- **Threat-data updates contact their sources only.** Only `nyx setup --update-threat-data` (and `u`
  on setup's Threat data tab) sends anything to `www.spamhaus.org` or `ipapi.is`, never to a target;
  no recon stage, `nyx ip`, `nyx cve` or key test names either host (a test checks).
- **Passive boundary.** Target-owned systems may only receive DNS lookups, TCP handshakes (read the
  unprompted banner, send nothing) and HTTP GET/HEAD to in-scope hosts. Egress enforces this
  through a `Policy` the runner rebuilds whenever the scope changes. Candidates and excluded
  hosts/addresses are never contacted as targets. A third-party client contacts only the source
  hosts its stage declared, refusing one that is in scope or excluded; a candidate that matches a
  declared source (a storage account a redirect recorded) is asked as that source. `nyx ip --active` also completes TLS handshakes (no
  application data), through `egress.NewProbe`'s `Probe`, which alone has a TLS client: `Clients`
  never does, so recon stages cannot handshake.
- The cross-target `go vet` in `make test` exists so that an untagged platform-specific call can't
  break one OS/arch unnoticed. If you change the target list, keep `TARGETS` in the `Makefile` in
  step with the list in `boundary_test.go`.

## Architecture

Flow: `cmd/nyx` → `internal/cli` (the command tree `nyx` → `recon` → `export`, plus `cve`, `ip`, `help`
and the help topics; cobra/viper flags, a pre-scan of the arguments, validation, help, signals, and
the one place that picks the exit code and writes the error) → `internal/run.Runner` → stages →
`internal/store` (SQLite via `modernc.org/sqlite`, under `<engagement>/.nyx/`) → `internal/output`
(CSV/TXT files) and `internal/report` (the console log, the summary and the `--json` envelope).
`invocation` builds one `layout.Stream` (terminal, colour depth, width) for stdout and one for stderr,
and the human renderers take a stream where they once took a depth.
`nyx cve` skips the runner: `internal/cli/cve.go` (flags, stdin, the worker pool, the writing) →
`internal/cve` (the CVE record and its field table, the NVD client with its sliding window, the human
layout and the batch outcome), which reaches the NVD through `egress`'s third-party client.
`nyx setup` skips it too: `internal/cli/setup.go` (the checks that exit 2, then the wiring) →
`internal/setup` (the Bubble Tea model: tabs, text field, dialogs, change tracking; it does no I/O and
gets a `setup.Backend`, defined in `backend.go`) → `internal/configedit` (the YAML document that keeps
comments and order, `Save`, and the `Store` that implements the Backend's file side) and
`internal/keycheck` (one authenticated request to one source's host, through egress's third-party
client with no `Policy`; the NVD's status rules are shared with `nyx cve` through `cve.Meaning`).
`config.Check` parses and checks a file's bytes, which `Load` calls too.
`nyx setup --update-threat-data` skips the editor and the config: `internal/cli/threat.go` (the
branch in `runSetup`, the output, the `--json` envelope and the exit code) → `internal/threatdata`
(`Dir`, `Load`, the shared acceptance rules and `Update`, which reaches Spamhaus and ipapi.is
through `egress`'s third-party client with no `Policy`). The Threat data tab uses the same `Update`
through two more `setup.Backend` methods.
`nyx ip` skips it too: `internal/cli/ip.go` (flags, stdin and the writing) → `internal/iplookup`
(the inputs, the sources, active probing, the record and its field table, the outcome and the
render), which reaches third parties and DNS through `egress` with no `Policy`, and the targets
through one `egress.NewProbe` per contacted address. Its outcome rules are shared with `nyx cve`
through `internal/batch`.

**Commands and errors.** `cli.Execute` alone picks the exit code and writes the error: a command
returns an error and prints none. The error is a `clierr.Error` (code, message, hint, input,
transient); `clierr.Problems` collects every validation problem into one `INVALID_INPUT` error, and
`config.Load` and `input.Parse` return it. Any other error is `UNEXPECTED_ERROR`, and a panic on the
main goroutine, in a check or in the store's writer is recovered. `Deps.Signals` (nil in tests that
don't send any; `cli.NotifySignals` in `main`) delivers signals: the first cancels, a second exits at
once. A new command needs only `AddCommand`, an `Example` and its help annotations
(`internal/cli/help.go`) to be in the root help and the pre-scan. **The exit codes, the error codes,
the five keys of the JSON error, the keys of the recon `--json` envelope (`data` and `meta`), and the
keys of the CVE record and of the `nyx cve` envelope, the keys of the `nyx ip` record and
envelope, and the keys of the threat-data update's envelope are a stable interface**: adding one is
compatible, renaming, removing or retyping one is a breaking change (`docs/exit-codes.md`
and `docs/console-and-json.md`). The default `nyx cve` selection broke this once, deliberately: it leaves out the
`affected_products` and `references` lists and has their counts instead (`--fields all` has both).

**Stages** (`internal/run/stage.go`) implement `Name/Contact/Sources/Configured/Checks/Run`.
- `Contact` is either `ThirdParty` or `Target`, never both. A stage that would do both is split
  into two stages. Only `Target` stages get HTTP/TCP target clients. They are skipped under
  `--passive`, and also unless the engagement holds the `--authorised` acknowledgement.
- A `Check.Key` must encode every input and setting that changes the work (for example a wordlist
  hash or crawl depth), so that changing a setting creates new checks instead of reusing stale
  ones. Check results are persisted. A re-run executes only checks that haven't completed, so
  resume works and failed checks are retried.
- `Run` reports negative results (NXDOMAIN, closed port) as completed checks with zero or more
  observations. A returned error means a transient failure: the check is retried on later runs.
  Wrap `run.ErrAbortStage` to abort the stage's remaining checks for this run.
- Optional interfaces: `WorkerCounter` (a custom pool size, used by ports),
  `Retiring` (completed checks the stage no longer yields are retired, so their evidence stops
  being current), `Evidencer` (names the source and supporting item a check gives a candidate;
  without it they are the stage name and the check key, so a stage whose key carries a setting
  must implement it or a changed setting would count twice), `CandidateSourcer` (maps each source
  its evidence is given under to its candidate family; a source no stage names is a family of its
  own), `ASNExpander` (its netblocks under an input ASN's check are in scope; the asn stage), and
  `Budgeted` (a per-run cap on the summed `Check.Cost` of the checks sent; the runner defers the
  first check that would pass it and all after it, without failing or retiring them, and the
  summary reports the deferred cost). `Historical` marks a stage whose addresses come from DNS history: an address that only such stages
  observe is left out of the abusive-network check. Code outside a stage never names a stage: it asks the
  stages through these interfaces.
- Stages read state only through `run.View`, which offers scope, inventory and cached current
  records. Web stages must use `ProbeHostnames()` (wildcard-aware), not the hostname records.
- The registry order is `defaultStages()` in `internal/cli/cli.go`, and that order matters (see
  its comment). The runner repeats passes over all stages until no new work appears. After any
  stage does work it flushes the store, rebuilds the scope (which also updates the egress Policy)
  and re-derives findings.

**Record kinds** (`internal/kinds/table.go`) are typed handles. Stages write with
`kinds.X.Obs(key, attrs)`, and readers decode with `kinds.X.Attrs(rec)`. A kind whose key is
made from its attributes (`resolution`, `third_party`, the port kinds and others) is a `Keyed`
handle: it writes with `kinds.X.Obs(attrs)` and makes the key itself (`kinds.X.Key(attrs)`), and
its `Attrs` fills in from the key what a record no longer current has lost. The store merges the
attributes that several stages observed for one record, field by field. `omitempty` and pointer
fields carry meaning (see the comment at the top of `table.go`). A kind's showing rules
(counted, printed, written, used for findings) live with it, and visibility is decided at read
time from the current scope. An entity kind carries its own placement rule (in scope, candidate
or excluded).

**Derived on read, never stored by stages.** `scope` (classifies hosts and addresses as
in-scope, candidate or excluded), `inventory` (wildcards, provider hosts, port eligibility) and
`findings` are pure functions of the current records, scope, settings and date. Risk stages
(`internal/stages/risk`) store only *evidence* kinds. `internal/findings` derives findings from
the evidence that is shown. A finding that is no longer derived stays on record but is marked not
current. Records keep `first_seen`/`last_seen`/`current` and are never deleted. The findings and
the other derived records (the `candidate_rank` of each candidate, ranked by `internal/candidates`)
come from the runner's list of derivers in `internal/run/derive.go`, each stored under its own
pseudo-stage and re-derived only when the kinds it reads, the inputs or the date change. A deriver
can return a hook that runs once its records are stored (the findings use one to announce a risen
severity and to keep the storage attribution for the render).

`nyx recon export` (`internal/cli/export.go`) reads an engagement without running it: `engagement.OpenReadOnly`
takes no lock, creates nothing and returns a `store.ReadOnly` whose `View` gives one snapshot, and
`run.BuildScope` classifies records with the same rules as a run. A kind a new stage's scope depends on goes in `scopeKinds`
(`internal/run/scopebuild.go`), which the rank deriver also reads.

**Pure knowledge packages** with no I/O: `cloudstorage` (bucket naming, S3/GCS/Azure),
`provider` (shared infrastructure from CNAME suffixes, address ranges and ASNs; data in the
embedded `providers.yaml`), `eol` (end of security support; embedded endoflife.date data and
`products.yaml`), `abusive` (ipapi.is's most-abusive network and ASN lists: the embedded snapshot, refreshed by `make threat-data`, and the parser of its pages; the matches are information only), `spamhaus` (Spamhaus's DROP, DROPv6 and ASN-DROP lists: parsing, validation, matching and the embedded `builtin.jsonl`, also refreshed by `make threat-data`), `banner` (product/version from SSH/FTP/SMTP banners), `orgname` (does a name
belong to an organisation input), `origin` (origin-behind-CDN decisions, which the `origincheck`
stage and the findings both call so they can't disagree), `thirdparty`, `palette`, `shellquote`,
`dnsname`, `sanitize` (strips terminal-acting characters from
target-supplied text), `weburl` (canonical URLs, service origins and static assets, shared by the
web and archive stages), `input`, `layout` (cell width, wrapping, tables, headings and rules for a
terminal; the renderers take a `layout.Stream` and return their plain output unchanged when it is
not a terminal). The built-in wordlist and sensitive-path list are embedded in
`internal/config/builtin/`.

**Config** (`internal/config`): the config file is the only source of settings and keys; flags
override it, and unknown keys are rejected. No setting or key is read from the environment (no
`NYX_*` variable, no `NVD_API_KEY`, no `.env`). `config` reads only `HOME` and `XDG_CONFIG_HOME`, from the `config.Env` passed in
(`Deps.Env`), never with `os.Getenv` or viper's `AutomaticEnv`. API keys come only from
`keys.<source>`; tests set one with the harness's `h.setKey` (and any setting with `h.set`). They are
`config.Secret` values and get redacted from all output, so never add a key flag or log a key.

**Output** files are written to `.nyx/tmp` and then renamed into place. A file is written only
when it has rows, and is removed once it has none.

## Testing

- Most behaviour tests live in `internal/cli/*_test.go`. They drive `cli.Execute` in-process
  through the `harness` in `harness_test.go`, with fake stages from `internal/testkit` or real
  stages pointed at loopback fakes. `egress.Options.SourceBaseURLs`, `ResolverAddrs` and
  `DialMap` redirect traffic without changing policy logic. The harness has UDP/HTTP/TCP
  "canaries" that detect any unexpected request. The clock is fixed at 2026-11-01 UTC.
- `--json` writes one envelope and no event lines, so the harness reads the events through
  `cli.Deps.Events` (a recorder that round-trips each event through JSON): `h.events()` returns them,
  plus a `summary` event made from the envelope on stdout. `h.envelope()` parses stdout as the real
  envelope, and `h.partial` asserts an exit 7.
- Doc tests check the user guide's wording: `docsText` and `docsSection` (`internal/cli/helpers_test.go`)
  read `README.md` and `docs/*.md` as one text, and a few packages read their own page (the favicon
  list in `docs/web.md`, the built-in lists in `docs/lists-and-limits.md`). Moving a sentence between
  pages is fine; moving it out of the `## ` section a test names is not.
- Every test calls `t.Parallel()` first. A run sees only the harness's environment: set a variable
  with `h.setenv`, never `t.Setenv` or `os.Setenv` (Go forbids `t.Setenv` in a parallel test). The
  harness also sets `Deps.NoFsync`, as an fsync on macOS flushes the whole drive cache and
  serialises the suite. A test that changes the working directory (`emptyDir`, `t.Chdir`) cannot
  be parallel, and says so with a `//nolint:paralleltest` and its reason (lint enforces the rest,
  and forbids `os.Getenv`, `t.Setenv` and `os.Setenv`). A test that starts a child process (`startChild`) is a subtest of the
  non-parallel `TestChildProcesses`, because a fork can briefly hold another test's engagement lock. Give a slow table test's subtests `t.Parallel()` when each builds its own world.
- `nyx setup` tests send keys as scripted stdin (`harness.setup`: one chunk per key press, paced so each
  gets its own frame, because the Program draws about every 17 ms) with `StdinIsTTY` and the window size
  faked. `pty_linux_test.go` runs the real child on a pseudo-terminal and checks termios, the alt screen
  and the error order; it is Linux-only, as macOS opens a pty with different ioctls. The harness gives
  every run an empty default config file, so the no-config hint is not printed; a test of the hint
  removes it.
- `crash_test.go` re-executes the test binary as a child process (`NYX_TEST_CHILD=1`) and uses
  `internal/fault` crash points (`NYX_FAULT=<point>`, such as `in-check-tx`, `after-commit`,
  `in-flight` or `render-mid-file`) to kill the process at known moments and verify resume and atomic output.

## Conventions

- Australian English in docs, comments and messages ("authorised", "behaviour", "sanitise"). Support
  for US English should be included for all input, e.g. `--authorized` is accepted as a flag alias.
- Specs live in `docs/specs/` (the `.claude/skills/spec-*` workflow). Each has `## Goal` and
  `## Behaviours`, then a `# Design` section once planned.
- CSV columns are read by people, not parsed by tools: change them freely, keeping `docs/output.md`
  accurate. Only the attribute JSON names in the state database must stay stable (renaming one
  breaks resume; see `internal/kinds/kinds.go`).
- Commit messages use conventional prefixes (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`,
  `style:`).
- `docs/todo.md` lists known deferred work, such as store statement batching, HTTP connection
  reuse, and how findings are announced.
