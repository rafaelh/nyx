# Release preparation

This page is for maintainers. It is not part of the user guide.

A release is a semver tag on `main` and a GitHub release that carries the four `make dist` binaries
and their `SHA256SUMS`. Releasing takes two commands with a review in between:

```sh
make release-prep                  # refresh dependencies and data, run every check
# review, update the threat-data dates if needed, commit "chore: prepare vX.Y.Z", push
make release VERSION=vX.Y.Z        # tag, build, verify, push the tag, publish
```

Both run `scripts/release.sh`. Every step is listed under [By hand](#by-hand), so a release can be
done or recovered without the script.

## Prerequisites

- `go`, `curl`, `jq`, `shasum` and `gh` on `PATH`. Sign `gh` in with `gh auth login`, using an
  account that can push tags and create releases.
- A clean checkout of `main` that matches `origin/main`. Both commands refuse to start otherwise.

## The version

`nyx --version` (and the `nyx/<version>` User-Agent) reports the module version that `go build`
stamps from git. A build from a clean commit that is exactly at a tag reports that tag. Any other
build reports a pseudo-version (`v0.0.0-20261124…-abcdef123456`), with `+dirty` when the tree had
changes. No version is written in a file, so **bumping the version means choosing a new tag**:

- It is `vMAJOR.MINOR.PATCH`, newer than every existing `v*` tag.
- Bump PATCH for fixes and data refreshes only, MINOR for new behaviour, and MAJOR for a breaking
  change to the stable interface: the exit codes, the error codes, and the JSON keys listed in
  [exit-codes.md](exit-codes.md) and [console-and-json.md](console-and-json.md).
- From v2 onwards, Go requires the module path to end in `/vN` (`github.com/rafaelh/nyx/v2`), or
  `go install …@v2.0.0` fails. `make release` refuses a major version of 2 or more without it.

## make release-prep

1. Checks the prerequisites above.
2. Updates the app's dependencies (`go get -u ./...`, `go mod tidy`, `go mod verify`) and the tools
   in `tools/go.mod` (golangci-lint and govulncheck).
3. Refreshes the end-of-life data (`make eol-data`) and the built-in threat data
   (`make threat-data`).
4. Runs `make lint`, `make vuln` and `make test`, and stops at the first failure with a hint.
5. Lists the changed files and leaves them uncommitted.

Then review the changes before committing:

- **Dependencies.** Read the `go.mod` diff. A major bump of a direct dependency deserves a look at
  its changelog, even when the tests pass.
- **Lint.** A newer golangci-lint can report new findings. Fix them, or pin the previous version in
  `tools/go.mod` and leave the upgrade for later.
- **Vulnerabilities.** `make vuln` (govulncheck, which contacts `vuln.go.dev`) reports vulnerable
  code that nyx actually calls. A static binary carries the standard library of the toolchain that
  built it, so a standard library finding is fixed by installing the patched Go release and raising
  the `go` line in `go.mod` to it.
- **End-of-life data.** Skim `internal/eol/data`. A cycle whose end date moved changes findings.
- **Threat data.** `make threat-data` prints each list's old and new date and the entries that
  changed. Copy the five dates into the table in
  [abusive-networks.md](abusive-networks.md#the-data-in-use).
  `TestAbusiveDocs_GiveTheSnapshotDates` fails until they match. A list that shrank to under half
  its entries is refused. If the shrink is real, rerun with `make threat-data ALLOW_SHRINK=1`.

Rerun `make test` after any fix. Then commit as `chore: prepare vX.Y.Z` and push to `origin main`.

## make release VERSION=vX.Y.Z

1. Checks the prerequisites and the version: its form, that it is newer than the latest tag, the
   `/vN` rule, and that no tag of that name exists locally or on `origin`.
2. Runs `make lint` and `make test` on the exact commit being released.
3. Creates the annotated tag locally.
4. Runs `make dist`, which empties `dist/`, builds the four binaries and writes `dist/SHA256SUMS`.
5. Checks that every binary is stamped with the version (`go version -m`), that the host's binary
   prints `nyx vX.Y.Z`, and that the checksums match.
6. Writes release notes from the commit subjects since the previous tag: `feat:` under Features,
   `fix:` under Fixes, and a compare link. `docs:`, `chore:`, `style:` and `refactor:` are left out.
   The first release says "Initial release."
7. Shows the notes and asks for confirmation (`YES=1` skips the question).
8. Pushes the tag and runs `gh release create` with the notes, the binaries and `SHA256SUMS`.

Up to the push, a failure or a "no" removes the local tag, so the command can be run again after a
fix. Edit the notes afterwards with `gh release edit vX.Y.Z --notes-file <file>`, or on GitHub.

## By hand

```sh
# Preflight
git switch main && git pull --ff-only && git status --short    # must print nothing
gh auth status

# Refresh
go get -u ./... && go mod tidy && go mod verify
go get -modfile=tools/go.mod -u tool && go mod tidy -modfile=tools/go.mod
make eol-data
make threat-data                    # then update the dates table in docs/abusive-networks.md
make lint vuln test
git commit -am "chore: prepare vX.Y.Z" && git push origin main

# Tag, build and check
git tag --list 'v*' --sort=-v:refname | head -n1    # the previous version
git tag -a vX.Y.Z -m vX.Y.Z
make dist
go version -m dist/nyx-linux-amd64 | grep '^\s*mod'  # shows vX.Y.Z
(cd dist && shasum -a 256 -c SHA256SUMS)

# Publish
git push origin vX.Y.Z
gh release create vX.Y.Z --verify-tag --title vX.Y.Z --generate-notes dist/nyx-* dist/SHA256SUMS
```

## Undoing a release

- Before the tag is pushed: `git tag -d vX.Y.Z`.
- A release that is wrong but harmless: publish a new patch version. Don't move a tag that has been
  pushed. The Go module proxy caches the first commit it saw for a version, and anyone who
  installed it keeps it.
- A release that must not be used: `gh release delete vX.Y.Z --cleanup-tag`, then
  [retract](https://go.dev/ref/mod#go-mod-file-retract) the version in `go.mod` in the next
  release.
