#!/usr/bin/env bash
# Prepares and publishes a nyx release. See docs/release-preparation.md.
#
#   scripts/release.sh prepare          refresh dependencies, eol data and threat data, then run
#                                       every check; leaves the changes uncommitted for review
#   scripts/release.sh publish vX.Y.Z   tag the pushed HEAD of main, build dist/, verify the
#                                       version stamp, push the tag and create the GitHub release
#
# YES=1 skips publish's confirmation prompt.
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
	echo "release: $*" >&2
	exit 1
}
step() { printf '\n==> %s\n' "$*"; }

# preflight requires a clean main that matches origin/main, the tools the steps use, and a
# signed-in gh.
preflight() {
	step "Preflight"
	local tool
	for tool in git go curl jq gh shasum; do
		command -v "$tool" >/dev/null || die "$tool is not on PATH"
	done
	[[ "$(git branch --show-current)" == main ]] || die "not on main"
	[[ -z "$(git status --porcelain)" ]] || die "the working tree is not clean"
	git fetch --quiet --tags origin || die "git fetch origin failed"
	[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] ||
		die "HEAD is not origin/main (push or pull first)"
	gh auth status >/dev/null 2>&1 || die "gh is not signed in (run gh auth login)"
	echo "main is clean and matches origin/main"
}

# run_check runs a make target and, if it fails, prints the hint before stopping.
run_check() {
	local target=$1 hint=$2
	step "make $target"
	if ! make "$target"; then
		echo >&2
		echo "release: make $target failed. $hint" >&2
		exit 1
	fi
}

prepare() {
	preflight

	step "Update the app's dependencies"
	go get -u ./...
	go mod tidy
	go mod verify

	step "Update the tools (golangci-lint, govulncheck)"
	go get -modfile=tools/go.mod -u tool
	go mod tidy -modfile=tools/go.mod

	step "make eol-data"
	make eol-data

	step "make threat-data"
	make threat-data

	run_check lint "A golangci-lint upgrade can add findings: fix them, or pin the previous version in tools/go.mod."
	run_check vuln "Upgrade the vulnerable module, or the Go toolchain (the go line in go.mod) for a standard library finding."
	run_check test "If TestAbusiveDocs_GiveTheSnapshotDates failed, copy the dates printed by make threat-data into the table in docs/abusive-networks.md and run make test again."

	step "Changes to review"
	git status --short
	git diff --stat
	cat <<'EOF'

Next:
  1. Review the diff: dependency bumps, internal/eol/data, internal/spamhaus/builtin.jsonl and
     internal/abusive/snapshot.json.
  2. If the threat data changed, check the five dates in docs/abusive-networks.md.
  3. Commit as "chore: prepare vX.Y.Z" and push to origin main.
  4. make release VERSION=vX.Y.Z
EOF
}

# check_version validates the version and requires it to be newer than every existing v* tag.
check_version() {
	local version=$1
	step "Check $version"
	[[ "$version" =~ ^v([0-9]+)\.[0-9]+\.[0-9]+$ ]] || die "$version is not vMAJOR.MINOR.PATCH"
	local major=${BASH_REMATCH[1]}
	if ((major >= 2)); then
		# Go requires a /vN suffix on the module path for major versions 2 and above.
		local module
		module=$(go list -m)
		[[ "$module" == */v"$major" ]] || die "$version needs the module path to end in /v$major (it is $module)"
	fi
	git rev-parse -q --verify "refs/tags/$version" >/dev/null && die "tag $version already exists"
	[[ -z "$(git ls-remote --tags origin "refs/tags/$version")" ]] || die "tag $version already exists on origin"

	local latest
	latest=$(git tag --list 'v*' --sort=-v:refname | head -n1)
	if [[ -n "$latest" ]]; then
		[[ "$(printf '%s\n%s\n' "$latest" "$version" | sort -V | tail -n1)" == "$version" ]] ||
			die "$version is not newer than the latest tag $latest"
		echo "$latest -> $version"
	else
		echo "first release: $version"
	fi
}

# verify_dist checks every binary in dist/ carries the release version, and that the host's
# binary reports it.
verify_dist() {
	local version=$1 module bin got
	module=$(go list -m)
	step "Verify the version stamp"
	for bin in dist/nyx-*; do
		got=$(go version -m "$bin" | awk -v m="$module" '$1 == "mod" && $2 == m { print $3 }')
		[[ "$got" == "$version" ]] || die "$bin is stamped '$got', not $version"
		echo "$bin: $got"
	done
	local host
	host="dist/nyx-$(go env GOOS)-$(go env GOARCH)"
	if [[ -x "$host" ]]; then
		got=$("$host" --version)
		[[ "$got" == "nyx $version" ]] || die "$host --version printed '$got'"
		echo "$host --version: $got"
	fi
	(cd dist && shasum -a 256 -c SHA256SUMS)
}

# write_notes writes release notes from the conventional-commit subjects since the previous tag.
write_notes() {
	local version=$1 previous=$2 out=$3 repo
	repo=$(gh repo view --json nameWithOwner -q .nameWithOwner)
	if [[ -z "$previous" ]]; then
		echo "Initial release." >"$out"
		return
	fi
	local subjects feats fixes
	subjects=$(git log --no-merges --format=%s "$previous..$version")
	feats=$(sed -n 's/^feat\(([^)]*)\)\{0,1\}!\{0,1\}: */- /p' <<<"$subjects")
	fixes=$(sed -n 's/^fix\(([^)]*)\)\{0,1\}!\{0,1\}: */- /p' <<<"$subjects")
	{
		if [[ -n "$feats" ]]; then printf '## Features\n\n%s\n\n' "$feats"; fi
		if [[ -n "$fixes" ]]; then printf '## Fixes\n\n%s\n\n' "$fixes"; fi
		printf 'Full changelog: https://github.com/%s/compare/%s...%s\n' "$repo" "$previous" "$version"
	} >"$out"
}

cleanup() {
	rm -f "$notes"
	if ((pushed == 0)) && git tag -d "$release_tag" >/dev/null 2>&1; then
		echo "release: removed the local tag $release_tag" >&2
	fi
}

publish() {
	local version=${1:-}
	[[ -n "$version" ]] || die "usage: scripts/release.sh publish vX.Y.Z"
	preflight
	check_version "$version"
	local previous
	previous=$(git tag --list 'v*' --sort=-v:refname | head -n1)

	run_check lint "Fix the findings and commit before releasing."
	run_check test "Fix the failures and commit before releasing."

	step "Tag $version (local)"
	git tag -a "$version" -m "$version"
	# Globals, because the EXIT trap runs after publish returns. Until the tag is pushed, a failure
	# removes it so the release can simply be run again.
	release_tag=$version
	pushed=0
	notes=$(mktemp)
	trap cleanup EXIT

	step "make dist"
	make dist
	verify_dist "$version"

	write_notes "$version" "$previous" "$notes"
	step "Release notes"
	cat "$notes"

	if [[ "${YES:-}" != 1 ]]; then
		local answer
		printf '\nPush tag and publish %s? [y/N] ' "$version"
		read -r answer
		[[ "$answer" == [yY] || "$answer" == [yY][eE][sS] ]] || die "not published"
	fi

	step "Push $version"
	git push origin "refs/tags/$version"
	pushed=1

	step "Create the GitHub release"
	gh release create "$version" --verify-tag --title "$version" --notes-file "$notes" \
		dist/nyx-* dist/SHA256SUMS
	gh release view "$version" --json url -q .url
}

case "${1:-}" in
prepare) prepare ;;
publish) publish "${2:-}" ;;
*)
	echo "usage: scripts/release.sh prepare | publish vX.Y.Z" >&2
	exit 2
	;;
esac
