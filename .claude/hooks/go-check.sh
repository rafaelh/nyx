#!/usr/bin/env bash
# PostToolUse hook: format and check a Go file after Claude edits it.
#
# - gofmt rewrites the file in place (silent on success).
# - go vet type-checks the edited file's package.
# - golangci-lint, the version pinned in tools/go.mod (run with go tool, so
#   nothing needs installing), lints that package, reporting only issues on
#   lines changed since HEAD so pre-existing findings don't block every edit.
#
# Exit 2 sends stderr back to Claude so it can fix the problem.
set -uo pipefail

file=$(jq -r '.tool_input.file_path // empty')
[[ "$file" == *.go && -f "$file" ]] || exit 0

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}" || exit 0

errors=""

if ! out=$(gofmt -w "$file" 2>&1); then
  errors+="gofmt failed on $file:"$'\n'"$out"$'\n'
  # A syntax error will also fail vet and lint with the same message.
  printf '%s' "$errors" >&2
  exit 2
fi

# Portable: BSD realpath (macOS) has no --relative-to.
pkg="./$(dirname "${file#"$PWD"/}")"

if ! out=$(go vet "$pkg" 2>&1); then
  errors+="go vet $pkg:"$'\n'"$out"$'\n'
fi

if ! out=$(go tool -modfile=tools/go.mod golangci-lint run --new-from-rev=HEAD "$pkg" 2>&1); then
  errors+="golangci-lint $pkg (new issues only):"$'\n'"$out"$'\n'
fi

if [[ -n "$errors" ]]; then
  printf '%s' "$errors" >&2
  exit 2
fi
exit 0
