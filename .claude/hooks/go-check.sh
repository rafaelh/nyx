#!/usr/bin/env bash
# Format and check Go edits after Claude's file-writing tools run.
#
# gofmt updates the file; vet and the pinned linter check its package.
# Lint reports changed lines only so existing findings do not block unrelated edits.
#
# Exit 2 returns diagnostics to Claude for correction.
set -uo pipefail

file=$(jq -r '.tool_input.file_path // empty')
[[ "$file" == *.go && -f "$file" ]] || exit 0

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}" || exit 0

errors=""

if ! out=$(gofmt -w "$file" 2>&1); then
  errors+="gofmt failed on $file:"$'\n'"$out"$'\n'
  # Stop here to avoid repeating syntax errors through vet and lint.
  printf '%s' "$errors" >&2
  exit 2
fi

# Resolve relatively without GNU-only realpath flags, for macOS compatibility.
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
