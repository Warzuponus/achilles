#!/usr/bin/env bash
# Achilles entrypoint for ShellCheck: find shell scripts under <src-root>, run
# ShellCheck over them, and write its JSON to <out-json>.
#
# Usage: scan.sh <src-root> <out-json> [extra shellcheck args...]
#
# ShellCheck takes files (not a directory) and writes JSON to stdout (no output
# flag), so we discover the scripts and redirect. It exits non-zero when it finds
# issues; Achilles keys success on the output file, so we don't fail on that.
# Written portably (no `mapfile`) so it runs on any bash.
set -u

root="${1:?usage: scan.sh <src-root> <out-json> [args...]}"; shift
out="${1:?usage: scan.sh <src-root> <out-json> [args...]}"; shift

list=$(find "$root" -type f \( -name '*.sh' -o -name '*.bash' \))
if [ -z "$list" ]; then
  # No shell scripts: emit an empty result set (a valid, findings-free scan).
  echo "[]" > "$out"
  exit 0
fi

files=()
while IFS= read -r f; do
  files+=("$f")
done <<< "$list"

shellcheck -f json "$@" "${files[@]}" > "$out"
