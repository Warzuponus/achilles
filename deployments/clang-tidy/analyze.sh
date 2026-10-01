#!/usr/bin/env bash
# Achilles entrypoint for clang-tidy: discover C/C++ sources under the source
# root, run clang-tidy, and convert its output to SARIF via clang-tidy-sarif.
#
# Usage: analyze.sh <src-root> <out-sarif> [extra clang-tidy args...]
# NOTE: no pipefail — clang-tidy may exit non-zero on findings, but clang-tidy-sarif
# still consumes its output and writes the SARIF file (that's what we key on).
set -u

root="${1:?usage: analyze.sh <src-root> <out-sarif> [args...]}"; shift
out="${1:?usage: analyze.sh <src-root> <out-sarif> [args...]}"; shift

mapfile -t files < <(find "$root" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \))
if [ "${#files[@]}" -eq 0 ]; then
  echo "clang-tidy: no C/C++ sources under $root" >&2
  exit 3
fi

CHECKS='clang-analyzer-*,bugprone-*,cert-*'
if [ -f "$root/compile_commands.json" ]; then
  clang-tidy -p "$root" --checks="$CHECKS" "$@" "${files[@]}" 2>/dev/null | clang-tidy-sarif -o "$out"
else
  # No compile database: analyze with clang defaults (flags after --).
  clang-tidy --checks="$CHECKS" "$@" "${files[@]}" -- 2>/dev/null | clang-tidy-sarif -o "$out"
fi
