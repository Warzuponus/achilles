#!/usr/bin/env bash
# Achilles entrypoint for Security Code Scan's `security-scan` tool.
# security-scan needs a .sln/.csproj target and writes obj/ during MSBuild load,
# but Achilles mounts the source read-only. So: discover the project, copy the
# tree to a writable workdir, restore, then scan.
#
# Usage: scan.sh <src-root> [security-scan flags...]   (e.g. --export=/mnt/out/x.sarif)
set -uo pipefail

root="${1:?usage: scan.sh <src-root> [flags...]}"; shift

work="$(mktemp -d)"
cp -a "$root/." "$work/" 2>/dev/null || cp -a "$root/." "$work/"

proj="$(find "$work" -maxdepth 4 -name '*.sln' | head -1)"
[ -z "$proj" ] && proj="$(find "$work" -maxdepth 4 -name '*.csproj' | head -1)"
[ -z "$proj" ] && proj="$(find "$work" -maxdepth 4 -name '*.vbproj' | head -1)"
if [ -z "$proj" ]; then
  echo "security-code-scan: no .sln/.csproj/.vbproj found under $root" >&2
  exit 3
fi

echo "security-code-scan: restoring $proj" >&2
dotnet restore "$proj" >&2 || true   # best-effort; --ignore-msbuild-errors covers gaps

echo "security-code-scan: scanning $proj" >&2
exec security-scan "$proj" "$@"
