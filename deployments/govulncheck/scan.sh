#!/usr/bin/env bash
# Achilles entrypoint for govulncheck: run source-mode analysis over the Go
# module at <src-root> and write SARIF to <out-sarif>.
#
# Usage: scan.sh <src-root> <out-sarif> [extra govulncheck args...]
#
# govulncheck emits SARIF on stdout and exits non-zero when it finds vulns;
# Achilles keys success on the output file existing, so we don't fail on that.
set -u

root="${1:?usage: scan.sh <src-root> <out-sarif> [args...]}"; shift
out="${1:?usage: scan.sh <src-root> <out-sarif> [args...]}"; shift

cd "$root" || { echo "govulncheck: cannot enter source root $root" >&2; exit 3; }

# Source mode (default) is reachability-aware: it reports which vulnerable
# symbols are actually called. Needs network (the vuln DB + the module graph).
govulncheck -format sarif "$@" ./... > "$out"
