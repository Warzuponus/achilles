#!/usr/bin/env bash
# Guards the published tree against content that must never ship: local paths, key
# material, deployment state, local vaults, and (optionally) a private denylist.
#
#   scripts/check-tree.sh                        # generic checks (what CI runs)
#   scripts/check-tree.sh --denylist FILE        # also fail on any pattern in FILE
#   scripts/check-tree.sh --ref <git-ref>        # check a ref instead of the working tree
#
# FILE holds one case-insensitive extended regex per line ('#' comments allowed). Keep it
# PRIVATE (outside the repo): a committed denylist of names would itself publish them.
# Run against the final publish candidate before pushing it anywhere.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DENY="" REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --denylist) DENY="${2:?--denylist needs a file}"; shift 2 ;;
    --ref)      REF="${2:?--ref needs a git ref}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# The tree under test, as a list of files and a directory of their contents.
if [ -n "$REF" ]; then
  git ls-tree -r --name-only "$REF" > "$TMP/files"
  mkdir "$TMP/tree"; git archive "$REF" | tar -x -C "$TMP/tree"; ROOT="$TMP/tree"
else
  git ls-files > "$TMP/files"; ROOT="."
fi
cp "$TMP/files" "$TMP/scan"

# report runs at the end of pipes (a subshell), so it records failure in a file, not a variable.
report() { echo "FAIL: $1" >&2; sed 's/^/    /' >&2; : > "$TMP/failed"; }

# 1. Files that must not be tracked at all.
bad_paths="$(grep -E '(^|/)(\.secrets/|\.env$|\.env\.[^/]*$|terraform\.tfvars$|backend\.hcl$|[^/]*\.tfstate(\.backup)?$|id_(rsa|ed25519|ecdsa)$|[^/]*\.pem$)|(^|/)\.terraform/|\.jsonl$' "$TMP/scan" \
            | grep -v -E '\.example$|\.env\.example$' || true)"
[ -z "$bad_paths" ] || printf '%s\n' "$bad_paths" | report "tracked files that must not be published (secrets, state, local vaults)"

# 2. Content patterns. grep_tree <grep flags> <ERE>: file:line:text for every hit in the
# scanned files (binary files skipped). NUL-delimited so odd filenames are safe, and
# portable across GNU and BSD xargs.
grep_tree() {
  (cd "$ROOT" && tr '\n' '\0' < "$TMP/scan" | xargs -0 grep -I -n "$@" 2>/dev/null) || true
}
check_content() { # <label> <ERE> [path:-exclusion ERE] [extra grep flags]
  local out
  out="$(grep_tree -E ${4:-} -- "$2")"
  if [ -n "${3:-}" ]; then out="$(printf '%s\n' "$out" | grep -v -E "$3" || true)"; fi
  [ -z "$out" ] || printf '%s\n' "$out" | cut -c1-180 | report "$1"
}
check_content "absolute home-directory paths" '/Users/[A-Za-z0-9._-]+/|/home/[a-z][a-z0-9._-]+/' \
  '^(docs/site\.html|scripts/check-tree\.sh):|/home/linuxbrew|/home/runner|/home/achilles'
# The project is local-first: a cloud SDK in go.mod would re-introduce a cloud dependency.
if [ -f "$ROOT/go.mod" ]; then
  bad_mod="$(grep -n -E 'cloud\.google\.com|google\.golang\.org|golang\.org/x/oauth2|aws-sdk|azure-sdk' "$ROOT/go.mod" || true)"
  [ -z "$bad_mod" ] || printf 'go.mod:%s\n' "$bad_mod" | report "cloud SDK module in go.mod (this project must run with no cloud dependency)"
fi
check_content "private key material" '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' \
  '^(scripts/check-tree\.sh|internal/fleet/[a-z_]*_test\.go):'
check_content "references to a hosted cloud service (this project must run with no cloud dependency)" \
  '[Ff]irestore|[Vv]ertex AI|Cloud Run|Workload Identity|googleapis\.com|gcloud|GOOGLE_CLOUD' '^scripts/check-tree\.sh:'

# 3. Optional private denylist: one case-insensitive ERE per line.
if [ -n "$DENY" ]; then
  [ -f "$DENY" ] || { echo "denylist not found: $DENY" >&2; exit 2; }
  n=0
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue ;; esac
    n=$((n+1))
    out="$(grep_tree -i -E -- "$pat")"
    # Never echo the pattern or the matching text: both may be the sensitive thing.
    [ -z "$out" ] || { printf '%s\n' "$out" | cut -d: -f1,2 | sed 's/^/    /' >&2
                       echo "FAIL: denylist entry #$n matched $(printf '%s\n' "$out" | wc -l | tr -d ' ') line(s) (locations above)" >&2; : > "$TMP/failed"; }
  done < "$DENY"
fi

if [ -e "$TMP/failed" ]; then echo "check-tree: FAILED" >&2; exit 1; fi
echo "check-tree: ok ($(wc -l < "$TMP/scan" | tr -d ' ') files)"
