#!/usr/bin/env bash
# End-to-end check of the compose quickstart: bring the stack up, scan the bundled
# vulnerable sample, and confirm the findings are visible in the War Room. Also
# proves the protections that stand in for authentication. Used by CI
# (.github/workflows/quickstart.yml) and runnable locally:
#
#   deploy/compose/smoke.sh          # builds, runs, tears down (keeps images)
#   KEEP=1 deploy/compose/smoke.sh   # leave the stack running afterwards
set -euo pipefail
cd "$(dirname "$0")"

PORT="${WARROOM_PORT:-8080}"
URL="http://localhost:${PORT}"
fail() { echo "SMOKE FAIL: $*" >&2; docker compose logs --tail=60 >&2 || true; exit 1; }
cleanup() { [ "${KEEP:-}" = 1 ] || docker compose --profile scan down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo ">> up (build + postgres + war room)"
docker compose up -d --build --wait || fail "stack did not become healthy"

echo ">> health"
curl -fsS "$URL/healthz" | grep -q ok || fail "/healthz"

echo ">> scan the bundled sample (strict: every scanner must run)"
docker compose --profile scan run --rm scan || fail "scan failed (a scanner could not run, or findings gated)"

echo ">> the dashboard lists the run"
RUN_ID="$(curl -fsS "$URL/" | grep -o '/runs/[^"?#<> ]*' | head -1 | sed 's|/runs/||')"
[ -n "$RUN_ID" ] || fail "no run listed on the dashboard"
echo "   run: $RUN_ID"

echo ">> the run page shows real findings from both a Python and a Go scanner"
PAGE="$(curl -fsS "$URL/runs/$RUN_ID")"
echo "$PAGE" | grep -q 'dangerous-eval' || fail "opengrep finding (python eval) missing from the run page"
echo "$PAGE" | grep -q 'G204'          || fail "gosec finding (go exec) missing from the run page"

echo ">> the port is published on loopback only"
BIND="$(docker compose port warroom 8080)"
case "$BIND" in 127.0.0.1:*) ;; *) fail "warroom is published on '$BIND' (must be 127.0.0.1)";; esac

# There is no authentication, so these are the defences that matter.
echo ">> DNS rebinding: a request whose Host is not this machine is refused"
[ "$(code -H 'Host: evil.example.com' "$URL/")" = 403 ] || fail "foreign Host header was accepted"
[ "$(code "http://127.0.0.1:${PORT}/")" = 200 ]          || fail "127.0.0.1 should be accepted"

echo ">> CSRF: cross-site writes are refused, same-origin and plain API writes work"
FORM='fingerprint=none&label=fp'
[ "$(code -X POST -H 'Sec-Fetch-Site: cross-site' -d "$FORM" "$URL/runs/$RUN_ID/feedback")" = 403 ] || fail "cross-site POST was accepted"
[ "$(code -X POST -H 'Origin: https://evil.example.com' -d "$FORM" "$URL/runs/$RUN_ID/feedback")" = 403 ] || fail "foreign-Origin POST was accepted"
[ "$(code -X POST -H 'Sec-Fetch-Site: cross-site' "$URL/admin/tenants/default/purge")" = 403 ] || fail "cross-site purge was accepted"
[ "$(code -X POST -H 'Sec-Fetch-Site: same-origin' -d "$FORM" "$URL/runs/$RUN_ID/feedback")" != 403 ] || fail "same-origin POST was blocked"

echo "SMOKE OK"
