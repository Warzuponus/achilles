#!/bin/sh
# check-live-scan.sh SCAN_JSON: fails unless an --ai scan's JSON report shows the
# model triaged findings with no triage errors and the review finished. Used by
# .github/workflows/live-anthropic.yml.
set -eu
f="$1"
[ -s "$f" ] || { echo "no report at $f"; exit 1; }
jq -e '.triage != null' "$f" >/dev/null || { echo "no triage section: the AI review did not run"; exit 1; }
jq '{complete, model: .triage.model, triage: .triage, findings: (.findings | length),
     verdicts: [.findings[] | select(.verdict != null) | .verdict.classification] | group_by(.) | map({(.[0]): length}) | add}' "$f"
jq -e '.triage.triaged > 0' "$f" >/dev/null || { echo "no finding got a verdict"; exit 1; }
jq -e '.triage.failed == 0' "$f" >/dev/null || { echo "triage errored on some findings"; exit 1; }
jq -e '(.triage.aborted // "") == ""' "$f" >/dev/null || { echo "the AI review stopped early"; exit 1; }
