#!/usr/bin/env bash
#
# Tier-2 end-to-end verification. For each scanner: build its image, run a
# known-vulnerable sample THROUGH Achilles (--runner docker), and assert findings
# surface. This is the test loop the dev laptop lacked (no Docker/JVM/PHP) — it
# runs on any box with Docker (incl. GitHub Actions runners).
#
# Requires: docker, go, python3. No host JVM/PHP — Java is compiled in a container.
# Usage: verify/tier2/verify.sh [findsecbugs] [psalm] [security-code-scan]  (default: all)
set -uo pipefail
cd "$(dirname "$0")/../.."   # repo root
command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 1; }

echo ">> building achilles"
go build -o bin/achilles ./cmd/achilles || { echo "achilles build failed"; exit 1; }

TOOLS="${*:-findsecbugs psalm security-code-scan clang-tidy bandit govulncheck railroader checkov shellcheck syft}"
fail=0

assert() { # <sarif> <name> <expected-substring-or-empty>
  # Match against the whole SARIF (ruleId + message): tools differ — find-sec-bugs
  # uses named rule ids (SQL_INJECTION_JDBC), Psalm uses numeric shortcodes with the
  # detail in the message ("tainted SQL"), so a content search is the robust check.
  local sarif="$1" name="$2" want="${3:-}" n
  if [ ! -f "$sarif" ]; then echo "FAIL[$name]: no SARIF produced at $sarif"; fail=1; return; fi
  n=$(python3 -c "import json;print(len(json.load(open('$sarif'))['runs'][0]['results']))" 2>/dev/null || echo 0)
  if [ "${n:-0}" -lt 1 ]; then echo "FAIL[$name]: expected >=1 finding, got ${n:-0}"; fail=1; return; fi
  if [ -n "$want" ] && ! grep -qi "$want" "$sarif"; then
    echo "FAIL[$name]: $n finding(s) but SARIF contains no '$want'"; fail=1; return
  fi
  echo "PASS[$name]: $n finding(s)"
}

if echo " $TOOLS " | grep -q " findsecbugs "; then
  echo ">> findsecbugs: build image"
  docker build -q -t achilles/findsecbugs:1.14.0 deployments/spotbugs-findsecbugs
  W=$(mktemp -d); cp -R verify/tier2/findsecbugs/sample/. "$W/"
  echo ">> findsecbugs: compile java sample (in a JDK container)"
  docker run --rm -v "$W:/work" -w /work eclipse-temurin:21-jdk javac Vuln.java
  echo ">> findsecbugs: scan via achilles"
  ./bin/achilles --config verify/tier2/findsecbugs.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" findsecbugs "SQL"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " psalm "; then
  echo ">> psalm: build image"
  docker build -q -t achilles/psalm:6.16.1 deployments/psalm
  W=$(mktemp -d); cp -R verify/tier2/psalm/sample/. "$W/"
  echo ">> psalm: scan via achilles"
  ./bin/achilles --config verify/tier2/psalm.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" psalm "SQL"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " security-code-scan "; then
  echo ">> security-code-scan: build image"
  docker build -q -t achilles/security-code-scan:5.6.7 deployments/security-code-scan
  W=$(mktemp -d); cp -R verify/tier2/security-code-scan/sample/. "$W/"
  echo ">> security-code-scan: scan via achilles"
  ./bin/achilles --config verify/tier2/security-code-scan.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" security-code-scan "SCS"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " clang-tidy "; then
  echo ">> clang-tidy: build image"
  docker build -q -t achilles/clang-tidy:18 deployments/clang-tidy
  W=$(mktemp -d); cp -R verify/tier2/clang-tidy/sample/. "$W/"
  echo ">> clang-tidy: scan via achilles"
  ./bin/achilles --config verify/tier2/clang-tidy.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" clang-tidy "cert"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " bandit "; then
  echo ">> bandit: build image"
  docker build -q -t achilles/bandit:1.9.4 deployments/bandit
  W=$(mktemp -d); cp -R verify/tier2/bandit/sample/. "$W/"
  echo ">> bandit: scan via achilles"
  ./bin/achilles --config verify/tier2/bandit.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" bandit "shell"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " govulncheck "; then
  echo ">> govulncheck: build image"
  docker build -q -t achilles/govulncheck:1.6.0 deployments/govulncheck
  W=$(mktemp -d); cp -R verify/tier2/govulncheck/sample/. "$W/"
  # The sample is committed with .txt suffixes so it's invisible to both the root
  # Go module (main.go would otherwise join the parent package graph) and to
  # Dependabot (its go.mod pins a deliberately-vulnerable dep). Restore the real
  # names in the scratch copy before scanning.
  mv "$W/go.mod.txt" "$W/go.mod"; mv "$W/go.sum.txt" "$W/go.sum"; mv "$W/main.go.txt" "$W/main.go"
  echo ">> govulncheck: scan via achilles"
  ./bin/achilles --config verify/tier2/govulncheck.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" govulncheck "GO-2021-0113"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " railroader "; then
  echo ">> railroader: build image"
  docker build -q -t achilles/railroader:4.3.8 deployments/railroader
  W=$(mktemp -d); cp -R verify/tier2/railroader/sample/. "$W/"
  echo ">> railroader: scan via achilles"
  ./bin/achilles --config verify/tier2/railroader.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" railroader "injection"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " checkov "; then
  echo ">> checkov: build image"
  docker build -q -t achilles/checkov:3.3.8 deployments/checkov
  W=$(mktemp -d); cp -R verify/tier2/checkov/sample/. "$W/"
  echo ">> checkov: scan via achilles"
  ./bin/achilles --config verify/tier2/checkov.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" checkov "CKV"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " shellcheck "; then
  echo ">> shellcheck: build image"
  docker build -q -t achilles/shellcheck:0.11.0 deployments/shellcheck
  W=$(mktemp -d); cp -R verify/tier2/shellcheck/sample/. "$W/"
  echo ">> shellcheck: scan via achilles"
  ./bin/achilles --config verify/tier2/shellcheck.yaml --runner docker --sarif-report "$W/out.sarif" "$W" || true
  assert "$W/out.sarif" shellcheck "SC2086"
  rm -rf "$W"
fi

if echo " $TOOLS " | grep -q " syft "; then
  echo ">> syft: build image"
  docker build -q -t achilles/syft:1.46.0 deployments/syft
  W=$(mktemp -d); cp -R verify/tier2/syft/sample/. "$W/"
  # Manifests are committed as .txt so their pinned versions don't trip
  # Dependabot; restore the real names in the scratch copy before scanning.
  mv "$W/go.mod.txt" "$W/go.mod"; mv "$W/package-lock.json.txt" "$W/package-lock.json"
  echo ">> syft: generate SBOM via achilles"
  ./bin/achilles --config verify/tier2/syft.yaml --runner docker --sbom "$W/sbom.json" "$W" || true
  # Syft produces an SBOM artifact (not findings), so assert on component count.
  n=$(python3 -c "import json;print(len(json.load(open('$W/sbom.json')).get('components',[])))" 2>/dev/null || echo 0)
  if [ "${n:-0}" -ge 1 ]; then echo "PASS[syft]: $n component(s)"; else echo "FAIL[syft]: SBOM has no components"; fail=1; fi
  rm -rf "$W"
fi

echo "----"
if [ "$fail" -eq 0 ]; then echo "TIER-2 VERIFY: PASS"; else echo "TIER-2 VERIFY: FAIL"; fi
exit "$fail"
