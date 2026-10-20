#!/usr/bin/env bash
# Scores Achilles and other open-source SAST tools on the OWASP Benchmark (Java
# and Python) with the same scorer: achilles-eval --mode owasp. Every number in
# docs/comparison.md comes from this script. Run it from the repository root:
#
#   bash evals/compare/run.sh            # all tools, both benchmarks
#   TOOLS="semgrep bandit" bash evals/compare/run.sh
#
# What it needs on PATH is listed in docs/comparison.md ("Reproduce"). A tool
# that is missing is reported as skipped, never scored.
set -euo pipefail

WORK=${WORK:-.achilles/compare}
TOOLS=${TOOLS:-"achilles-own achilles-oss semgrep bearer findsecbugs bandit"}
BENCH_JAVA=bc5ffeb09fb18ab039806d84ca1f718c2e332c54
BENCH_PY=f1291485808b66e20ddb6b01b10dc71b3df8c8ba
SEMGREP_RULES=17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9
BEARER_RULES=v0.48.4
HERE=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$WORK/out"
WORK=$(cd "$WORK" && pwd)
OUT=$WORK/out

clone() { # dir url commit-or-tag
	[ "$(cat "$WORK/$1.at" 2>/dev/null)" = "$3" ] && return
	rm -rf "${WORK:?}/$1"
	git init -q "$WORK/$1"
	git -C "$WORK/$1" fetch -q --depth 1 "$2" "$3"
	git -C "$WORK/$1" checkout -q FETCH_HEAD
	echo "$3" >"$WORK/$1.at"
}
clone BenchmarkJava https://github.com/OWASP-Benchmark/BenchmarkJava "$BENCH_JAVA"
clone BenchmarkPython https://github.com/OWASP-Benchmark/BenchmarkPython "$BENCH_PY"
JAVA_SRC=$WORK/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode
PY_SRC=$WORK/BenchmarkPython/testcode

go build -o "$WORK/achilles" ./cmd/achilles
go build -o "$WORK/achilles-eval" ./cmd/achilles-eval
printf 'mode: commercial\n' >"$WORK/own.yaml"
printf 'mode: oss\n' >"$WORK/oss.yaml"

SUMMARY=$OUT/summary.tsv
printf 'benchmark\ttool\trecall\tdecoys_flagged\tprecision\tscore\tseconds\n' >"$SUMMARY"

has() { command -v "$1" >/dev/null 2>&1; }
skip() { echo "== $1 on $2: skipped ($3)" >&2; printf '%s\t%s\tskipped: %s\t\t\t\t\n' "$2" "$1" "$3" >>"$SUMMARY"; }

# timed CMD...: runs CMD and puts its wall-clock seconds in $SECS.
timed() {
	local start end
	start=$(date +%s.%N)
	"$@"
	end=$(date +%s.%N)
	SECS=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.0f", b-a}')
}

# owasp TOOL BENCH DIR [SARIF]: scores SARIF, or with none runs Achilles itself
# (ACHILLES_SETTINGS picks the mode). Writes $OUT/BENCH-TOOL.{txt,json}.
owasp() {
	local tool=$1 bench=$2 dir=$3 sarif=${4:-}
	if [ -n "$sarif" ]; then
		"$WORK/achilles-eval" --mode owasp --owasp-dir "$dir" --owasp-sarif "$sarif" \
			--out "$OUT/$bench-$tool.json" >"$OUT/$bench-$tool.txt"
	else
		"$WORK/achilles-eval" --mode owasp --owasp-dir "$dir" --achilles-bin "$WORK/achilles" \
			--out "$OUT/$bench-$tool.json" >"$OUT/$bench-$tool.txt"
	fi
}

# row TOOL BENCH: appends the averages and $SECS to the summary.
row() {
	jq -r --arg t "$1" --arg b "$2" --arg s "$SECS" \
		'[$b, $t, (.StrictTPR*10|round/10), (.StrictFPR*10|round/10), (.StrictPrecision*10|round/10), (.StrictScore*10|round/10), $s] | @tsv' \
		"$OUT/$2-$1.json" >>"$SUMMARY"
	echo "== $1 on $2: $(tail -n1 "$SUMMARY" | cut -f3- | tr '\t' ' ')" >&2
}

for tool in $TOOLS; do
	case $tool in
	achilles-own | achilles-oss)
		cfg=$WORK/own.yaml
		[ "$tool" = achilles-oss ] && cfg=$WORK/oss.yaml
		for b in java python; do
			dir=$WORK/BenchmarkJava
			[ $b = python ] && dir=$WORK/BenchmarkPython
			# The scan runs inside achilles-eval, so the time includes scoring (well under a second).
			ACHILLES_SETTINGS=$cfg timed owasp "$tool" $b "$dir" 2>"$OUT/$b-$tool.log"
			row "$tool" $b
		done
		;;
	semgrep)
		if ! has semgrep; then skip semgrep both "semgrep not on PATH"; continue; fi
		clone semgrep-rules https://github.com/semgrep/semgrep-rules "$SEMGREP_RULES"
		for b in java python; do
			src=$JAVA_SRC dir=$WORK/BenchmarkJava
			[ $b = python ] && src=$PY_SRC dir=$WORK/BenchmarkPython
			timed semgrep scan --quiet --metrics=off --disable-version-check \
				--config "$WORK/semgrep-rules/$b" --sarif -o "$OUT/$b-semgrep.sarif" "$src"
			owasp semgrep $b "$dir" "$OUT/$b-semgrep.sarif"
			row semgrep $b
		done
		;;
	bearer)
		if ! has bearer; then skip bearer both "bearer not on PATH"; continue; fi
		clone bearer-rules https://github.com/Bearer/bearer-rules "$BEARER_RULES"
		for b in java python; do
			src=$JAVA_SRC dir=$WORK/BenchmarkJava
			[ $b = python ] && src=$PY_SRC dir=$WORK/BenchmarkPython
			timed bearer scan "$src" --quiet --disable-version-check --force \
				--disable-default-rules --external-rule-dir "$WORK/bearer-rules/rules" \
				--format json --output "$OUT/$b-bearer-raw.json" || true # exits 1 on findings
			jq -f "$HERE/bearer.jq" "$OUT/$b-bearer-raw.json" >"$OUT/$b-bearer.sarif"
			owasp bearer $b "$dir" "$OUT/$b-bearer.sarif"
			row bearer $b
		done
		;;
	findsecbugs)
		if ! has findsecbugs.sh; then skip findsecbugs java "findsecbugs.sh not on PATH"; continue; fi
		if ! has mvn; then skip findsecbugs java "mvn not on PATH (it scans compiled classes)"; continue; fi
		(cd "$WORK/BenchmarkJava" && mvn -q -B -Dspotless.skip=true compile &&
			mvn -q -B dependency:build-classpath -Dmdep.outputFile="$WORK/java-classpath.txt") >/dev/null
		timed findsecbugs.sh -effort:max -auxclasspath "$(cat "$WORK/java-classpath.txt")" \
			-sarif="$OUT/java-findsecbugs.sarif" "$WORK/BenchmarkJava/target/classes/org/owasp/benchmark/testcode" 2>/dev/null
		owasp findsecbugs java "$WORK/BenchmarkJava" "$OUT/java-findsecbugs.sarif"
		row findsecbugs java
		;;
	bandit)
		if ! has bandit; then skip bandit python "bandit not on PATH"; continue; fi
		timed bandit -q -r "$PY_SRC" -f json -o "$OUT/python-bandit-raw.json" || true # exits 1 on findings
		jq -f "$HERE/bandit.jq" "$OUT/python-bandit-raw.json" >"$OUT/python-bandit.sarif"
		owasp bandit python "$WORK/BenchmarkPython" "$OUT/python-bandit.sarif"
		row bandit python
		;;
	*) echo "unknown tool $tool" >&2; exit 2 ;;
	esac
done

echo
if has column; then column -t -s $'\t' "$SUMMARY"; else cat "$SUMMARY"; fi
echo
echo "Per-category scorecards: $OUT/<benchmark>-<tool>.txt"
