#!/usr/bin/env bash
# Prints the tables in docs/comparison.md from the output of run.sh:
#   bash evals/compare/tables.sh [.achilles/compare/out]
set -euo pipefail
OUT=${1:-.achilles/compare/out}

echo "### Summary"
echo
echo "| Benchmark | Tool | Recall | Decoys flagged | Precision | Score | Score, related CWEs | Seconds |"
echo "|---|---|---|---|---|---|---|---|"
tail -n +2 "$OUT/summary.tsv" | while IFS=$'\t' read -r b t rec dec prec score secs; do
	rel=""
	[ -f "$OUT/$b-$t.json" ] && rel=$(jq '.RelatedScore*10|round/10' "$OUT/$b-$t.json")
	echo "| $b | $t | $rec | $dec | $prec | **$score** | $rel | $secs |"
done

for b in java python; do
	files=()
	for f in "$OUT/$b"-*.json; do
		case $f in *-raw.json) continue ;; esac # a tool's own report, not a score
		files+=("$f")
	done
	[ ${#files[@]} -gt 0 ] || continue
	echo
	echo "### Score per category, $b"
	echo
	header="| Category |"
	sep="|---|"
	for f in "${files[@]}"; do
		t=${f##*/$b-}
		header+=" ${t%.json} |"
		sep+="---|"
	done
	echo "$header"
	echo "$sep"
	jq -rs '
		. as $runs
		| ($runs[0].strict | length) as $n
		| range(0; $n) as $i
		| "| \($runs[0].strict[$i].category)/\($runs[0].strict[$i].cwe) | "
		  + ([ $runs[] | .strict[$i].score | (.*10|round/10) | tostring ] | join(" | ")) + " |"' "${files[@]}"
done
