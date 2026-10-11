# Reports & Gating

How to get the output you want, and how to fail a build on the *right* findings.

## Output formats

Achilles prints a human report to stdout by default. Add any of these to also
write a file (they compose — ask for several at once):

| Flag | Format | Best for |
|------|--------|----------|
| `--html-report f.html` | self-contained HTML | humans — open in a browser; findings + AI review, upgrade advice, and threat model in one page |
| `--sarif-report f.sarif` | SARIF 2.1.0 | GitHub code scanning, other SARIF consumers |
| `--junit f.xml` | JUnit XML | CI test panels |
| `--markdown f.md` | Markdown table | pasting into a PR/issue |
| `--github` | Actions annotations | inline `::error`/`::warning` in a workflow log |
| `--sbom f.json` | CycloneDX SBOM | supply-chain inventory (via Syft; independent of findings) |
| `--diagnostics f.json` | JSON sidecar | debugging coverage — which tools failed to run/parse, LLM token usage |

Every report says whether the scan was **complete** (a banner names any scanner that
failed to run) and how much of it the AI review **covered**. Findings the AI
confirmed are listed first within each severity. The **HTML report** is the showcase: it folds in the LLM agents' output when they
ran (systemic-risk review, dependency upgrade plan, STRIDE threat model) plus each
finding's triage verdict and suggested fix. See [LLM Triage & Agents](llm-and-agents.md).

```bash
achilles --html-report report.html --sarif-report achilles.sarif .
```

## Gating: fail on severity

By default Achilles exits 0 (report-only). Make it gate with `--fail-on`:

```bash
achilles --fail-on high .     # exit 1 if any surviving finding is >= high
```

Severity order: `critical > high > medium > low`. The gate runs *after* all
filtering below, so it only ever considers findings you didn't suppress.

### The gate and the AI review

With `--triage` (or `--ai`), a finding the AI review is **confident is a false
positive** (confidence at least 0.7, and the adversarial second pass did not
overturn it) is moved out of the gate, out of the issues Achilles files, and out of
the headline counts. It is not hidden: every report lists these findings in their own
section ("Ruled out by the AI review", with the model's reason), and SARIF carries
them as *suppressed* results so code scanning shows them as dismissed. These are
never dismissed: uncertain or low-confidence verdicts, verdicts the judge overturned,
findings about credentials (the model never sees those), and anything the review did
not reach.

A true positive the judge *refuted* is ruled out only when the judge backed the
refutation (a stated confidence of at least 0.7 and a quote that really appears in the
code it was shown) and the first pass was not itself sure (below 0.9). A refutation
that falls short is shown as **disputed by judge**: the finding stays in the gate and
in the issues, because two reviews disagreeing is a reason for a person to look, not a
reason to drop it.

```bash
achilles --ai --fail-on high .                  # gate on what survived the AI review
achilles --ai --keep-dismissed --fail-on high . # gate on raw scanner severity instead
```

Use `--keep-dismissed` when the code's authors are not trusted: a hostile repository
can try to talk the model into dismissing a real finding (see
[SECURITY.md](../SECURITY.md)). Every report states how many findings the AI
review covered, so a partial review is visible.

### One other thing fails the run

Independent of `--fail-on`: if **Evidence Vault writes fail**, the run exits
non-zero even when no finding would have gated it. The vault is the audit trail,
so a scan whose evidence didn't persist must not look like a clean pass. You get
the failure count and the first cause (e.g. a database permission error), and the
check runs *before* the severity gate so an outage can't hide behind a passing
gate. The report and other outputs are still produced.

## Cutting noise so the gate is useful

A gate on *every* finding fails forever on legacy debt. Three tools narrow it to
what matters — they stack.

### 1. Noise filter (on by default)

Vendored / generated / minified files are dropped before findings are counted.
Add your own patterns or turn it off:

```bash
achilles --exclude 'tests,*.gen.go' .     # extra patterns (path segment or glob)
achilles --no-default-excludes .          # disable the built-in filter
```

Note: test code is **not** excluded by default — real issues live in tests too.

### 2. Baselines: only new findings

A baseline is a file of finding fingerprints to suppress. Seed it once, commit it,
then future scans only surface (and gate on) findings not in it.

```bash
achilles --write-baseline .achilles/baseline.json .   # seed from the current state
git add .achilles/baseline.json && git commit -m "seed achilles baseline"

# later runs: pre-existing findings are suppressed, new ones surface
achilles --baseline .achilles/baseline.json --fail-on high .
```

Findings are classified **introduced / pre-existing / fixed** against the baseline,
so you can see churn. When a finding is legitimately a false-positive-in-context,
regenerate the baseline to accept it (this is exactly how Achilles scans itself —
see `.achilles/baseline.json`).

### 3. Diff-aware: only changed files

On a PR, scan only files changed vs the base branch:

```bash
achilles --diff origin/main --fail-on high .
```

Combine with a baseline for the strictest, quietest gate — new findings, in
changed files, at/above your severity floor:

```bash
achilles --diff origin/main --baseline .achilles/baseline.json --fail-on high .
```

### `--pr-mini`: baseline autopilot

If you don't want to manage a baseline file by hand, `--pr-mini` does it: if the
file is absent it seeds it (full scan, no gate); if present it delta-scans and
gates on what's new. It's mutually exclusive with `--baseline`/`--write-baseline`.

```bash
achilles --pr-mini .achilles/pr-baseline.json --fail-on high .
```

## Recommended CI gate

```bash
achilles \
  --diff origin/${BASE_BRANCH} \
  --baseline .achilles/baseline.json \
  --sarif-report achilles.sarif \
  --github \
  --fail-on high \
  .
```

Diff + baseline keep the signal high; `--sarif-report` feeds the Security tab;
`--github` annotates the diff; `--fail-on high` blocks the merge. Wire it up in
[CI & the Scan Hub](ci-and-hub.md).
