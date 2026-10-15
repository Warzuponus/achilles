# Reports & Gating

How to get the output you want, and how to fail a build on the *right* findings.

## Output formats

Achilles prints a human report to stdout by default. Add any of these to also
write a file (they compose — ask for several at once):

| Flag | Format | Best for |
|------|--------|----------|
| `--html-report f.html` | self-contained HTML | humans — open in a browser; findings + AI review, upgrade advice, and threat model in one page |
| `--sarif-report f.sarif` | SARIF 2.1.0 | GitHub code scanning, other SARIF consumers |
| `--json-report f.json` | JSON | scripts and dashboards: the whole scan in Achilles' own shape, with a `schemaVersion` and a `complete` flag |
| `--gitlab-sast f.json`, `--gitlab-secret-detection f.json` | GitLab security reports | GitLab's security widget and vulnerability report (see [GitLab CI](ci-and-hub.md#gitlab-ci)) |
| `--gitlab-code-quality f.json` | GitLab Code Quality | findings in the merge request widget on every GitLab tier |
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

Severity order: `critical > high > medium > low > info`. The gate runs *after* all
filtering below, so it only ever considers findings you didn't suppress. A value that
is not one of those five is an error (exit 2), not a threshold.

Exit codes: **0** the scan ran and nothing met the threshold (or no `--fail-on` was
given); **1** a finding met the `--fail-on` threshold; **2** anything else, including a
bad flag, a failed vault write, `--strict-tools` with a failed scanner, and an
interrupted run. Ctrl-C (or SIGTERM) stops the scanners and any model calls, removes
temporary files, and exits 2 without writing a report; a second Ctrl-C ends the
process immediately.

**Where severity comes from.** Each scanner reports a SARIF level (`error`, `warning`,
`note`) and some also report a CVSS-style `security-severity` score. Achilles takes
the more severe of the two: `error` is high, `warning` medium, `note` low, and a score
of 9.0 or more is **critical**, 7.0 high, 4.0 medium, anything above 0 low. So
`critical` comes from scanners that publish scores (Trivy and osv-scanner for
dependency CVEs, some rule packs); a tool that only reports levels tops out at high.
A result with no level and no score is medium (the SARIF default), except a credential
finding, which is high: Gitleaks states no severity, and a leaked secret has to be
able to fail a gate.

### The gate and the AI review

With `--triage` (or `--ai`), a finding the AI review is **confident is a false
positive** (confidence at least 0.7, and the adversarial second pass did not
overturn it) is moved out of the gate, out of the issues Achilles files, and out of
the headline counts. It is not hidden: every report lists these findings in their own
section ("Ruled out by the AI review", with the model's reason), and SARIF carries
them as *suppressed* results so code scanning shows them as dismissed. These are
never dismissed: uncertain or low-confidence verdicts, verdicts the judge overturned,
findings about credentials (the model never sees those), dependency advisories (see
below), and anything the review did not reach.

**Dependency advisories are not reviewed by the model.** A finding that is a known
vulnerability in a dependency (anything from osv-scanner or govulncheck, and any
finding whose rule is a CVE / GHSA / GO / PYSEC / RUSTSEC id, which is how Trivy
reports a vulnerable package) points at a manifest or lockfile, not at code. The AI
review has nothing to read there, so these findings are never sent to it, never get a
verdict, and are never ruled out. They stay in the gate exactly as the scanner
reported them and are fixed by upgrading; `--sca-advice` plans the upgrades. Reports
say how many there were, separately from findings the review failed to reach.

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

Vendored / generated / minified files are dropped before findings are counted:
vendored directories (`vendor`, `node_modules`, `third_party`, ...), minified assets,
`*.pb.go` and `*_pb2.py`, and any file whose header says a tool wrote it (Go's
`// Code generated ... DO NOT EDIT.` line, or an `@generated` marker in a comment near
the top). That header is the scanned repository's say-so, so it never hides a
credential, a dependency advisory or a finding in commit history, and
`--no-repo-config` ignores it. Add your own patterns or turn it off:

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

A committed baseline can be edited by a pull request, which could add a finding and
its fingerprint together. With `--diff`, Achilles warns on stderr and at the top of
every report when the commits under review change the baseline file, so treat that
warning as part of the review.

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

### Suppressing one finding in the code

When a finding has been looked at and is fine where it is, say so beside it:

```python
subprocess.run(cmd, shell=True)  # achilles:ignore B602 -- cmd comes from a fixed table in build.py
```

```go
// achilles:ignore gosec:G204 -- bin is checked against an allowlist in resolveTool
out, err := exec.Command(bin, args...).Output()
```

The comment names the rule (or several, separated by commas) and gives a reason after
` -- `. It applies to a finding on its own line, or on the line directly below when
the comment stands alone. A rule can be written as its id (`G204`), with its tool
(`gosec:G204`), or as the last part of a long dotted id (`dangerous-system-call`, or `template-injection` for `zizmor/template-injection`).

What happens to a suppressed finding:

- It does not gate, is not sent to the model, and files no issue. An open issue for
  it is closed with a comment that quotes the reason and says it was not fixed.
- It is **not hidden**. Every report lists suppressed findings with their reasons, the
  scan prints how many there were, and SARIF marks them as suppressed in source.
- With `--diff`, a suppression on a line the change itself added or edited is flagged
  on stderr and at the top of every report, the same way a change to a scanner's
  ignore file is. The change is suppressing a finding in itself; read the reason.
- With `--no-repo-config` no suppression comment is honoured.

What a comment cannot do:

- Suppress without saying why, or without naming the rule. Such a comment is not
  honoured, and the scan says where it is. There is no "ignore everything here".
- Suppress a credential finding, a dependency advisory, or a finding from the git
  history. Use the scanner's own allowlist for a test fixture that looks like a
  secret; an advisory is resolved by upgrading.
- Suppress a different rule that fires on the same line. Each rule is named.

Scanners have their own inline comments too (`#nosec`, `nosemgrep`, `gitleaks:allow`).
Those remove the finding before Achilles sees it, so they are not reported; prefer
`achilles:ignore` where you want the suppression to stay visible.

### Credentials in the git history

A scan reads the files as they are now. A credential that was committed and deleted a
commit later is in none of them, so it is not reported, but it is in every clone and
fork of the repository and has to be treated as leaked. `--secrets-history` scans the
commits as well:

```bash
achilles --secrets-history --fail-on high .             # every commit on every fetched branch
achilles --secrets-history --diff origin/main --fail-on high .   # only the commits since main
```

- A finding from the history names the commit that added the credential and says what
  deleting the line does not fix: the credential must be revoked and replaced. Its
  location is the file and line in that commit, which may no longer exist.
- A credential that is still in a file is reported once, as the finding in the file. One
  that appears in several commits is reported once, for the earliest.
- With `--diff`, only the commits since that ref are read, and a finding in them is kept
  even when the net diff no longer contains the file. That is the case this exists for
  on a pull request: a secret added in one commit and removed in the next.
- **It needs the whole history.** CI checkouts are shallow by default, and a shallow
  clone holds only the newest commits. Achilles then reports the history scan as
  incomplete instead of clean; fetch everything (`fetch-depth: 0` for
  `actions/checkout`, `GIT_DEPTH: "0"` in GitLab CI). Scan the repository root: the
  history covers the whole repository whatever directory is given.
- If git cannot read the checkout at all (not a repository, or one owned by another
  user, which is common for a directory mounted into a container), the history scan is
  reported as a failed tool. Inside a container, mark the mount as safe first:
  `git config --global --add safe.directory /src`.
- The repository's own `.gitleaks.toml` and `.gitleaksignore` apply, and are named, as
  for the scan of the files.

It is off by default because it reads every commit. A repository can turn it on for
itself with `secrets-history: true` in `.achilles.yaml`.

### `--pr-mini`: baseline autopilot

If you don't want to manage a baseline file by hand, `--pr-mini` does it: if the
file is absent it seeds it (full scan, no gate); if present it delta-scans and
gates on what's new. It's mutually exclusive with `--baseline`/`--write-baseline`.

```bash
achilles --pr-mini .achilles/pr-baseline.json --fail-on high .
```

### Keeping these choices in the repository

Exclusions, the baseline path and the gate can live in `.achilles.yaml` at the
repository root instead of in every command line and workflow:

```yaml
exclude: [testdata, "*.pb.go"]
baseline: .achilles/baseline.json
fail-on: high
```

A flag on the command line still wins. The file can only shape the scan, and its use
is always reported; see [Settings files](cli-reference.md#settings-files).

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
