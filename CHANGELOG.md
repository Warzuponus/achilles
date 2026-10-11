# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release (`v0.1.0`) is pending.

### Added
- **One-flag AI scan:** `--ai` turns on triage, fix suggestions, the repo review and
  the dependency advisor, and writes `report.html`, `report.md` and `achilles.sarif`
  into `--report-dir`.
- **LLM provider presets** (`--llm-provider openai|openrouter|ollama|anthropic`) and a
  pre-scan check of the LLM setup: missing key, a key sent to the wrong provider, an
  API key over plain http, or a missing model all fail before any scanning.
- **AI verdicts now change the result.** A confident false positive is moved out of the
  gate, the counts and the issues, and listed in its own report section (and as a
  suppressed SARIF result). `--keep-dismissed` restores the old behavior.
- **Honest reports:** every report states whether the scan was complete (failed scanners
  are named, including in the HTML report and SARIF) and how many findings the AI review
  covered.
- **Privacy controls for LLM calls:** credentials are masked in prompts, credential
  findings are never sent to the model or dismissed by it, `--llm-no-code` sends no
  source, and the destination host is printed before any code leaves the machine.
- **Prompt-injection hardening:** every prompt tells the model the code under review is
  untrusted data (`triage/v3`).
- **Standalone binary:** the tool registry and baseline rules are embedded, so
  `achilles` runs from any directory. New `--version`, `achilles doctor` and
  `achilles tools install|list` (hash-pinned scanner downloads, fail-closed on a
  mismatch), plus an optional community Opengrep ruleset.
- **Release automation:** goreleaser config, a tag-triggered release workflow with
  signed checksums, and `scripts/install.sh`.
- **Hardened GitHub issue filing** (`internal/issues`): severity threshold, per-run cap,
  grouping modes, dry run, de-duplication across runs, reopen-on-regression, closing of
  resolved or AI-dismissed findings, fix suggestions in the body, secret redaction, and a
  refusal to publish vulnerability details in a public repository without
  `--allow-public-issues`.
- **GitHub Action rewritten:** downloads the release binary instead of compiling,
  inputs for the LLM key, provider, model, issues and report upload, a job summary, and
  a three-line example workflow.
- Issue and pull-request templates, `NOTICE`, and this changelog.

- **Verify fixes by re-scan** (`--verify-fixes`, on by default with `--remediate`): each
  proposed patch is applied to a temp copy and the scanner that reported the finding is
  re-run. `--fix-pr` applies only verified patches; reports and issues show the status.
- **Deep verification** (`--deep-verify N`, `--deep-max-steps`): a bounded, read-only,
  secrets-blocked tool loop that lets the model read and search the repository to settle
  findings a single-file review could not. It can confirm freely but can only support a
  dismissal with cited evidence, and never overrides a confident true positive.
- **Gate-structured verdicts** (`triage/v4`): the model answers designed-behavior,
  reachable, attacker-controlled, sanitized and new-capability separately; comments and
  names are treated as claims, not evidence. Entry-point hints (routes, handlers, CLI
  args) from the finding's own file are added to the prompt.
- **Self-consistency sampling** (`--llm-samples`): borderline verdicts are re-asked and
  the majority wins; a split is `uncertain` and is never dismissed.

- **Detection benchmark** (`achilles-eval --mode detect`, `make eval-detect`): scans
  ground-truth corpora and scores recall by vulnerability class, tracing every miss to where
  it was lost (not detected, tool missing, noise filter, dismissed by the AI review, and so
  on). A committed hermetic fixture baseline gates regressions. See
  [Benchmarking Detection](docs/benchmarking.md).

### Changed
- `--timeout` bounds the scanners only; the AI phases have their own `--llm-budget`
  (default 45m) and run `--llm-concurrency` findings in parallel, most severe first.
- A rejected key or exhausted credits now stops the run immediately instead of failing
  every finding in turn.
- Finding paths are repo-relative whatever scanner reported them (Opengrep reported
  absolute paths).
- The action defaults to `mode: oss`, matching the CLI.
- `--config` defaults to the embedded registry instead of `configs/tools.yaml` in the
  current directory.

### Changed (toolchain)
- Built and tested with Go 1.27 (`go 1.27`, `toolchain go1.27.1`): `go.mod`, every workflow, the
  action, and the container base images (digest-pinned) move together. Building from source now
  needs Go 1.27; release binaries and the images are unaffected for users.

### Removed
- The `Docs to Pages` workflow. The guides remain in `docs/`, and `make docs-html` still builds
  the single-page `docs/site.html`.

### Fixed
- **The AI review could rule out a known CVE.** Dependency findings (osv-scanner,
  govulncheck, Trivy vulnerabilities) went through the same prompt as code findings,
  with a lockfile line or nothing at all as "code context", and a confident false
  positive took them out of the gate. They are no longer sent to the model (which also
  removes two paid calls per CVE), never receive or inherit a verdict, are skipped by
  `--deep-verify` and `--calibrate`, and can never be dismissed. Reports count them
  separately.
- **Trivy never ran its IaC / misconfiguration checks.** It was invoked as plain
  `trivy fs`, which runs only the vulnerability and secret scanners. The registry now
  passes `--scanners vuln,misconfig,secret`, and gives Trivy network access under
  `--runner docker`, where it previously could not download its database and always
  failed.
- **`--fail-on critical` could never fire, and a typo failed everything.** No scanner
  result was ever mapped to `critical`: only the SARIF level was read, and the
  `security-severity` score that Trivy and others publish was ignored, so a CVSS 9.8 was
  reported as high. Scores are now read (9.0+ critical, 7.0+ high, 4.0+ medium), taking
  the more severe of level and score. A result with no level at all was `unknown`, which
  no threshold matches, so Gitleaks findings could not fail a gate; they are now high,
  and other level-less results get the SARIF default (medium). `--fail-on` rejects a
  value that is not a severity instead of treating it as "below everything".
- **Three `fp` labels could silence a rule forever.** Feedback-driven calibration ran on
  every triage, ruled out all future findings of a rule after three false-positive labels
  at 80%, never expired, and applied at any severity, with no model looking at the code.
  It is now opt-in (`--calibrate`), needs ten distinct labeled findings at 90%, ignores
  labels older than 180 days, never applies above medium severity or to credential
  findings, counts each finding once by its latest label, and says in the run log and in
  every report how many verdicts came from feedback instead of a review.
- **The adversarial judge could silently drop real findings.** Two cases: a verdict of
  `uncertain` that the judge "refuted" was ruled out even when the judge was arguing the
  finding is real, and any true positive was ruled out on the judge's bare yes/no. Now
  (`triage/v5`) a refuted `uncertain` verdict is never ruled out, and a true positive is
  ruled out only when the judge states a confidence of at least 0.7, quotes context that
  Achilles verifies it actually sent, and the triage pass was below 0.9. Anything less is
  reported as **disputed by judge** and stays in the gate. Model-reported confidences are
  normalized to 0..1 (a reply of `85` is 0.85, not "above every threshold").
- Opengrep under `--runner docker` asked Docker for an empty image; it now runs as the
  local binary, as documented.
- Opengrep crashed under a non-UTF-8 locale when reading non-ASCII community rules.
- Release binaries reported a "-dirty" commit: goreleaser's untracked `dist/` made Go stamp
  the build as modified. A commit injected by the release process is now trusted, and
  `/dist/` is git-ignored.
- The full container image build ran the runner out of disk; the workflow now frees space first.
- osv-scanner exiting with "No package sources found" (a tree with no dependency
  manifests) was reported as a failed tool, marking every such scan "incomplete" and
  failing it under `--strict-tools`. It is now an empty result (`nothingToScan` in the
  tool registry).
- Documentation referred to a release tag and install paths that did not exist.
