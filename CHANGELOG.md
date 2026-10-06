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

### Fixed
- Opengrep under `--runner docker` asked Docker for an empty image; it now runs as the
  local binary, as documented.
- Opengrep crashed under a non-UTF-8 locale when reading non-ASCII community rules.
- osv-scanner exiting with "No package sources found" (a tree with no dependency
  manifests) was reported as a failed tool, marking every such scan "incomplete" and
  failing it under `--strict-tools`. It is now an empty result (`nothingToScan` in the
  tool registry).
- Documentation referred to a release tag and install paths that did not exist.
