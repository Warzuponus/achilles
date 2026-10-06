# CLI Reference

Every `achilles` flag, grouped by task. (For `achilles-fleet`, see [Fleet](fleet.md).)

> **Flags before the target.** `achilles [flags] <target-path>`. Go's stdlib
> `flag` stops at the first positional, so a flag after the path is ignored.
> The target defaults to `.` if omitted.

## Subcommands

These run instead of a scan. (A scan target literally named `version`, `doctor` or
`tools` must be written `./version` etc.)

| Command | What it does |
|---------|--------------|
| `achilles version` | same as `--version` |
| `achilles doctor` | per default-profile scanner: where it was found (`~/.achilles/bin` first, then `PATH`), its version vs the pinned one, `ok`/`missing`/`outdated`/`no-asset`, and the exact fix command; also whether `go` (needed by gosec) and Docker are available, whether an LLM key is set (`set`/`not set` only — the key is never printed) and the resolved base URL, and whether the community rules are installed. Exits non-zero (2) if a required scanner is missing. |
| `achilles tools list` | pinned versions, whether upstream publishes a download for this platform, and what is installed |
| `achilles tools install [--force] [name...]` | download, sha256-verify (fail closed) and install pinned scanners into `$ACHILLES_HOME/bin` (default `~/.achilles/bin`). Names: `opengrep gosec osv-scanner trivy gitleaks rules`. No names = all five plus the community rules. Skips tools already at the pinned version unless `--force`. |
| `achilles tools doctor` | same as `achilles doctor` |

## Scan setup

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(embedded `configs/tools.yaml`)* | tool registry file; empty uses the registry built into the binary |
| `--profile` | `default` | `default` (baseline tools) or `full` (adds heavy per-language tools) |
| `--mode` | `oss` | license mode: `oss` or `commercial` (strict — refuses non-`commercialSafe` tools) |
| `--attest` | — | comma-separated tool IDs you hold a license attestation for (satisfies the gate in `commercial`) |
| `--runner` | `local` | run tools `local` (PATH) or `docker` (pinned images) |
| `--timeout` | `5m` | overall scan timeout |
| `--version` | — | print version, commit, build date, Go version and platform, then exit |
| `--from-sarif` | — | skip scanning; normalize an existing SARIF file (exercises the report spine) |
| `--sarif-out` | — | also write each tool's raw SARIF into this directory |

## Evidence Vault

| Flag | Default | Description |
|------|---------|-------------|
| `--vault` | `.achilles/vault.jsonl` | vault path (file backend) |
| `--vault-backend` | `file` | `file` or `postgres`. `postgres` reads its connection string from `$ACHILLES_VAULT_DSN` (env only — never a flag, it holds a password) |
| `--vault-tenant` | `default` | the **project** these results belong to (a namespace for grouping the repos you scan). The postgres backend stores it under the key `tenant-<id>`, which is what the War Room reads |

## Noise, baselines & diff-aware scanning

| Flag | Default | Description |
|------|---------|-------------|
| `--exclude` | — | extra noise patterns, comma-separated (path segment like `tests`, or glob like `*.gen.go`) |
| `--no-default-excludes` | `false` | disable the built-in vendored/generated/minified filter |
| `--no-correlate` | `false` | disable cross-tool correlation (triage every duplicate report separately) |
| `--dry-run` | `false` | scan, print the LLM cost estimate, stop before any model call or outward action |
| `--max-cost` | `0` | refuse to start LLM work above this estimated USD spend (needs `--price-config`) |
| `--price-config` | — | YAML per-model token prices (see `configs/prices.example.yaml`) |
| `--baseline` | — | suppress findings whose fingerprint is in this baseline file |
| `--write-baseline` | — | write current findings' fingerprints as a baseline to this file |
| `--diff` | — | keep only findings in files changed vs this git ref (e.g. `origin/main`) |
| `--pr-mini` | — | auto-baseline: seed the file if absent (no gate), else delta-scan against it |

See [Reports & Gating](reports-and-gating.md) for how these combine.

## Gating

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on` | — | exit non-zero if a finding at/above this severity survives filtering: `critical\|high\|medium\|low` |

## LLM triage & agents

Needs `--llm-model` and an API key in `ACHILLES_LLM_API_KEY` (or `OPENAI_API_KEY`).

| Flag | Default | Description |
|------|---------|-------------|
| `--ai` | `false` | one-flag AI scan: `--triage --remediate --review --sca-advice`, and write `report.html`, `report.md`, `achilles.sarif` into `--report-dir` |
| `--report-dir` | `achilles-report` | where `--ai` writes its reports (an explicit `--html-report`/`--markdown`/`--sarif-report` wins) |
| `--llm-provider` | `$ACHILLES_LLM_PROVIDER` | endpoint preset: `openai`, `openrouter`, `ollama`, `anthropic` (experimental). Sets `--llm-base-url`; `ollama` also sets `--llm-auth none` |
| `--llm-budget` | `45m` | time allowed for all AI phases combined (separate from `--timeout`, which bounds the scanners) |
| `--llm-concurrency` | `4` | findings triaged in parallel, most severe first |
| `--llm-no-code` | `false` | privacy mode: send the model only rule, message and location, never source. The AI then never dismisses findings |
| `--keep-dismissed` | `false` | keep findings the AI confidently dismissed in the gate, issues and counts (default: list them separately) |
| `--llm-samples` | `1` | ask the model this many times on borderline verdicts and keep the majority; a verdict the samples disagree on is never dismissed. The cost estimate becomes an upper bound |
| `--deep-verify` | `0` | let the model read and search the repository (bounded, read-only, secrets-blocked) to settle the N highest-priority findings; see [Deep verification](deep-verify.md) |
| `--deep-max-steps` | `6` | with `--deep-verify`: most tool calls per finding |
| `--verify-fixes` | `true` | with `--remediate`: re-scan each proposed patch in a temp copy; `--fix-pr` applies only verified ones; see [Verifying fixes](verifying-fixes.md) |
| `--triage` | `false` | LLM triage + adversarial judge on each finding; confident false positives leave the gate (see [Reports & Gating](reports-and-gating.md#the-gate-and-the-ai-review)) |
| `--remediate` | `false` | propose fixes for high-confidence findings (implies `--triage`) |
| `--rag` | `false` | RAG few-shot from past feedback (needs `--llm-embed-model`) |
| `--review` | `false` | holistic full-repo security review agent |
| `--sca-advice` | `false` | dependency-upgrade advisor (merge-safety scored) |
| `--threat-model` | — | infer an OTM threat model, write it to this file |
| `--llm-base-url` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `--llm-model` | `$ACHILLES_LLM_MODEL` | default/fallback model |
| `--llm-judge-model` | — | model for the judge pass (default: same as `--llm-model`) |
| `--llm-embed-model` | `$ACHILLES_LLM_EMBED_MODEL` | embeddings model for `--rag` |
| `--llm-auth` | `key` | credential mode: `key` (Bearer, from `ACHILLES_LLM_API_KEY`; optional for local runtimes), `api-key` (same key as an `api-key:` header — Azure OpenAI), or `none` (no credential header — local runtimes). Extra headers, query, timeout and retries: [provider settings](llm-and-agents.md#any-openai-compatible-provider) |
| `--model-config` | — | YAML routing each task (triage/judge/remediation/review/sca/threat-model) to a model/endpoint |

Full walkthrough: [LLM Triage & Agents](llm-and-agents.md).

## Feedback & the learning loop

| Flag | Default | Description |
|------|---------|-------------|
| `--feedback` | — | record analyst feedback for a finding fingerprint, then exit |
| `--label` | — | `tp` or `fp` (with `--feedback`) |
| `--note` | — | optional note (with `--feedback`) |
| `--rule-health` | `false` | print per-rule TP/FP health from feedback, then exit |
| `--metrics` | `false` | print a metrics rollup over the vault, then exit |
| `--research` | `false` | research agents synthesize + validate new Opengrep rules |
| `--mine-rules` | `false` | mine rules from analyst-confirmed findings (needs `--llm-model`) |
| `--rule-repo` | `.achilles/generated-rules` | generated-rule repository directory |
| `--rule-shadow-days` | `7` | admitted generated rules are report-only until this many days old |
| `--research-max` | `20` | max dependencies to research per run (budget cap) |

## Report outputs

| Flag | Default | Description |
|------|---------|-------------|
| `--html-report` | — | self-contained HTML report (findings + AI review/advice/threat-model) |
| `--sarif-report` | — | unified SARIF 2.1.0 report (for GitHub code scanning etc.) |
| `--junit` | — | JUnit XML report (for CI test panels) |
| `--markdown` | — | Markdown summary (good for a PR comment) |
| `--github` | `false` | emit GitHub Actions annotations to stdout |
| `--sbom` | — | generate a CycloneDX SBOM (via Syft) to this file |
| `--diagnostics` | — | write a diagnostics sidecar (tool/parse failures + LLM token usage) |
| `--strict-tools` | `$ACHILLES_STRICT_TOOLS` | fail (exit 2) if any scanner could not run or be normalized, instead of reporting a partial scan. On in the container image — see [Running in containers](containers.md) |

## GitHub integrations (outward-facing, opt-in)

Need `GITHUB_TOKEN` and `--repo` (or `$GITHUB_REPOSITORY`).

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | `$GITHUB_REPOSITORY` | `owner/name` for GitHub integrations |
| `--pr-comment` | `0` | post/update a sticky summary comment on this PR number |
| `--pr-review` | `0` | post findings as inline review comments (needs `--pr-head-sha`) |
| `--pr-head-sha` | — | PR head commit SHA for `--pr-review` |
| `--file-issues` | `false` | open/maintain GitHub Issues with fix suggestions for kept findings; see [Filing issues](#filing-issues) below |
| `--fix-pr` | `false` | open a review PR with auto-fixes (needs `--remediate`; **never merges**) |
| `--fix-remote` | `origin` | git remote to push the auto-fix branch to |
| `--fix-base` | current branch | base branch for the auto-fix PR |

### Filing issues

`--file-issues` opens one GitHub Issue per finding (or per rule, or one rollup), labelled
`achilles`, with the message, a permalink to the code, the AI review, and the suggested
fix/diff. It reads `GITHUB_TOKEN` (or `GH_TOKEN`); `--repo` defaults to
`$GITHUB_REPOSITORY`, permalinks use `$GITHUB_SHA` and `$GITHUB_SERVER_URL`. It is skipped
under the global `--dry-run`. Only findings that survived AI review are filed (dismissed and
shadow findings never are).

| Flag | Default | Description |
|------|---------|-------------|
| `--issues-min-severity` | `medium` | lowest severity to file (`critical`, `high`, `medium`, `low`, `info`) |
| `--issues-max` | `25` | most **new** issues per run, highest severity first; the rest are filed on later runs |
| `--issues-group` | `finding` | `finding` (one issue per fingerprint), `rule` (one per tool+rule, with a table of locations) or `rollup` (a single issue). Each mode tracks only its own issues; switching modes leaves old issues untouched |
| `--issues-label` | `achilles` | label that marks (and scopes) the issues Achilles manages |
| `--issues-dry-run` | `false` | print the issues that would be created/updated/reopened/closed and call no write API |
| `--issues-strict` | `false` | exit non-zero if any GitHub call failed or filing was refused (otherwise failures only warn) |
| `--allow-public-issues` | `false` | allow filing in a **public** repository (see below) |

Behavior across runs:

- **Dedupe**: a hidden marker in each issue body identifies the finding. Findings that share a
  fingerprint (the same snippet in several files) are merged into one issue listing every
  location. An issue is only edited when its content (severity, location, AI review, fix)
  changed, not merely because the commit moved.
- **Human close = suppress.** Close an issue to stop Achilles filing that finding again.
- **Auto-close and reopen.** When a *full* scan no longer reports a finding, Achilles closes
  its issue with a comment and the `achilles:resolved` label. If the finding returns, the
  issue is reopened with a comment. Issues closed without that label (by a person) are never
  reopened. Auto-close is skipped, and the summary says why, when the scan is narrowed by
  `--diff`, `--baseline` or `--pr-mini`, or when any scanner failed. A finding the AI review
  now confidently dismisses also closes its open issue (with the reasoning).
- **Public repositories are refused** unless `--allow-public-issues` is set: issue bodies describe
  unfixed vulnerabilities. If visibility cannot be determined it is treated as public.
  Use `--sarif-report` and upload to the Security tab instead.
- **Secrets are never echoed.** For secret-scanner findings (gitleaks, secret/key/token/password
  rules, CWE-798/259/321) the issue has only rule, severity, `file:line` and rotation guidance:
  no matched text, code or diff. Other text is passed through the secret redactor, local paths
  are made repo-relative, and bodies are capped below GitHub's size limit (the diff is cut first).
- **Rate limits**: new issues are paced about a second apart and 429/secondary-rate-limit
  responses are retried a few times (honoring `Retry-After`) before giving up.
- Paths are made relative to the scan target, so scan the repository root for correct permalinks.

## Common recipes

```bash
# Local dev: fast scan, HTML report, don't fail
achilles --html-report report.html .

# CI gate: only new high-severity findings vs main, emit SARIF + annotations
achilles --diff origin/main --baseline .achilles/baseline.json \
  --sarif-report achilles.sarif --github --fail-on high .

# AI-assisted full analysis (needs a key)
export ACHILLES_LLM_API_KEY=...
achilles --triage --remediate --review --sca-advice \
  --threat-model tm.otm.json --html-report report.html \
  --llm-model gpt-4o .

# Record analyst feedback (a false positive), then see rule health
achilles --feedback <fingerprint> --label fp --note "test fixture"
achilles --rule-health
```
