# CLI Reference

Every `achilles` flag, grouped by task. (For `achilles-fleet`, see [Fleet](fleet.md).)

> **Flags before the target.** `achilles [flags] <target-path>`. Go's stdlib
> `flag` stops at the first positional, so a flag after the path is ignored.
> The target defaults to `.` if omitted.

## Scan setup

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `configs/tools.yaml` | tool registry file |
| `--profile` | `default` | `default` (baseline tools) or `full` (adds heavy per-language tools) |
| `--mode` | `oss` | license mode: `oss` or `commercial` (strict — refuses non-`commercialSafe` tools) |
| `--attest` | — | comma-separated tool IDs you hold a license attestation for (satisfies the gate in `commercial`) |
| `--runner` | `local` | run tools `local` (PATH) or `docker` (pinned images) |
| `--timeout` | `5m` | overall scan timeout |
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
| `--triage` | `false` | LLM triage + adversarial judge on each finding |
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
| `--file-issues` | `false` | file/reconcile issues (dedupe by fingerprint; closed suppresses; resolved auto-close) |
| `--fix-pr` | `false` | open a review PR with auto-fixes (needs `--remediate`; **never merges**) |
| `--fix-remote` | `origin` | git remote to push the auto-fix branch to |
| `--fix-base` | current branch | base branch for the auto-fix PR |

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
