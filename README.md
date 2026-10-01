# Achilles

LLM-assisted harness that orchestrates open-source SAST tools, normalizes their
findings, and uses LLMs to interpret, verify, and prioritize them — improving over
time from analyst feedback.

**New here? Start with the [User Guides](docs/README.md)** (or `docker compose up` — see
[Running in containers](docs/containers.md)) — getting started, the
CLI reference, reports & gating, LLM triage & agents, CI & the scan hub, and the
fleet. See [DESIGN.md](DESIGN.md) for the full architecture and roadmap, and
[DEPLOY.md](DEPLOY.md) for how to run it (a workstation, Docker, GitHub Actions, scheduled scans).

> Independently implemented from public SAST concepts and standards. See
> [Acknowledgements](#acknowledgements).

## Status

**The build roadmap is complete** (Phases 0–6, backlog Tiers A–F). Achilles is
**local-first**: it runs on your own machine, in Docker, or in your own GitHub
Actions, with no cloud service and no authentication layer. It is meant for someone
scanning their **own** repositories.

What you can run today:
- **CLI + GitHub Actions** — per-PR gate, or a routed full scan with LLM analysis.
- **Central scan hub** — scan *other* org repos from this repo via a GitHub App;
  targets need no secrets and no workflow of their own. Results are workflow
  artifacts (HTML, SARIF, Markdown); there is no cloud vault.
- **Docker / docker compose** — one image with the scanners, plus PostgreSQL, the
  War Room, and optional `scan`, `fleet` and local-model (`ollama`) profiles. See
  [Running in containers](docs/containers.md).
- **Fleet** — `achilles-fleet` scans many of your repos (paths or git URLs) into
  per-project vaults, once or on an interval.
- **Multi-model LLM routing** — per-task models over any OpenAI-compatible
  endpoint (OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM, OpenRouter, gateways).

`achillesd` is a server-rendered War Room (HTMX/Alpine) over the Evidence Vault
with **per-project vault isolation** and **secret redaction**. Analyst verdicts
submitted in the UI feed straight back into calibration, closing the learning loop.

```bash
achillesd --vault-root .achilles/tenants   # War Room on http://127.0.0.1:8080
```

Endpoints: `/` (dashboard), `/runs/{id}` (findings + verdicts + feedback),
`POST /runs/{id}/feedback`, `/runs/{id}/audit` (JSON audit trail), `/events`
(SSE), and `GET/POST /admin/tenants` + `POST /admin/tenants/{id}/purge`
(retention) + `GET /admin/fleet` (cross-project rollup). A **project switcher**
in the dashboard header lists every project that holds data — discovered from the
vault backend, not just the registry, since scans write to their project vault
without registering — and the choice persists in a cookie so navigating into a run
stays in that project. `GET /healthz` is a liveness probe.

**Security model — there is no authentication.** Anyone who can reach the War Room's
port can read every finding and can submit feedback, create projects, purge data and
view the fleet rollup. It is therefore built to be reachable only from your own
machine: it listens on loopback by default and refuses another address without
`--allow-remote`; the compose stack publishes it on `127.0.0.1` only; the `Host`
header must be `localhost`/`127.0.0.1`/`::1` or listed in `--allowed-hosts` (this
defeats DNS rebinding); and cross-origin state-changing requests are rejected. To
share it, put your own authenticating reverse proxy in front (and add its hostname
to `--allowed-hosts`) or don't share it. Details:
[Running in containers](docs/containers.md#security-model-no-authentication).

The vault backend is `--vault-backend file|postgres`. PostgreSQL is the shared
backend that lets scans and the War Room (possibly in different containers) see the
same data; the file backend is safe to share between a scan and a running
`achillesd` on one host (local filesystem only).

### Everything through Phase 5

**CI integration**: baseline- and diff-aware scanning (fail only on
newly-introduced findings), exports for SARIF / JUnit / Markdown, GitHub PR
annotations, a reusable GitHub Action, and release builds.

> **Flag ordering:** flags must come *before* the target path
> (`achilles --mode commercial --sarif-report out.sarif ./src`) — Go's stdlib
> flag parser stops at the first positional arg. (cobra migration is on the roadmap.)

### Everything through Phase 4

**Research agents** turn threat intel into new detections: inventory the
codebase, research each dependency (grounded, citation-mandatory), synthesize
Opengrep rules, and admit them **only if they pass a validation gate** — a
self-growing, self-curating rule corpus. Admitted rules are then **loaded into
subsequent scans** automatically, serving a **shadow window**
(`--rule-shadow-days`, default 7) during which they run report-only — findings
show up but are excluded from the `--fail-on` gate and from written baselines —
so a freshly-generated rule can never block CI before it's been observed.

```
CLI → load tools.yaml → license gate → run engines → SARIF → normalize
    → [--triage] calibration short-circuit? → RAG few-shot → LLM triage
    → adversarial judge → [--remediate] fix → Evidence Vault + report
[--research] inventory → research (cited issues) → synthesize rule
    → §9.3 gate (parses ∧ matches vulnerable ∧ ¬matches patched) → admit | quarantine
feedback: achilles --feedback <fingerprint> --label tp|fp   (feeds calibration + RAG)
```

**The validation gate is non-negotiable**: a generated rule ships only if it
compiles, matches a vulnerable fixture, and does **not** match the patched one.
Everything else is quarantined for human review, never auto-run.

The LLM client is **OpenAI-compatible** (`--llm-base-url` + `--llm-model`, key
from `ACHILLES_LLM_API_KEY`/`OPENAI_API_KEY`), so OpenAI, Azure, vLLM, or Ollama
all work — point `--llm-base-url` at a local runtime to keep code in your
boundary. Triage and judge can use different models (`--llm-judge-model`).

- **Apache-2.0** licensed. AGPL tools (e.g. TruffleHog) are invoked only as
  separate-process containers, never linked — see [THIRD-PARTY.md](THIRD-PARTY.md).
- Tools are declared in [configs/tools.yaml](configs/tools.yaml); a SARIF-emitting
  tool is a config entry, no Go code (`generic` adapter). Opengrep uses a bespoke
  adapter as the reference example.
- `--mode commercial` refuses any non-commercial-safe tool (e.g. Brakeman).

## Build & test

```bash
make build            # -> bin/achilles
make test             # hermetic unit tests (no Docker/tools/network needed)
make test-integration # + real tools where installed (skips if absent)
make vet
make eval-context     # triage eval vs the labeled corpus (hermetic: no model, no key)
make eval-gate        # the same, failing if context coverage regressed
```

See [TEST_PLAN.md](TEST_PLAN.md) for the per-phase verification matrix and
[evals/](evals/README.md) for the triage eval harness (ground truth for whether a
prompt/context/model change actually helped).

## Try it

**Without installing anything** — ingest an existing SARIF file to exercise the
normalize → report path:

```bash
make run
# or:
./bin/achilles --from-sarif internal/normalize/testdata/sample.sarif
```

**Real scan (uses tools from `configs/tools.yaml` found on PATH):**

```bash
./bin/achilles /path/to/code
```

**Commercial-mode (refuses non-commercial-safe tools):**

```bash
./bin/achilles --mode commercial /path/to/code
```

**Containerized (per-tool images from config, reproducible + isolated):**

```bash
./bin/achilles --runner docker /path/to/code
```

**Full scan (adds the heavy per-language tools — Python/JVM/PHP/.NET/C++):**

```bash
./bin/achilles --runner docker --profile full /path/to/code
```

`--profile full` also runs Bandit (Python), Railroader (Ruby/Rails),
SpotBugs+find-sec-bugs (JVM), Psalm (PHP), Security Code Scan (.NET), clang-tidy
(C/C++), govulncheck (reachability-aware Go dependency vulns), Checkov
(second IaC scanner, alongside Trivy), and ShellCheck (shell scripts). These
need their Achilles-built images
(`deployments/<tool>/`) and language prerequisites (compiled bytecode /
`psalm.xml` / a restorable .NET project / a Go module); missing ones degrade to
a partial scan.

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--config` | `configs/tools.yaml` | tool registry file |
| `--profile` | `default` | `default` (baseline tools) or `full` (also the heavy per-language tools) |
| `--mode` | `oss` | `oss` (all tools) or `commercial` (only license-clean tools) |
| `--attest` | — | comma-separated tool IDs with a supplied license attestation (e.g. `codeql`) |
| `--runner` | `local` | `local` (binaries on PATH) or `docker` (per-tool images from config) |
| `--vault` | `.achilles/vault.jsonl` | Evidence Vault path (file backend) |
| `--vault-backend` | `file` | `file` or `postgres` (any PostgreSQL; DSN from `$ACHILLES_VAULT_DSN`) |
| `--vault-tenant` | `default` | the project these results belong to; postgres stores them under `tenant-<id>`, which the War Room reads |
| `--sarif-out` | — | write each tool's SARIF into this directory |
| `--from-sarif` | — | skip scanning; normalize an existing SARIF file |
| `--fail-on` | — | exit non-zero at/above a severity (`critical\|high\|medium\|low`) |
| `--timeout` | `5m` | scan timeout |
| `--triage` | `false` | run LLM triage + adversarial judge on findings |
| `--remediate` | `false` | propose fixes for high-confidence findings (implies `--triage`) |
| `--review` | `false` | run the holistic full-repo security review agent (systemic risks; needs `--llm-model`) |
| `--sca-advice` | `false` | run the SCA dependency-upgrade advisor (merge-safety-scored plan; needs `--llm-model`) |
| `--threat-model` | — | infer an OTM threat model (trust zones/components/STRIDE threats) and write it to this file (needs `--llm-model`) |
| `--llm-base-url` | `https://api.openai.com/v1` | OpenAI-compatible endpoint (or `$ACHILLES_LLM_BASE_URL`) |
| `--llm-model` | `$ACHILLES_LLM_MODEL` | model for triage (required with `--triage`) |
| `--llm-judge-model` | — | separate model for the judge pass (model routing) |
| `--llm-auth` | `key` | credential: `key` (Bearer, from `ACHILLES_LLM_API_KEY`), `api-key` (`api-key:` header, Azure OpenAI) or `none` (local runtimes) |
| `--model-config` | — | YAML routing each step (triage/judge/remediation) to a model/endpoint; see `configs/models.example.yaml` |
| `--rag` | `false` | inject similar past-feedback findings as few-shot (needs `--llm-embed-model`) |
| `--llm-embed-model` | `$ACHILLES_LLM_EMBED_MODEL` | embeddings model for `--rag` |
| `--feedback` | — | record analyst feedback for a finding fingerprint, then exit |
| `--label` | — | `tp` or `fp` (with `--feedback`) |
| `--note` | — | optional note (with `--feedback`) |
| `--rule-health` | `false` | print per-rule TP/FP health from accumulated feedback (noisy vs. high-yield), then exit |
| `--metrics` | `false` | print a fleet rollup over the vault (findings by severity/tool/rule/target, FP rate, LLM spend), then exit |
| `--research` | `false` | research inventory deps → synthesize + gate-validate new rules |
| `--mine-rules` | `false` | mine Opengrep rules from analyst-confirmed findings (validated + admitted; needs `--llm-model`) |
| `--rule-repo` | `.achilles/generated-rules` | generated-rule repository directory (admitted rules load into scans) |
| `--rule-shadow-days` | `7` | admitted generated rules are report-only (don't gate) until this old |
| `--research-max` | `20` | max dependencies to research per run (budget cap) |
| `--diff` | — | diff-aware: keep only findings in files changed vs this git ref |
| `--exclude` | — | extra noise patterns (comma-sep): a path segment (`tests`) or glob (`*.gen.go`) |
| `--no-default-excludes` | `false` | disable the built-in vendored/generated/minified noise filter |
| `--no-correlate` | `false` | disable cross-tool correlation (triage every duplicate report separately) |
| `--dry-run` | `false` | scan, print the LLM cost estimate, and stop before any model call or outward action |
| `--max-cost` | `0` | refuse to start LLM work if estimated spend exceeds this many USD (needs `--price-config`) |
| `--price-config` | — | YAML per-model token prices for estimation (see [configs/prices.example.yaml](configs/prices.example.yaml)) |
| `--baseline` | — | suppress findings present in this baseline file |
| `--pr-mini` | — | auto seed-vs-delta: seed the baseline if absent (no gate), else delta-scan against it |
| `--write-baseline` | — | write current findings' fingerprints as a baseline |
| `--sarif-report` | — | write a unified SARIF report (GitHub code scanning) |
| `--junit` | — | write a JUnit XML report |
| `--markdown` | — | write a Markdown summary (PR comment) |
| `--html-report` | — | write a self-contained HTML report: findings + AI review, upgrade advice, and threat model. Open in a browser |
| `--github` | `false` | emit GitHub Actions annotations to stdout |
| `--pr-comment` | `0` | post/update a sticky summary comment on this PR number (needs `GITHUB_TOKEN` + `--repo`) |
| `--pr-review` | `0` | post findings as inline review comments on this PR (needs `--pr-head-sha`; deduped, diff-line-only) |
| `--pr-head-sha` | — | PR head commit SHA for `--pr-review` (`github.event.pull_request.head.sha`) |
| `--file-issues` | `false` | file/reconcile GitHub issues for kept findings (dedupe by fingerprint; a closed issue suppresses; resolved issues auto-close). Full-repo scans only — skips auto-close under `--diff` |
| `--fix-pr` | `false` | open a review PR with high-confidence auto-fixes (needs `--remediate`): applies each remediation diff to a fresh branch, pushes, opens a PR — **never merges** |
| `--fix-remote` | `origin` | git remote to push the auto-fix branch to (with `--fix-pr`) |
| `--fix-base` | current branch | base branch for the auto-fix PR (with `--fix-pr`) |
| `--repo` | `$GITHUB_REPOSITORY` | `owner/name` for GitHub integrations |
| `--diagnostics` | — | write a sidecar JSON: tool/parse failures (coverage gaps) + LLM token usage |
| `--sbom` | — | generate a CycloneDX SBOM of the target (via Syft) and write it to this file |

`--fail-on` is baseline/diff-aware: it gates on the *surfaced* set, so CI fails
only on newly-introduced (or changed-file) findings. See
[.github/workflows/scan-example.yml](.github/workflows/scan-example.yml) and
[action.yml](action.yml).

## Layout

```
cmd/achilles        CLI entrypoint (load config → gate → run → vault → report)
internal/config     tools.yaml loader (declarative tool registry)
internal/policy     license-mode gate (oss/commercial + attestation)
internal/vault      Evidence Vault — append-only provenance store
internal/model      Finding + minimal SARIF types
internal/scanner    Scanner interface + registry
  ├─ generic        config-driven adapter (any SARIF tool, no code)
  └─ opengrep       bespoke adapter (reference example)
internal/exec       container/local Runner (path-placeholder resolution)
internal/normalize  SARIF → Finding (reused by every SARIF-emitting tool)
internal/enrich     code-context enricher (lines around a finding's span)
internal/triage     LLM triage + adversarial judge + remediation engine
  └─ llm            OpenAI-compatible client + model Router
     └─ llmtest     fake client for hermetic tests (never in the binary)
internal/knowledge  learning loop: feedback capture + calibration + chromem-go RAG
internal/inventory  detect languages + dependencies (Recon)
internal/research   research agents → rule synthesis → §9.3 validation gate → rule repo
internal/baseline   baseline load/write + suppression (fail only on new findings)
internal/vcs        diff-aware scanning (changed files via git)
internal/report     human report + SARIF/JUnit/Markdown/GitHub-annotation exports
internal/metrics    fleet metrics rollup over the vault (--metrics)
internal/server     War Room: per-project isolation, redaction, handlers, templates
internal/fleet      fleet control plane: config -> plan -> concurrent dispatch
cmd/achillesd       War Room HTTP server
cmd/achilles-fleet  fleet dispatcher (many projects x targets -> per-project vaults)
internal/eval       triage eval harness: labeled corpus -> context + verdict scoring
cmd/achilles-eval   eval CLI (--mode context | verdict)
evals/triage        labeled corpus (14 cases, 7 tp / 7 fp) + committed context baseline
configs/tools.yaml  declarative tool registry
configs/rules       in-house baseline rules (clean IP, ASCII-only)
.github/workflows   repo CI + example scan workflow;  action.yml  reusable Action
```

## Roadmap complete — selected follow-ups

Phases 0–6 are done. Remaining polish lives in [tasks/todo.md](tasks/todo.md):
cobra CLI migration, feeding admitted generated rules back into scans, a
SQLite-backed vault, and an AGPL-import CI guard. See [DESIGN.md](DESIGN.md) and [TEST_PLAN.md](TEST_PLAN.md).

## Acknowledgements

Achilles orchestrates excellent open-source tools it does not own: Opengrep, gosec,
Trivy, Gitleaks and osv-scanner (and, optionally, many more — see
[THIRD-PARTY.md](THIRD-PARTY.md) for each one's license and how it is invoked).

Some design ideas were informed by public writing, notably Block's
["CodeCrucible: A Blueprint for LLM-Driven SAST"](https://engineering.block.xyz/blog/codecrucible-a-blueprint-for-llm-driven-sast)
(a pre-flight cost gate, cross-tool finding correlation, and wider code context for
triage). Those are concepts only; the implementation here is original.

## License

Apache-2.0 — see [LICENSE](LICENSE). Contributions are welcome under the same terms;
see [CONTRIBUTING.md](CONTRIBUTING.md).
