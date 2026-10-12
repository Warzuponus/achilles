# Onboarding — Achilles

Welcome. This gets you from clone to productive. For *why* things are shaped the
way they are, read [DESIGN.md](DESIGN.md); for running it (workstation, Docker,
GitHub Actions, scheduled scans), see [DEPLOY.md](DEPLOY.md); for how it is tested, [TEST_PLAN.md](TEST_PLAN.md).

## What Achilles is

An **LLM-assisted harness that orchestrates open-source SAST tools**. It runs a
set of scanners, normalizes every tool's output to one SARIF-shaped `Finding`
model, then (optionally) uses an LLM to interpret and adversarially verify each
finding, learning from analyst feedback over time. It's Apache-2.0, Go, and
local-first (no cloud service, no authentication layer), and safe to run on code
you do not own — every default tool is license-clean for commercial use.

It is two programs:
- **`achilles`** (CLI) — ephemeral, per-scan. Runs in CI (or a laptop).
- **`achillesd`** (server) — the "War Room" UI/API over the Evidence Vault. Runs
  on your own machine (loopback only; no authentication — see
  [docs/containers.md](docs/containers.md#security-model-no-authentication)).

## Mental model — the pipeline

```
load tools.yaml → license gate (--mode) + profile (--profile)
  → run applicable scanners (each in a pinned container or local binary)
  → normalize native output → SARIF-shaped Finding
  → correlate  → enrich (code context, git blame)
  → [--triage] [--calibrate] feedback short-circuit? → RAG few-shot → LLM triage
               → adversarial judge → [--remediate] fix
  → Evidence Vault (append-only provenance) + report (human / SARIF / JUnit / PR annotations / gate)
  → [GitHub, opt-in] PR summary comment · inline review · issue lifecycle · auto-fix PR
[--research] inventory deps → research agent (cited) → synthesize rule
             → validation gate → admit | quarantine
```

Everything above the adapter line is tool-agnostic. Adding a tool almost never
touches Go.

## Quickstart

```bash
git clone https://github.com/Warzuponus/achilles.git && cd achilles
make build            # -> bin/achilles   (Go 1.27, no cgo)
make test             # hermetic unit tests: no Docker, tools, network, or API keys
make vet              # go vet
./bin/achilles --from-sarif internal/normalize/testdata/sample.sarif   # spine, no tools needed
./bin/achilles /path/to/code            # real scan (uses tools from configs/tools.yaml on PATH)
```

`make test` is the fast, always-green loop. Heavier verification is opt-in
(`make test-integration`, `make verify-tier2`, `make license-check`) — see below.

## Repo layout

[CONTRIBUTING.md](CONTRIBUTING.md#where-things-are) has the map of commands and packages.

## Core concepts

- **Tool registry (`configs/tools.yaml`)** — each tool declares its license,
  `commercialSafe`, languages, container image, and `argv` (with `{src}`,
  `{rules}`, `{out}` placeholders). A SARIF-emitting tool is *config only*.
- **License mode (`--mode oss|commercial`)** — the policy gate refuses
  non-`commercialSafe` tools in commercial-mode (this is the "safe on customer
  code" guarantee). `commercial` is the strict one.
- **Scan profiles (`--profile default|full`)** — `default` = the 5 baseline
  tools (Opengrep, gosec, Trivy, OSV-Scanner, Gitleaks); `full` adds the heavy
  per-language tools (findsecbugs/JVM, psalm/PHP, security-code-scan/.NET,
  clang-tidy/C++), which need their built images + prerequisites.
- **Runners** — `--runner local` (binaries on PATH) or `docker` (pinned images).
  Docker mode relies on each image's entrypoint; per-tool `network` policy
  (`none` by default for containment, `default` for tools that need egress like
  osv-scanner / .NET NuGet restore).
- **Evidence Vault (`internal/vault`)** — append-only provenance of every raw
  output, finding, LLM call, verdict, and feedback. It *is* the audit trail, the
  reproducibility record, and the learning corpus. Backends: `file` (JSONL) or
  `postgres` (`--vault-backend`; DSN from `ACHILLES_VAULT_DSN`). Results are grouped
  into **projects** (`--vault-tenant`).
- **LLM layer** — OpenAI-compatible (`--llm-base-url/--llm-model`, key from
  `ACHILLES_LLM_API_KEY`). Triage → structured verdict; a second **judge** call
  tries to refute it (only unrefuted true-positives are high-confidence).
  Opt-in via `--triage`/`--remediate`.
- **Learning loop** — analyst TP/FP feedback (CLI `--feedback` or the War Room)
  feeds **RAG** few-shot and, only when `--calibrate` is passed, per-rule
  **calibration** (resolves chronically-noisy low-severity rules without an LLM
  call). Feedback in the UI is the *same* signal.
- **Research agents (`--research`)** — turn threat intel into new Opengrep rules,
  admitted only if they pass the **validation gate** (compile ∧ match a
  vulnerable fixture ∧ NOT match the patched one). The load-bearing guardrail.
- **GitHub integration (all opt-in + outward-facing)** — write results
  back to a PR/repo, keyed by finding fingerprint so re-runs don't duplicate.
  `--pr-comment <n>` posts/updates one sticky summary comment; `--pr-review <n>
  --pr-head-sha <sha>` posts inline diff comments (deduped, out-of-diff lines
  skipped); `--file-issues` files/reconciles issues (a **closed** issue
  suppresses, a **resolved** one auto-closes — full-repo scans only, auto-close
  is skipped under `--diff`); `--fix-pr` (with `--remediate`) commits the fixes
  that passed verification to a fingerprint-named branch, in a temporary
  worktree, and opens a **review PR** — it **never
  merges** (the guardrail; `--fix-remote`/`--fix-base` tune the push target and
  base). Repo comes from `--repo` or `$GITHUB_REPOSITORY`, token from
  `GITHUB_TOKEN`. Posting is the **CI's** job with its own token; locally these
  are verified only against mock servers, never a live repo.

## Verification philosophy (important)

Three tiers, by dependency:

1. **Hermetic** (`make test`, `go test ./...`) — no Docker/tools/network/keys.
   Scanner execution is tested with a fake `exec.Runner`; the LLM with a fake
   client (`triage/llm/llmtest`); normalization against committed SARIF fixtures.
   **This must always pass.**
2. **Integration** (`-tags integration`, `make test-integration`) — runs real
   tools (opengrep, git) where installed; `t.Skip()`s otherwise.
3. **CI-native harnesses** — for tools that need a runtime/Docker the dev laptop
   lacks, verification happens on GitHub's runners:
   - `verify/tier2/verify.sh` (+ `tier2-verify.yml`) builds each heavy tool image
     and runs a known-vulnerable sample **through Achilles**, asserting the
     finding surfaces.
   - `quickstart.yml` runs the compose stack end to end (build, scan the bundled
     sample, check the War Room, check the Host and cross-origin protections).

The rule of thumb this repo lives by: **don't mark a tool "verified" until it's
green in one of these.** Scaffolding is fine; claiming it works without a run is
not.

## Common task: add a scanner

- **SARIF-emitting + on PATH / has a public image** → add a `configs/tools.yaml`
  entry (id, license, `commercialSafe`, languages, `image` pinned by digest,
  `bin`, `argv` writing to `{out}/results.sarif`, `outputFile`, and
  `successExitCodes` so a crash after a partial report is not read as a clean
  scan). No Go code. Set
  `enabled: true` for the baseline or `profiles: [full]` for opt-in.
- **Needs a language runtime / no public image / no native SARIF** → add
  `deployments/<tool>/` (a Dockerfile, possibly a wrapper + a SARIF converter),
  a disabled config entry, a `verify/tier2/<tool>/sample`, a `verify/tier2/<tool>.yaml`,
  and a case in `verify.sh`. Then push and watch `tier2-verify` — iterate against
  the real output until `PASS[<tool>]`. (findsecbugs, psalm, security-code-scan,
  clang-tidy are worked examples.)
- **Non-SARIF, simple** → a small `Normalizer` in `internal/normalize` (rare).

## CI workflows (`.github/workflows/`)

| Workflow | Runs | Purpose |
|----------|------|---------|
| `ci.yml` | every push/PR | build, vet, gofmt, hermetic tests under the race detector (Linux) and on Windows, `govulncheck`, the action against the bundled sample, best-effort integration tests |
| `self-scan.yml` | push/PR | Achilles scans its own Go code (gosec) with `--strict-tools`, gates on findings not in `.achilles/baseline.json` |
| `license-check.yml` | push/PR | fails if any Go dep is copyleft (AGPL/GPL/LGPL), or if the shipped license texts are stale |
| `tier2-verify.yml` | on demand / tool changes | end-to-end verify of the heavy tools (Docker) |
| `quickstart.yml` | compose / image changes | the docker compose quickstart, end to end |

Copy-paste consumer templates (they do not run here) live in `examples/workflows/`:
`achilles.yml` (the AI-verified scan), `scan-example.yml` (SARIF upload + PR gate),
`scan-ollama-example.yml` (routed LLM scan) and `scan-hub.yml` (scan other repositories from one place).

## Conventions & gotchas

- **`configs/rules/*.yaml` must be ASCII** — Opengrep's config reader is
  ASCII-only (an em-dash once caused a scan to exit 2).
- **Self-scan baseline** — `.achilles/baseline.json` is committed. New gosec
  findings on our own code fail `self-scan` if ≥ high; if they're
  FP-in-context, regenerate: `achilles --config configs/selfscan.yaml
  --write-baseline .achilles/baseline.json .`
- **Heavy tools are `enabled: false` + `profiles: [full]`** on purpose — they
  need locally-built images + prerequisites (compiled bytecode / `psalm.xml` /
  a restorable .NET project). `--profile full` switches them on; missing ones
  degrade to a partial scan, they don't fail the run.
- **Commercial-license posture** — AGPL/GPL tools (e.g. TruffleHog) are invoked
  **only as separate-process containers, never imported as Go modules**. The
  `license-check` workflow enforces this. See [THIRD-PARTY.md](THIRD-PARTY.md).
- **The Evidence Vault `Store` has no update/delete** — that's the append-only
  guarantee. Retention (`Purger`) is a separate interface (`POST /admin/tenants/{id}/purge`).

## Deploying

Achilles is local-first; [DEPLOY.md](DEPLOY.md) has the four supported paths:

- **The CLI** on a workstation, with a file vault.
- **Docker / docker compose** — the all-in-one image, PostgreSQL, the War Room on
  `127.0.0.1`, and `scan` / `fleet` / `ollama` profiles
  ([docs/containers.md](docs/containers.md)).
- **GitHub Actions** — the action, the per-PR gate, the routed LLM scan, and the
  central **scan hub** (scan other repos via a GitHub App; results are workflow
  artifacts, no cloud vault).
- **Scheduled scans** with `achilles-fleet` (compose profile, cron, or a Kubernetes
  `CronJob`).

There is no authentication in the War Room; do not expose it beyond loopback.

## Where to look next

- [DESIGN.md](DESIGN.md) — architecture and the §-numbered rationale.
- [CONTRIBUTING.md](CONTRIBUTING.md#where-things-are) — a map of the code, and how to make a change.
- [DEPLOY.md](DEPLOY.md) — the ways to run it: CLI, Docker, GitHub Actions, scheduled scans.
- [TEST_PLAN.md](TEST_PLAN.md) — what is tested, where, and what is not.
- [GitHub issues](https://github.com/Warzuponus/achilles/issues) — backlog and bugs (start here for "what's next").
