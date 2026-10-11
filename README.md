# Achilles

Point it at a repository and an LLM API key. It runs open-source security scanners,
has a model review every finding the way a human triager would, and gives you back a
report and (on GitHub) issues with suggested fixes. Free, Apache-2.0, runs on your own
machine or in your own GitHub Actions. No service to sign up for.

> Independently implemented from public SAST concepts and standards. See
> [Acknowledgements](#acknowledgements).

## Quickstart

**On GitHub** (recommended). Add one secret (`LLM_API_KEY`) and one variable
(`LLM_MODEL`), then copy [`examples/workflows/achilles.yml`](examples/workflows/achilles.yml)
to `.github/workflows/`:

```yaml
permissions: { contents: read, issues: write }
steps:
  - uses: actions/checkout@v4
  - uses: Warzuponus/achilles@v0.1.0
    with:
      llm-api-key: ${{ secrets.LLM_API_KEY }}
      llm-provider: openrouter     # or openai | ollama
      llm-model: ${{ vars.LLM_MODEL }}
      issues: "true"
```

Run it from the Actions tab. You get an `achilles-report` artifact (HTML, Markdown,
SARIF), a summary on the job page, and one issue per confirmed finding with the AI's
reasoning and a suggested fix. Re-runs update those issues rather than duplicating
them. Details: [CI & the Scan Hub](docs/ci-and-hub.md).

**On your machine**, as a single binary (Linux and macOS; a Windows build is
published too and its tests run in CI, but `install.sh` and the GitHub Action are
Linux and macOS only, so on Windows download the zip from the release page):

```bash
curl -fsSLO https://raw.githubusercontent.com/Warzuponus/achilles/main/scripts/install.sh
sh install.sh                      # verifies the release checksum; installs to ~/.local/bin
achilles tools install             # downloads the pinned scanners, verified by sha256
achilles doctor                    # what is installed, what is missing, how to fix it

export ACHILLES_LLM_API_KEY=...    # your provider's key
achilles --ai --llm-provider openrouter --llm-model <model> .
open achilles-report/report.html
```

**In Docker**, which already contains the scanners:
`docker run --rm -v "$PWD":/work ghcr.io/warzuponus/achilles achilles --ai ... /work`
(see [Running in containers](docs/containers.md)).

Every path above needs a **release**, and none exists yet; until then build from source
(`make build`) or use `version: source` in the action.

## What you get

- **Scanners, one report.** Opengrep (many languages), gosec, osv-scanner (dependency
  CVEs), Trivy (IaC, misconfiguration, secrets) and Gitleaks, normalized into one set
  of findings. A scanner that failed to run is called out in every report; a partial
  scan is never presented as a clean one.
- **AI verification.** Each finding goes to a model with the code around it, then a
  second adversarial pass tries to refute the verdict. Confident false positives drop
  out of the gate, the counts and the issues, and are listed separately so you can audit
  them. Reports say how many findings the review actually covered.
- **Patches checked, not trusted.** A suggested fix is applied to a temp copy and the
  scanner that reported the finding is re-run; `--fix-pr` opens a PR only with patches
  where the finding is gone and nothing new appeared ([Verifying Fixes](docs/verifying-fixes.md)).
- **Optional deeper checks:** `--deep-verify N` lets the model read and search the repo
  (read-only, bounded, secrets blocked) to settle the findings a one-file review could not
  ([Deep Verification](docs/deep-verify.md)), and `--llm-samples` re-asks borderline verdicts
  and never dismisses one the answers disagree on.
- **Fix suggestions** for confirmed findings, a repo-level security review, a
  dependency-upgrade plan, and an optional threat model.
- **Gating for CI:** fail only on new findings (`--baseline`, `--diff`) at or above a
  severity.
- **Privacy controls:** credentials are masked before anything is sent to the model,
  findings about credentials are never sent, `--llm-no-code` sends no source at all,
  and a local model (`--llm-provider ollama`) keeps everything on your machine.

## Know the limits

- **The AI review is a judgment, not a proof.** The model sees one file's worth of
  context per finding, not the whole program. A repository you do not trust can try to
  talk it into dismissing a real finding: for that case use `--keep-dismissed`. See
  [SECURITY.md](SECURITY.md).
- **Coverage depends on the scanners.** The default set covers Go, dependencies, IaC
  and secrets well. Code-level coverage for Python, JavaScript, Java, Ruby and PHP comes
  mostly from Opengrep rules: Achilles ships a small baseline set, and
  `achilles tools install` adds the community rules (a Commons Clause licence applies;
  they are skipped under `--mode commercial`, see [THIRD-PARTY.md](THIRD-PARTY.md)). The
  heavier per-language analyzers (`--profile full`) need Docker.
- **Accuracy is only lightly measured:** an 18-case labeled triage corpus and a small
  detection benchmark (24 labeled issues in synthetic fixtures; about 46% recall with the
  default scanners, far lower for Python and JavaScript with only the bundled rules;
  the community rules were not measured), not real-repository precision and recall. See [evals/](evals/README.md) and
  [Benchmarking Detection](docs/benchmarking.md).
- **You choose the model and pay the provider.** `--dry-run` prints a cost estimate
  first. There is no default model.
- **Issues publish vulnerabilities** to everyone who can read the repo, so Achilles
  refuses to file them in a public repository unless you pass `--allow-public-issues`.

## Local-first, no authentication

Achilles has no cloud service and no login. The optional War Room (`achillesd`) is a
local web view over the Evidence Vault, reachable only from your own machine; it has
**no authentication**, and anyone who can reach its port can read every finding. See
[Running in containers](docs/containers.md#security-model-no-authentication). The
[User Guides](docs/README.md) cover the rest: getting started, every flag, reports and
gating, LLM triage and agents, CI and the scan hub, and the fleet. [DESIGN.md](DESIGN.md)
has the architecture; [DEPLOY.md](DEPLOY.md) every way to run it.

### Everything through Phase 5

**CI integration**: baseline- and diff-aware scanning (fail only on
newly-introduced findings), exports for SARIF / JUnit / Markdown, GitHub PR
annotations, a reusable GitHub Action, and release builds.

> **Flag ordering:** flags may come before or after the target path
> (`achilles --mode commercial ./src` and `achilles ./src --mode commercial` are the same).

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
    → [--triage] [--calibrate] feedback short-circuit? → RAG few-shot → LLM triage
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

The complete, current list is in the **[CLI Reference](docs/cli-reference.md)**
(`achilles --help` prints the same). The ones most people need:

| Flag | Purpose |
|------|---------|
| `--ai` | the full AI-verified scan and all three reports (`--report-dir`) |
| `--llm-provider`, `--llm-model` | which LLM endpoint and model; key from `ACHILLES_LLM_API_KEY` |
| `--llm-no-code`, `--keep-dismissed` | privacy mode; gate on raw scanner severity instead of AI-filtered |
| `--fail-on` | exit non-zero at or above a severity |
| `--baseline`, `--diff` | only new findings, only changed files |
| `--file-issues` | open and maintain GitHub issues (`--issues-*` options) |
| `--dry-run`, `--max-cost` | cost estimate before any model call |
| `--html-report`, `--sarif-report`, `--markdown` | write a report |

Subcommands: `achilles doctor`, `achilles tools install|list`, `achilles version`.

`--fail-on` is baseline/diff-aware: it gates on the *surfaced* set, so CI fails
only on newly-introduced (or changed-file) findings. See
[examples/workflows/scan-example.yml](examples/workflows/scan-example.yml) and
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

Phases 0–6 are done. Open follow-ups include a cobra CLI migration, a SQLite-backed
vault, OSV.dev grounding for the research agents, and SARIF `baselineState` output.
See [DESIGN.md](DESIGN.md) and [TEST_PLAN.md](TEST_PLAN.md); ideas and bugs are tracked
in [GitHub issues](https://github.com/Warzuponus/achilles/issues).

## Acknowledgements

Achilles orchestrates excellent open-source tools it does not own: Opengrep, gosec,
Trivy, Gitleaks and osv-scanner (and, optionally, many more — see
[THIRD-PARTY.md](THIRD-PARTY.md) for each one's license and how it is invoked).

The attacker-first verification ideas (answering explicit gate questions per finding,
trying to disprove a finding before reporting it, checking that fixes work, and
measuring detection against known-vulnerable code) were informed by the open-source
[VulnHunter](https://github.com/nealbridges/VulnHunter) project (Apache-2.0, a fork of
Capital One's VulnHunter). Those are concepts only; no code or prompt text is copied.

Some design ideas were informed by public writing, notably Block's
["CodeCrucible: A Blueprint for LLM-Driven SAST"](https://engineering.block.xyz/blog/codecrucible-a-blueprint-for-llm-driven-sast)
(a pre-flight cost gate, cross-tool finding correlation, and wider code context for
triage). Those are concepts only; the implementation here is original.

## License

Apache-2.0 — see [LICENSE](LICENSE). Contributions are welcome under the same terms;
see [CONTRIBUTING.md](CONTRIBUTING.md).
