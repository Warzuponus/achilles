# Achilles

[![CI](https://github.com/Warzuponus/achilles/actions/workflows/ci.yml/badge.svg)](https://github.com/Warzuponus/achilles/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Warzuponus/achilles)](https://github.com/Warzuponus/achilles/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Point it at a repository and an LLM API key. It runs open-source security scanners,
has a model review every finding the way a human triager would, and gives you back a
report and (on GitHub) issues with suggested fixes. Free, Apache-2.0, runs on your own
machine or in your own GitHub Actions. No service to sign up for.

> Independently implemented from public SAST concepts and standards. See
> [Acknowledgements](#acknowledgements).

## Why not just run the scanners yourself?

You can, and Achilles runs the same ones. If raw scanner output in CI is all you
want, each scanner's own action is simpler. Achilles is for what comes after the
scan:

| | Scanners on their own | With Achilles |
|---|---|---|
| Output | one format and one report per tool | one set of findings, one report, one gate |
| A scanner that could not run | usually a green job | named in every report; a run where no scanner could run fails; `--strict-tools` fails on any |
| False positives | you read every finding | a model reviews each one with the code around it, a second pass argues against the verdict, and confident false positives leave the gate (listed, so you can audit them) |
| Suggested fixes | none, or unchecked | applied to a copy and re-scanned before being called a fix |
| New findings only | per-tool baselines | one baseline and `--diff` across all tools |

How Achilles' own rules score against Semgrep, Bearer, Find Security Bugs and Bandit
on the OWASP Benchmark, run the same way and including where Achilles loses, is in
[docs/comparison.md](docs/comparison.md), with the commands to reproduce it.

## Quickstart

**On GitHub** (recommended). Add one secret (`LLM_API_KEY`) and one variable
(`LLM_MODEL`), then copy [`examples/workflows/achilles.yml`](examples/workflows/achilles.yml)
to `.github/workflows/`:

```yaml
permissions: { contents: read, issues: write }
steps:
  - uses: actions/checkout@v4
  - uses: Warzuponus/achilles@v0.3.1
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

**On your machine**, as a single binary (Linux and macOS; on Windows download the zip
from the [release page](https://github.com/Warzuponus/achilles/releases), because
`install.sh` and the GitHub Action support Linux and macOS only):

```bash
curl -fsSLO https://raw.githubusercontent.com/Warzuponus/achilles/main/scripts/install.sh
sh install.sh                      # verifies the release checksum; installs to ~/.local/bin
achilles tools install             # downloads the pinned scanners, verified by sha256
achilles doctor                    # what is installed, what is missing, how to fix it

export ACHILLES_LLM_API_KEY=...    # your provider's key
achilles --ai --llm-provider openrouter --llm-model <model> .
open achilles-report/report.html
```

**Set up a repository in one step.** In the repository, after installing the
scanners:

```bash
achilles init
```

It writes `.achilles.yaml` (fail on high, use the baseline), a CI workflow for GitHub
or GitLab (detected; it needs no secret and scans pull requests and the default
branch), adds the Evidence Vault to `.gitignore`, and seeds `.achilles/baseline.json`
with the findings in the code today. From then on CI fails only on new findings.
Existing files are left alone (`--force` replaces them, `--dry-run` shows what it
would write).

**In Docker**, which already contains the scanners:
`docker run --rm -v "$PWD":/work ghcr.io/warzuponus/achilles achilles --ai ... /work`
(see [Running in containers](docs/containers.md)).

**From source:** `make build` (Go 1.27), then `./bin/achilles`. No scanners installed
yet? `make run` feeds a sample SARIF file through the normalize and report steps.

## What you get

- **Scanners, one report.** Opengrep (many languages), gosec, osv-scanner (dependency
  CVEs), Trivy (dependencies, IaC misconfiguration, secrets) and Gitleaks, normalized
  into one set of findings. A scanner that failed to run, or ran but could not analyze
  everything, is called out in every report; a partial scan is never presented as a
  clean one.
- **AI verification.** Each finding goes to a model with the code around it, then a
  second adversarial pass tries to refute the verdict. Confident false positives drop
  out of the gate, the counts and the issues, and are listed separately so you can audit
  them. Reports say how many findings the review actually covered. Dependency
  advisories and credential findings are never dismissed by the model.
- **Patches checked, not trusted.** A suggested fix is applied to a temp copy and the
  scanner that reported the finding is re-run. A fix is called verified only when the
  finding is gone and nothing new appeared ([Verifying Fixes](docs/verifying-fixes.md)).
- **Fix suggestions** for confirmed findings, a repo-level security review and a
  dependency-upgrade plan.
- **Gating for CI:** fail only on new findings (`--baseline`, `--diff`) at or above a
  severity.
- **Privacy controls:** credentials are masked before anything is sent to the model,
  findings about credentials are never sent, `--llm-no-code` sends no source at all,
  and a local model (`--llm-provider ollama`) keeps everything on your machine.

### Stable and experimental

**Stable in v0.3.1:** the `achilles` CLI, the five default scanners and the built-in
rules, `--ai` (review plus adversarial judge), the HTML, Markdown and SARIF reports,
baseline and diff gating, inline suppressions (`achilles:ignore`), the GitHub Action,
issue filing, `achilles init`, `achilles tools install` and `achilles doctor`.

**Experimental** (they work and are tested, but have had less real-world use, and
their flags or behavior may change): `--fix-pr`, `--deep-verify`, `--hunt`, `--llm-samples`,
`--calibrate` and `--feedback`, `--rag`, `--threat-model`, `--sbom`, the research
agents (`--research`, `--mine-rules`), the `anthropic` provider preset, the War Room
(`achillesd`), the fleet dispatcher (`achilles-fleet`), `--profile full` with its
per-language tool images, the MCP server (`achilles mcp`), and the GitLab report outputs (`--gitlab-sast`,
`--gitlab-secret-detection`, `--gitlab-dependency-scanning`, `--gitlab-code-quality`: checked against GitLab's published
report schemas, and accepted and read by gitlab.com from a real pipeline). `--gitlab-mr-comment` has been run
against gitlab.com too: it posts the note and updates it in place. The
[User Guides](docs/README.md) cover each of them.

## Know the limits

- **The AI review is a judgment, not a proof.** The model sees one file's worth of
  context per finding, not the whole program. A repository you do not trust can try to
  talk it into dismissing a real finding: for that case use `--keep-dismissed`. See
  [SECURITY.md](SECURITY.md).
- **Coverage depends on the scanners.** The default set covers Go, dependencies, IaC
  and secrets well. Code-level coverage for Python, JavaScript, Java, Ruby and PHP comes
  mostly from Opengrep rules: Achilles ships about 90 of its own for Python,
  JavaScript and TypeScript, Java, Ruby, PHP and credentials (Apache-2.0, loaded in
  every mode), and `achilles tools install` adds the community rules (a Commons Clause
  licence applies; they are skipped under `--mode commercial`, see
  [THIRD-PARTY.md](THIRD-PARTY.md)). The heavier per-language analyzers
  (`--profile full`) need Docker.
- **Go code and Go 1.27.2 or newer.** gosec cannot yet read the compiler data that Go
  1.27.2 writes, so with that toolchain on your PATH it skips its type-based rules.
  Achilles reports gosec as incomplete when this happens instead of passing the scan.
  Until gosec catches up, scan Go code with Go 1.27.1 (the Docker image does).
- **Accuracy is measured, and modest on recall:** on 270 documented vulnerabilities in
  five deliberately vulnerable apps (DVWA, NodeGoat, PyGoat, RailsGoat, WebGoat), the
  scanners with Achilles' own rules find 31% (36% with the community rule pack), and
  that includes access-control and logic flaws no pattern rule can find. On the OWASP
  Benchmark, which has decoys and so measures false positives too, the own rules score
  69.7 for Java and 50.3 for Python (true-positive minus false-positive rate). The
  rules were partly written against these benchmarks, so expect less elsewhere; their
  out-of-sample scores, before that work, were 4.7 and 19.5. There is also an 18-case
  labeled triage corpus and a 24-issue synthetic regression benchmark. See
  [evals/](evals/README.md) and [Benchmarking Detection](docs/benchmarking.md).
- **You choose the model and pay the provider.** `--dry-run` prints a cost estimate
  first. There is no default model.
- **Issues publish vulnerabilities** to everyone who can read the repo, so Achilles
  refuses to file them in a public repository unless you pass `--allow-public-issues`.

## Local-first, no authentication

Achilles has no cloud service and no login. The optional War Room (`achillesd`) is a
local web view over the Evidence Vault, reachable only from your own machine; it has
**no authentication**, and anyone who can reach its port can read every finding. See
[Running in containers](docs/containers.md#security-model-no-authentication).

## How it works

```
scan      load the tool registry → license-mode gate → run the scanners → SARIF
          → normalize into findings → drop vendored and generated files
          → baseline and --diff → group the same defect reported by several tools
review    (--ai) add code context → model verdict → adversarial judge
          → fix suggestion → re-scan the fix
report    human, HTML, Markdown, SARIF, JUnit, GitLab → GitHub issues → --fail-on gate
record    every step is appended to the Evidence Vault (a local file, or PostgreSQL)
```

- Tools are declared in [configs/tools.yaml](configs/tools.yaml). A tool that emits
  SARIF is a config entry, with no Go code.
- The model client speaks the OpenAI-compatible API (`--llm-provider`, or
  `--llm-base-url` plus `--llm-model`), so a hosted provider, a gateway or a local
  runtime all work. The review and the judge can use different models
  (`--model-config`).
- `--mode commercial` refuses any tool not marked commercial-safe in the registry and
  skips the community Opengrep rules. Copyleft scanners are only ever run as separate
  programs, never linked: see [THIRD-PARTY.md](THIRD-PARTY.md).
- `--runner docker` runs each scanner in its pinned image, with no network unless the
  tool has to fetch advisory data. Opengrep has no public image and always runs as the
  local binary (Achilles prints a line saying so).
  `--profile full` adds the heavier per-language tools (Bandit, SpotBugs with
  Find Security Bugs, Psalm, Security Code Scan, clang-tidy, govulncheck, Checkov,
  ShellCheck, Railroader); you build their images from `deployments/<tool>/`, and a
  tool that cannot run makes the scan partial, not clean.

[DESIGN.md](DESIGN.md) has the architecture and [DEPLOY.md](DEPLOY.md) every way to
run it.

## Flags

The complete, current list is in the **[CLI Reference](docs/cli-reference.md)**
(`achilles --help` prints the same). The ones most people need:

| Flag | Purpose |
|------|---------|
| `--ai` | the full AI-verified scan and all three reports (`--report-dir`) |
| `--llm-provider`, `--llm-model` | which LLM endpoint and model; key from `ACHILLES_LLM_API_KEY` |
| `--llm-no-code`, `--keep-dismissed` | privacy mode; gate on raw scanner severity instead of AI-filtered |
| `--fail-on` | exit 1 if a finding at or above a severity remains |
| `--baseline`, `--diff` | only new findings, only changed files |
| `--strict-tools` | fail if any scanner could not run or could not analyze everything (a run where none could run always fails) |
| `--file-issues` | open and maintain GitHub issues (`--issues-*` options) |
| `--dry-run`, `--max-cost` | cost estimate before any model call; a cap on what the run may spend |
| `--html-report`, `--sarif-report`, `--markdown` | write a report |

Flags may come before or after the target path. Subcommands: `achilles doctor`,
`achilles tools install|list`, `achilles version`. Exit codes: 0 clean, 1 gated by
`--fail-on`, 2 error.

## Build and test

```bash
make build            # -> bin/achilles
make test             # hermetic unit tests (no Docker, tools, network or keys)
make test-integration # + real tools where installed (skips if absent)
make eval-gate        # triage eval against the labeled corpus (no model, no key)
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the setup, the conventions and a map of the
code. [evals/](evals/README.md) explains the eval harness.

## How this was built

Achilles was written by one developer working with AI coding assistants, and the
commit history says which commits were co-authored by one. Code written that way
deserves more scrutiny, not less, so the project leans on checks you can run
yourself: a hermetic test suite, the race detector, `govulncheck` and a Windows job in
CI, a labeled corpus that scores the AI review, a detection benchmark that publishes
its misses, and a self-scan that gates every change. What has and has not been
measured is stated in [Know the limits](#know-the-limits), [DEPLOY.md](DEPLOY.md) and
[Benchmarking Detection](docs/benchmarking.md). Reports that show it being wrong are
the most useful contribution: there is an
[issue template](.github/ISSUE_TEMPLATE/false_result.yml) for exactly that.

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
