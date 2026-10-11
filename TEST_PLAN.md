# Achilles — how it is tested

A security tool that quietly misses things is worse than none, so "done" here means a
check passes, not that the code looks right. This page says what is checked, where,
and what is not checked at all.

## Principles

1. **Hermetic by default.** `go test ./...` passes with no external tools, network,
   Docker, database or API keys. Scanners are exercised through a fake `exec.Runner`
   or a fake scanner binary built from the test itself; the model through a fake
   client (`internal/triage/llm/llmtest`) or a local `httptest` server;
   normalization against committed SARIF fixtures.
2. **Real tools are opt-in.** Tests behind the `integration` build tag run real
   scanners and skip themselves when a tool is absent. A skipped check is reported
   as skipped, never as a pass.
3. **A guard is only tested if the test fails without it.** For anything that
   protects a boundary (the fix scope rule, redaction, host and cross-origin checks,
   project isolation, process-tree kill), break the guard, watch the test fail,
   restore it.
4. **Every bug gets a regression test** before the fix is called done.

```bash
make test              # hermetic unit tests (go test ./...)
make test-integration  # + real tools where installed (-tags integration)
make vet               # go vet
gofmt -l .             # must print nothing
make eval-gate         # triage context coverage against the committed baseline
```

## What runs in CI

| Check | Where | When |
|---|---|---|
| gofmt, `go vet`, build | `ci.yml` | every push and PR |
| Hermetic tests under the race detector, with a PostgreSQL service for the vault tests | `ci.yml` | every push and PR |
| The same tests on Windows | `ci.yml` (`test-windows`) | every push and PR |
| `govulncheck` over the module and the Go toolchain | `ci.yml` (`vulncheck`) | every push and PR |
| Tree hygiene: no local paths, key material, deployment state or cloud SDKs | `ci.yml` (`scripts/check-tree.sh`, `make check-deps`) | every push and PR |
| Triage eval, context mode: the prompt still contains the evidence a triager needs | `ci.yml` (`make eval-gate`) | every push and PR |
| The GitHub Action, built from the checkout, against the bundled sample with `--strict-tools` | `ci.yml` (`action`) | every push and PR |
| Achilles scanning its own code with `--strict-tools`, gating on findings not in the baseline | `self-scan.yml` | every push and PR |
| No copyleft Go dependency; shipped license texts match the linked modules | `license-check.yml` | every push and PR |
| The compose quickstart end to end: build the image, start PostgreSQL and the War Room, scan the sample with every scanner required to run, check the findings in the UI, check the Host and cross-origin protections | `quickstart.yml` | image, compose, `cmd/` and `internal/` changes; weekly |
| Each `--profile full` tool image finds a known-vulnerable sample through Achilles | `tier2-verify.yml` | tool image and registry changes; on demand |
| Integration tests with real tools | `ci.yml` | every push and PR, best effort (a failure does not fail the job) |

## What the tests cover, by area

| Area | Evidence |
|---|---|
| Normalization (SARIF and the native formats) | unit tests over committed fixtures: field mapping, severity (level and `security-severity`), CWE, fingerprint precedence and stability, secret and dependency classification, malformed input |
| Tool registry and license gate | table tests: safe and non-safe tools under each mode, attestation, config validation; the embedded registry is loaded and checked |
| Running tools | fake-runner tests for argv and mounts; real child processes for timeout and interrupt (the whole process tree must die); a scanner that reports it could not analyze everything makes the scan incomplete |
| The scan pipeline | end-to-end tests that run `achilles` itself against a fake scanner: exit codes (0, 1 gated, 2 error), flags before and after the target, `--strict-tools`, fix verification on its own clock |
| Evidence Vault | append and read back, persistence across reopen, cross-process locking (Unix and Windows), PostgreSQL backend against a real server in CI |
| Model review and judge | scripted fake model: verdict parsing, the judge's three outcomes, when a refuted true positive may be dismissed, confidence clamping, schema fallback, prompt contents |
| What may be dismissed | table tests: dependency advisories and credential findings never are; calibration is off unless asked for and bounded when on |
| Fix verification and `--fix-pr` | real `git`: the scope rule (one file, the finding's own, never CI or git control paths), apply and re-scan outcomes, commits made in a temporary worktree without touching the user's checkout |
| Redaction and privacy | credentials masked in prompts, reports, issues and the War Room (findings and audit trail); credential findings never sent to a model; raw scanner output scrubbed before it is stored |
| Reports and exports | SARIF re-parses as SARIF 2.1.0; JUnit re-parses; Markdown escaping; HTML report states scan completeness |
| GitHub integrations | mock-server tests only: issue lifecycle, de-duplication, PR comments. **Never run against a live repository in CI.** |
| War Room | `httptest`: project isolation, redaction, feedback, audit export, Host and cross-origin guards, the Content-Security-Policy, no third-party script |
| Fleet | planning and dispatch with a fake runner; fetching from local git repositories |
| Eval harness | corpus validation, scoring math, regression detection; `make eval-corpus` checks the corpus's claims about scanners by running them |

## What is not verified

- **Accuracy on real repositories.** The triage eval is 18 labeled cases and the
  detection benchmark is 24 labeled issues in synthetic fixtures. They catch gross
  regressions; they are not precision and recall on real code. See
  [evals/README.md](evals/README.md) and [docs/benchmarking.md](docs/benchmarking.md).
- **Verdict-mode eval numbers for the current prompt.** The recorded model runs in
  `evals/` predate the latest prompt version and have not been repeated on it.
  Verdict mode needs an API key and spends money, so it is run deliberately, not in CI.
- **Live GitHub writes.** Issue filing, PR comments and `--fix-pr` are tested against
  mock servers and a local git remote, not against github.com.
- **The `anthropic` provider preset** has not been run against the live API.
- **Tests on macOS.** Release binaries are built for it; CI tests Linux and Windows.
- **The scan hub example workflow and the fleet `CronJob` patterns** are documented
  setups, not tested ones.
- **Live per-scan progress in the War Room** is not built.

[DEPLOY.md](DEPLOY.md#what-is-and-is-not-verified) has the same accounting for each way
of running Achilles.
