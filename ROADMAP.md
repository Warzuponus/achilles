# Roadmap

Where Achilles is and where it is going. What has shipped is recorded in detail in
the [CHANGELOG](CHANGELOG.md); the architecture is in [DESIGN.md](DESIGN.md); what
has and has not been tested is in [TEST_PLAN.md](TEST_PLAN.md). Nothing below is a
promise of a date.

Last reviewed: 2026-11-09, against `main` after #55.

## Where it stands

The latest release is **v0.3.1** (2026-10-19). Since then a large set of changes has
merged to `main` and is waiting for **v0.4.0** (see Unreleased in the CHANGELOG).

| Release | Date | Headline |
|---|---|---|
| v0.1.0 | 2026-10-12 | First public release: five scanners, AI review with an adversarial judge, fix verification by re-scan, baselines and diff gating, the GitHub Action and issue filing, the Evidence Vault, the War Room and the fleet dispatcher |
| v0.2.0 | 2026-10-14 | `achilles init`, 62 built-in rules in every licence mode, inline suppressions, the MCP server, secret scanning of git history |
| v0.3.0 | 2026-10-18 | First recall figure on real code (five vulnerable apps), taint between functions, ERB templates, the native Anthropic client, GitLab dependency reports |
| v0.3.1 | 2026-10-19 | Own rules rebuilt from the OWASP Benchmark (Java 4.7 to 69.7, Python 19.5 to 50.3), GitLab checked on gitlab.com, Windows long-path fix |
| Unreleased | | See below |

### Merged since v0.3.1

- **Out-of-sample evaluation on OWASP Juice Shop** (`achilles-eval --mode
  juice-shop`): 5 of 13 reachable challenges at 63% precision before, 12 of 13 at 73%
  after the new rules (in-sample). #50
- **Comparison with other open-source SAST tools** on the OWASP Benchmark (Semgrep CE,
  Bearer, Find Security Bugs, Bandit), reproducible with `evals/compare/run.sh`. #51
- **Clearer AI verdicts** from Cloudflare's security-audit skill: hardening notes,
  needs-validation questions, attacker, impact and an assessed severity, cited-line
  checks, and a blind-judge eval mode. #52
- **Source-to-sink paths, a regression test with every fix, rules for code that calls
  AI models, and hunt mode** (`--hunt`, experimental). #53
- **Live tests for the native Anthropic client** and a structured-output schema fix. #49
- **Pre-scan modelling, milestones 1 and 2:** the surface map with risk-ordered review
  (`--prioritize surface`, `--plan-out`), and the threat-context file with scan depth
  and a tool plan that skips scanners with nothing to analyze. #54, #55

## Next: v0.4.0

These are what stand between `main` and the next release.

- [x] **Re-run the verdict eval on the current prompt** (`triage/v8`) with a real
  model, with and without `--blind-judge`, and record it in `evals/`. Done
  2026-11-10: 94.4% balanced accuracy either way, no genuine issue dismissed, and
  no genuine issue called hardening ([evals/README.md](evals/README.md#measured-triagev8-2026-11-10)).
  The run also found that fixture paths leaked the label; fixtures are now staged.
- [ ] **Confirm `minimax-m3.1-flash` for the triage seat.** It scored 100% in one
  staged run at about a third of `minimax-m2.7`'s price. Re-run with `--repeat 5`
  before changing `configs/models.ollama.yaml`.
- [x] **Run the surface map and tool plan on a few real repositories** and check that
  no scanner is skipped that had something to find. Done on 19 repositories across
  Go, Python, JavaScript, Java, PHP, Ruby, C#, C and Terraform: the plan skipped
  Checkov on repositories with GitHub workflows and no IaC, where Checkov reports
  workflow findings. Fixed: Checkov now also counts CI pipelines and OpenAPI
  documents. Every other skip was right. See
  [evals/scan-plan](evals/scan-plan/README.md).
- [ ] **Cut v0.4.0:** move Unreleased in the CHANGELOG under a version, bump the
  version in the README, DEPLOY.md and `action.yml` examples, and let the
  release workflows build the binaries and images.

## Planned

Roughly in priority order.

### Accuracy

- **Recall on real code.** The own rules find 35% of the 270 documented
  vulnerabilities in five vulnerable apps (up from 31% on 2026-11-09). Work through
  the misses in [docs/benchmarking.md](docs/benchmarking.md) that a rule can reach;
  most of those left need taint that crosses files.
- **A second out-of-sample target** that no rule was written against, now that Juice
  Shop is in-sample.
- **Tune the surface-map weights** against the detection benchmark; today they are a
  starting point.
- **Measure the AI review on real code**, not only the 18-case corpus.

### Pre-scan modelling (milestone 3 and on)

- An optional, grounded LLM pass that names components and trust zones from the
  surface map.
- Hypothesis checks for missing controls by the deep verifier, advisory until
  verified. See [docs/surface-map.md](docs/surface-map.md#where-this-is-going).

### Experimental to stable

Promote each experimental feature once it has had real-world use. The first
candidates:

- **The `anthropic` provider preset:** its live tests have passed through OpenRouter's
  Messages-compatible endpoint; run them against `api.anthropic.com` itself.
- **`--deep-verify`, `--fix-pr` and the surface map**, after the v0.4.0 checks above.
- **Live GitHub writes** (issue filing, PR comments, `--fix-pr`) checked against a real
  repository, as the GitLab integration was on gitlab.com.

### Coverage and platforms

- **Go 1.27.2 and newer:** gosec cannot read that compiler's export data yet. Track
  upstream and drop the Go 1.27.1 advice when it can.
- **Languages no scanner covers** (Rust, for example): reports already name them; add a
  scanner or rules.
- **macOS in CI.** Release binaries are built for it but tests run on Linux and Windows.
- **Homebrew and Scoop packages** (they need a tap and a bucket repository).

### Platform

- Live per-scan progress in the War Room (the SSE transport exists; the per-scan stream
  does not).
- Performance-based demotion of noisy generated rules (DESIGN §9.4).
- A SQLite vault backend, and content-addressed storage for large raw scanner output.

## Not planned

- **Authentication in the War Room.** It is a local view bound to your own machine by
  design; put it behind your own proxy if you need to share it.
- **A hosted service or a login.** Achilles stays a tool you run yourself.
- **A default model or a shipped price table.** Model names and prices change faster
  than this project.

Ideas and requests are welcome as
[feature requests](.github/ISSUE_TEMPLATE/feature_request.yml).
