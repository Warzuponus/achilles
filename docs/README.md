# Achilles User Guides

Task-oriented guides for **using** Achilles. For *why* it's built the way it is
see [DESIGN.md](../DESIGN.md); for the ways to run it (workstation, containers, GitHub Actions,
scheduled scans) see [DEPLOY.md](../DEPLOY.md); for contributing see [ONBOARDING.md](../ONBOARDING.md).

| Guide | Read it when you want to… |
|-------|---------------------------|
| [Getting Started](getting-started.md) | install Achilles, run your first scan, and understand the core knobs (profiles, license mode, runners, the vault) |
| [CLI Reference](cli-reference.md) | look up every flag, grouped by task, with copy-paste examples |
| [Reports & Gating](reports-and-gating.md) | choose an output format (HTML/SARIF/JUnit/Markdown), gate CI on new findings, and cut noise with baselines + diff-aware scans |
| [LLM Triage & Agents](llm-and-agents.md) | turn on LLM triage/judge/remediation, run the review / SCA-advice / threat-model agents, and route each task to a different model (any OpenAI-compatible endpoint, incl. Ollama) |
| [Deep Verification](deep-verify.md) | let the model read the repository (bounded, read-only) to settle the findings a single-file review could not |
| [Verifying Fixes](verifying-fixes.md) | understand how proposed patches are re-scanned before `--fix-pr` or an issue calls them verified |
| [Benchmarking Detection](benchmarking.md) | measure how much of a known-vulnerable codebase Achilles actually finds, and where each miss was lost |
| [CI & the Scan Hub](ci-and-hub.md) | wire Achilles into GitHub Actions — a per-PR gate, a routed full scan, or a central hub that scans other repos |
| [Fleet](fleet.md) | scan many of your repos from one command into per-project vaults |
| [Running in containers](containers.md) | run Achilles with Docker Compose or Kubernetes: the all-in-one image, PostgreSQL, the War Room (and its no-authentication security model), recurring scans, and local models |

## Prefer HTML?

These guides are also rendered as a single self-contained page:
[`docs/site.html`](site.html) — open it in a browser (sidebar nav, no external
assets). Rebuild it after editing any guide with `make docs-html` (needs
`pip install markdown`); the generator is [`docs/build.py`](build.py).

## The 30-second version

```bash
make build                          # -> bin/achilles
achilles /path/to/code              # scan with the default toolset, print a report
achilles --html-report report.html --fail-on high /path/to/code
```

**One rule that trips everyone up:** flags must come **before** the target path
(`achilles --profile full ./src`, not `achilles ./src --profile full`). Achilles
uses Go's stdlib `flag`, which stops parsing at the first positional argument.
