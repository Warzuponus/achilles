# Contributing to Achilles

Thanks for helping. This is a small project with a high bar for correctness: a security
tool that quietly misses things is worse than none. The habits below exist for that.

## Getting set up

```bash
go version          # Go 1.27
make build          # -> bin/achilles (and friends: go build ./cmd/...)
go test ./...       # hermetic; no network, no API keys, no database required
```

Optional, for the pieces that need infrastructure (they skip themselves when absent):

- **PostgreSQL vault tests:** run a throwaway Postgres and set
  `ACHILLES_TEST_POSTGRES_DSN` (the command is at the top of
  `internal/vault/postgres_test.go`). CI runs them against a service container.
- **The container quickstart:** `deploy/compose/smoke.sh` (needs Docker).
- **The history scan against the real gitleaks:** `achilles tools install gitleaks`,
  then `go test -tags integration ./cmd/achilles -run History`. The same for the
  opt-in workflow scanner: `achilles tools install zizmor`, then `-run Zizmor`.

**What CI runs, and when.** A pull request gets the Linux build and tests (with the
race detector), the linter, `govulncheck`, the license check, the self-scan and the
composite action. Three heavier jobs are kept off pull requests because every minute
is billed while the repository is private:

- the **Windows** tests run on every push to `main`, and on demand: Actions -> CI ->
  Run workflow, on your branch. Do that for a change that touches file paths, file
  locking or process handling;
- the **container quickstart** runs on a pull request only when the image, the
  compose files or the sample change, and on `main` for any code change;
- **Tier-2 verify** runs on `main` when a tool image or the registry changes, and on
  demand.

A newer push to a pull request cancels the run of the older one.

Achilles is local-first and links no cloud SDKs. `make check-deps` asserts that
`go.mod` contains no cloud SDK modules — run it if you touch vault or LLM wiring or
add a dependency.

## Where things are

```
cmd/achilles          the CLI: flags, the scan pipeline, reports, GitHub integrations
cmd/achillesd         the War Room HTTP server
cmd/achilles-fleet    scans many projects and targets into per-project vaults
cmd/achilles-eval     the eval CLI (context, verdict, corpus and detect modes)

configs/              tools.yaml (the tool registry) and the built-in Opengrep rules
                      (configs/rules/achilles-*.yaml), both embedded in the binary
internal/config       loads the tool registry
internal/policy       the license-mode gate (oss, commercial, attestation)
internal/toolchain    `achilles tools install`: pinned, checksum-verified scanners
internal/exec         runs a tool as a local binary or in a container
internal/scanner      the scanner interface and registry
  generic             config-driven adapter for any tool that emits SARIF
  opengrep            the one hand-written adapter
internal/normalize    tool output (SARIF and a few native formats) → findings
internal/model        the finding, verdict and SARIF types
internal/noise        drops vendored, generated and minified files
internal/baseline     known findings, so a gate fails only on new ones
internal/vcs          changed files for --diff
internal/correlate    groups one defect reported by several tools

internal/enrich       adds the code around a finding for the model
internal/redact       masks credentials before text leaves the machine
internal/triage       the model review, the adversarial judge, fix suggestions
  llm                 the OpenAI-compatible client and per-task routing
  llm/llmtest         a fake client for hermetic tests
internal/deep         --deep-verify: bounded, read-only repository lookups
internal/verifyfix    re-scans a proposed fix; the scope rule for what a fix may touch
internal/cost         the pre-flight cost estimate (--dry-run, --max-cost)
internal/knowledge    feedback, calibration and retrieval of past verdicts
internal/review       the repo-level security review
internal/advisor      the dependency-upgrade plan
internal/threatmodel  the threat-model agent
internal/inventory    languages and dependencies of a codebase
internal/research     research agents and rule synthesis (experimental)

internal/report       human, HTML, Markdown, SARIF and JUnit output
internal/issues       files and maintains GitHub issues
internal/github       the small GitHub REST client
internal/gitops       the git steps behind --fix-pr
internal/vault        the Evidence Vault (file and PostgreSQL)
internal/metrics      rollups over the vault
internal/tenant       the project registry for the War Room
internal/server       the War Room: handlers, templates, redaction
internal/fleet        fleet config, planning and dispatch
internal/eval         the eval harness

evals/                the labeled triage corpus and the detection benchmark
deployments/          Dockerfiles: the all-in-one image and the --profile full tools
deploy/compose/       the compose stack and its smoke test
examples/             example workflows and a small vulnerable sample
third_party/licenses  license texts shipped with the binaries (generated: make licenses)
```

## Making a change

1. Keep it small and focused. Follow the conventions of the code around it.
2. **Prove it works.** Add the smallest test that would have caught the bug or that pins
   the new behavior. For anything that guards a boundary (Host and cross-origin checks, project
   isolation, credential scrubbing, fail-closed behavior), also check that the test fails when the
   guard is broken — temporarily break it, watch the test fail, restore it.
3. Run `gofmt -l .` (must print nothing), `go vet ./...`, `go test ./...`.
4. Update the docs in `docs/` if behavior or flags change, then `make docs-html` (needs
   `pip install markdown`) to regenerate `docs/site.html`.
5. Sign off your commits (below) and open a pull request describing what changed and
   how you verified it.

### Developer Certificate of Origin

Contributions are accepted under the project's [Apache-2.0](LICENSE) license. By
signing off a commit you certify the [DCO](https://developercertificate.org/): that you
wrote the change or have the right to submit it under this license.

```bash
git commit -s -m "fix: describe the change"     # adds: Signed-off-by: Your Name <you@example.com>
```

## Writing a built-in rule

The built-in Opengrep rules are in `configs/rules/achilles-<language>.yaml`, and every
one of them needs test cases in `internal/config/testdata/rules/` (a file with the same
name as the rule file, any extension). Mark each line that must fire with a
`# ruleid: <rule id>` comment on the line above, and the near misses that must not with
`# ok: <rule id>`. A rule earns its place by catching something real with few false
positives, so the `ok:` cases matter as much as the `ruleid:` ones.

```bash
achilles tools install opengrep
go test -tags integration -run TestRules ./internal/config
```

The test fails on a wrong match and on a rule with no case at all; CI runs it with the
pinned Opengrep. Opengrep reads rule files as ASCII and does not support YAML anchors,
and a pattern containing `: ` must be quoted. Rules are original work under the project's
license: do not copy a rule from a pack with another license. To see what a rule change
does to detection, run the benchmark (`go run ./cmd/achilles-eval --mode detect`, see
[evals/detect](evals/detect)).

## Self-scan and the baseline

Achilles scans its own code in CI and gates on findings that are **not** in
`.achilles/baseline.json`. If your change introduces a finding:

- **Fix it** if you can. That is almost always right.
- If it is genuinely acceptable, explain why in the PR and regenerate the baseline (the
  command is at the top of `.github/workflows/self-scan.yml`).

A baseline entry is a fingerprint of `tool | rule | normalized code snippet`, so it
suppresses that *pattern* wherever it appears — not just at one line. Only accept
something you would also accept if the same code showed up in another package. Do not
"fix" this by adding the location to the fingerprint; that would invalidate every
baseline and feedback label at once.

## Things that bite

- **A feature keyed on a data field is inert if nothing populates the field.** Test with
  production-shaped input, not only hand-written fixtures, and measure how many real
  records the feature actually applies to.
- **Measure the outcome, not the mechanism.** Wider LLM context that moves a proxy metric
  but not the number of decidable cases did not help. The eval harness (`evals/`) exists
  for this; use it when you change prompts or context.
- **Failures must be loud.** A scanner that cannot run, a vault write that fails, a
  credential that is missing: each must surface as an error or a clear warning, never as
  an empty or "clean" result.
- **Secrets never go in argv, URLs, logs or the vault.** Pass them through the
  environment and scrub them from error text.

## Releasing (maintainers)

A release is a pushed tag. `release.yml` builds and signs the archives and creates the
GitHub Release; `release-images.yml` publishes the images.

1. `main` is green, including the self-scan, and `CHANGELOG.md` has a dated section
   for the version (move the entries out of `[Unreleased]`).
2. If a dependency changed: `make licenses`, commit, and re-check `THIRD-PARTY.md`.
   If a bundled scanner version changed, update it in `configs/tools.yaml`,
   `internal/toolchain/manifest.go`, the Dockerfile and (for Opengrep)
   `deployments/achilles/licenses/opengrep/SOURCE.md` together.
3. If `docs/` changed since the last release, regenerate the HTML guide and commit it:
   `make docs-html` (needs Python and `pip install markdown`).
4. Dry run: Actions → Release → Run workflow builds every archive without publishing.
5. Tag and push: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. A tag with a
   suffix (`vX.Y.Z-rc1`) is a pre-release and does not move `latest`.
6. Check what users will run: `VERSION=vX.Y.Z sh scripts/install.sh` on a clean machine,
   `docker run --rm ghcr.io/warzuponus/achilles achilles --version`, and the example
   workflow pinned at the new tag.

Never move a tag that has been published. If a release is wrong, cut the next patch
version.

## Reporting bugs and security issues

Bugs and ideas: open an issue with how to reproduce it. **Security vulnerabilities:
do not open an issue** — see [SECURITY.md](SECURITY.md).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
