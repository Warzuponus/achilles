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

Achilles is local-first and links no cloud SDKs. `make check-deps` asserts that
`go.mod` contains no cloud SDK modules — run it if you touch vault or LLM wiring or
add a dependency.

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
3. Dry run: Actions → Release → Run workflow builds every archive without publishing.
4. Tag and push: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. A tag with a
   suffix (`vX.Y.Z-rc1`) is a pre-release and does not move `latest`.
5. Check what users will run: `VERSION=vX.Y.Z sh scripts/install.sh` on a clean machine,
   `docker run --rm ghcr.io/warzuponus/achilles achilles --version`, and the example
   workflow pinned at the new tag.

Never move a tag that has been published. If a release is wrong, cut the next patch
version.

## Reporting bugs and security issues

Bugs and ideas: open an issue with how to reproduce it. **Security vulnerabilities:
do not open an issue** — see [SECURITY.md](SECURITY.md).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
