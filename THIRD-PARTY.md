# Third-Party Components

Achilles is licensed under **Apache-2.0**. It orchestrates third-party
open-source scanners and depends on third-party Go libraries. This file records
their licenses and how Achilles uses them.

## The AGPL / copyleft process-boundary rule

Some scanners (e.g. **ShellCheck**, GPL-3.0, or **TruffleHog**, AGPL-3.0, if you add
it) are strong-copyleft. Achilles invokes such tools **only as separate processes in
their own container** — never by importing them as libraries. Arm's-length process invocation is "mere
aggregation" and does not impose the tool's copyleft on Achilles. The
[license-check CI workflow](.github/workflows/license-check.yml) enforces this:
it fails the build if any Go dependency is copyleft (AGPL/GPL/LGPL) via
`go-licenses check --disallowed_types=forbidden,restricted` (also `make
license-check`). Permissive (MIT/Apache/BSD) and weak/file-level copyleft (MPL)
imports are allowed.

> This is engineering guidance, not legal advice. Obtain legal review before
> redistributing Achilles inside a commercial product.

## What the downloadable `achilles` binary bundles (and what it fetches)

The release archives (`.goreleaser.yaml`) contain only Achilles itself, built from
this repository, plus its Go library dependencies (permissive licenses; see the
license check above). **No third-party scanner is included.** Embedded in the
binary: `configs/tools.yaml` and the Achilles-authored rules in `configs/rules/`
(original work, Apache-2.0).

Every archive carries `LICENSE`, `NOTICE`, this file, and `third_party/licenses/`:
the license (and any NOTICE or PATENTS file) of each Go module linked into the
binaries, and of the Go standard library, copied unchanged from the module.
`make licenses` regenerates that directory and CI fails if it does not match the
modules in `go.mod`.

`achilles tools install` downloads, on the user's machine and from the upstream
project, the unmodified release assets listed in
`internal/toolchain/manifest.go` (the same versions as the container image below),
each verified against a pinned sha256 before it is unpacked. Those tools keep their
own licenses and run only as separate processes.

One tool in that manifest is opt-in and is not in the container image:
[zizmor](https://github.com/zizmorcore/zizmor) 1.30.1 (MIT), installed only by
`achilles tools install zizmor` and run only with `--with zizmor`.

`achilles tools install rules` downloads the community
[opengrep-rules](https://github.com/opengrep/opengrep-rules) pack at a pinned commit
(security rules for the main languages only). It is the Semgrep rules, **LGPL-2.1
with a Commons Clause** that forbids selling the rules (including hosting or
consulting whose value derives substantially from them). It is therefore never
embedded, committed or redistributed by Achilles, and Achilles does not load it
under `--mode commercial`. Review the `LICENSE` file installed alongside the rules
before using it in a paid service.

## Redistributed binaries in the container image

The all-in-one image (`deployments/achilles/Dockerfile`, published to GHCR) bundles
these **unmodified upstream release binaries**, each pinned by version and sha256 and
run only as a separate process:

| Binary | Version | License | Upstream (source) |
|--------|---------|---------|-------------------|
| Opengrep | v1.25.0 | LGPL-2.1 | <https://github.com/opengrep/opengrep> |
| Trivy | 0.72.0 | Apache-2.0 | <https://github.com/aquasecurity/trivy> |
| Gitleaks | 8.30.1 | MIT | <https://github.com/gitleaks/gitleaks> |
| gosec | v2.27.1 | Apache-2.0 | <https://github.com/securego/gosec> |
| OSV-Scanner | v2.4.0 | Apache-2.0 | <https://github.com/google/osv-scanner> |
| Go toolchain (full variant) | 1.27.1 | BSD-3-Clause | <https://go.dev> |

Their complete corresponding source is available at the upstream locations above for
the pinned versions. The image carries the license texts with the binaries:

| Path in the image | What |
|---|---|
| `/usr/share/doc/achilles/{LICENSE,NOTICE,THIRD-PARTY.md}` | Achilles itself |
| `/usr/share/doc/achilles/licenses/achilles/` | the Go modules linked into the Achilles binaries (the same `third_party/licenses/` as the archives) |
| `/usr/share/doc/achilles/licenses/opengrep/` | the LGPL-2.1 text, and `SOURCE.md` naming the exact release asset and source commit of the unmodified binary |
| `/usr/share/doc/achilles/licenses/{trivy,gitleaks}/` | the `LICENSE` from each project's own release archive |
| `/usr/share/doc/achilles/licenses/{gosec,osv-scanner}/` | each tool's license and those of every module linked into it (both are built from source in the image) |
| `/usr/local/go/LICENSE` | the Go toolchain (full variant) |
| `/usr/share/doc/*/copyright` | the Debian base image's packages |

Opengrep is LGPL-2.1 and the image redistributes its binary. The license text and a
pointer to the exact source travel with it, and the binary is unmodified, but whether
pointing at the upstream repository satisfies the license's source requirement for
your distribution is a legal question this file does not settle. If you redistribute
the image, consider mirroring the Opengrep source for the pinned tag alongside it.

## Scanner tools (invoked as external processes / containers)

| Tool | License | Commercial-safe | Invocation | Notes |
|------|---------|-----------------|------------|-------|
| Opengrep | LGPL-2.1 | Yes | container/CLI | Primary multi-language SAST engine |
| gosec | Apache-2.0 | Yes | container/CLI | Go SAST (SARIF) |
| Bandit | Apache-2.0 | Yes (separate process) | container/CLI | Python SAST; Achilles-built image (deployments/bandit); native JSON normalized (SARIF formatter crashes outside a git repo) |
| Trivy | Apache-2.0 | Yes | container/CLI | SCA / IaC / secrets / misconfig (SARIF) |
| Checkov | Apache-2.0 | Yes (separate process) | container/CLI | 2nd IaC scanner (CloudFormation/K8s/Helm/…); Achilles-built image (deployments/checkov), SARIF-native |
| Gitleaks | MIT | Yes | container/CLI | Secrets |
| TruffleHog | **AGPL-3.0** | Yes, **process-boundary only** | container/CLI | Candidate; **not shipped and not in `configs/tools.yaml`**. If you add it, run it only as a separate process; never linked |
| ShellCheck | **GPL-3.0** | Yes, **process-boundary only** | container/CLI | Shell (sh/bash) SAST; Achilles-built image (deployments/shellcheck), native JSON normalized; never linked |
| Syft | Apache-2.0 | Yes (separate process) | container/CLI | SBOM generator (CycloneDX); Achilles-built image (deployments/syft); backs `--sbom` (artifact, not findings) |
| Grype | Apache-2.0 | Yes | container/CLI | SCA (candidate; not yet wired) |
| OSV-Scanner | Apache-2.0 | Yes | container/CLI | SCA |
| govulncheck | BSD-3-Clause | Yes (separate process) | container/CLI | Go reachability-aware dep vulns; Achilles-built image (deployments/govulncheck), SARIF-native |
| SpotBugs + Find Security Bugs | LGPL-2.1 | Yes (separate process) | container/CLI | JVM bytecode taint analysis; Achilles-built image (deployments/spotbugs-findsecbugs) |
| Psalm | MIT | Yes | container/CLI | PHP taint analysis; Achilles-built image (deployments/psalm) |
| Security Code Scan | LGPL-3.0 | Yes (separate process) | container/CLI | .NET (C#/VB) SAST; Achilles-built image (deployments/security-code-scan); needs NuGet egress |
| clang-tidy | Apache-2.0 WITH LLVM-exception | Yes | container/CLI | C/C++ SAST; Achilles-built image (deployments/clang-tidy); SARIF via clang-tidy-sarif |
| clang-tidy-sarif (sarif-rs) | MIT | Yes | container/CLI | Converts clang-tidy output → SARIF |
| KICS | Apache-2.0 | Yes | container/CLI | IaC (candidate; not yet wired) |
| Railroader | MIT | Yes (separate process) | container/CLI | Ruby/Rails SAST (MIT Brakeman fork); Achilles-built image (deployments/railroader); native JSON normalized |
| Brakeman | Brakeman Public Use License | **No** | — | Not wired. Free to scan your own code; commercial use needs a paid license, so it is excluded from commercial-mode |
| CodeQL | GitHub terms | Customer code needs paid license | — | BYO-license opt-in only |

## Go library dependencies

Enforced by the license-check CI workflow: all imports must be permissive or MPL
(no AGPL/GPL/LGPL). Direct dependencies:

| Module | License | Use |
|--------|---------|-----|
| gopkg.in/yaml.v3 | MIT / Apache-2.0 | parse `configs/tools.yaml` |
| github.com/philippgille/chromem-go | MPL-2.0 | embedded vector store (RAG) |
| github.com/jackc/pgx/v5 | MIT | PostgreSQL vault backend |

MPL-2.0 (chromem-go) is weak/file-level copyleft: fine to import for a commercial
product (obligations cover only the MPL-licensed files, whose source is public).

(Regenerate this section as dependencies change. A `go-licenses` check runs in CI:
see `.github/workflows/license-check.yml`.)
