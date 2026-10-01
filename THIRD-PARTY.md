# Third-Party Components

Achilles is licensed under **Apache-2.0**. It orchestrates third-party
open-source scanners and depends on third-party Go libraries. This file records
their licenses and how Achilles uses them.

## The AGPL / copyleft process-boundary rule

Some scanners (e.g. **TruffleHog**, AGPL-3.0) are strong-copyleft. Achilles
invokes such tools **only as separate processes in their own container** — never
by importing them as libraries. Arm's-length process invocation is "mere
aggregation" and does not impose the tool's copyleft on Achilles. The
[license-check CI workflow](.github/workflows/license-check.yml) enforces this:
it fails the build if any Go dependency is copyleft (AGPL/GPL/LGPL) via
`go-licenses check --disallowed_types=forbidden,restricted` (also `make
license-check`). Permissive (MIT/Apache/BSD) and weak/file-level copyleft (MPL)
imports are allowed.

> This is engineering guidance, not legal advice. Obtain legal review before
> redistributing Achilles inside a commercial product.

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
| Go toolchain (full variant) | 1.26 | BSD-3-Clause | <https://go.dev> |

Their complete corresponding source is available at the upstream locations above for
the pinned versions; the image also carries this file and `LICENSE` under
`/usr/share/doc/achilles/`. The Debian base image's packages carry their own licenses
in `/usr/share/doc/*/copyright`.

## Scanner tools (invoked as external processes / containers)

| Tool | License | Commercial-safe | Invocation | Notes |
|------|---------|-----------------|------------|-------|
| Opengrep | LGPL-2.1 | Yes | container/CLI | Primary multi-language SAST engine |
| gosec | Apache-2.0 | Yes | container/CLI | Go SAST (SARIF) |
| Bandit | Apache-2.0 | Yes (separate process) | container/CLI | Python SAST; Achilles-built image (deployments/bandit); native JSON normalized (SARIF formatter crashes outside a git repo) |
| Trivy | Apache-2.0 | Yes | container/CLI | SCA / IaC / secrets / misconfig (SARIF) |
| Checkov | Apache-2.0 | Yes (separate process) | container/CLI | 2nd IaC scanner (CloudFormation/K8s/Helm/…); Achilles-built image (deployments/checkov), SARIF-native |
| Gitleaks | MIT | Yes | container/CLI | Secrets |
| TruffleHog | **AGPL-3.0** | Yes, **process-boundary only** | container/CLI | Secrets w/ verification; never linked |
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
| Checkov / KICS | Apache-2.0 | Yes | container/CLI | IaC |
| Railroader | MIT | Yes (separate process) | container/CLI | Ruby/Rails SAST (MIT Brakeman fork); Achilles-built image (deployments/railroader); native JSON normalized |
| Brakeman | CC BY-NC-SA | **No** | — | Excluded from commercial-mode |
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

(Regenerate this section as dependencies change; a `go-licenses`-based check is
planned for CI.)
