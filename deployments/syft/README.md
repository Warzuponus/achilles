# Syft (SBOM generator)

[Syft](https://github.com/anchore/syft) generates a Software Bill of Materials
(SBOM) — an inventory of the packages/dependencies in a project or image.
**License: Apache-2.0** — fully commercial-safe, invoked as a separate-process
container.

## Role — an artifact, not findings

Syft does **not** find vulnerabilities; it produces a **CycloneDX SBOM**, which
is a supply-chain / compliance deliverable. In Achilles it backs the
`--sbom <path>` feature: it runs outside the scan→normalize pipeline, writes the
SBOM to the given path, and records it to the Evidence Vault (`KindSBOM`).
Vulnerability detection stays with Trivy / OSV-Scanner / govulncheck.

## Build

```bash
docker build -t achilles/syft:1.46.0 deployments/syft
```

Usage (via Achilles):

```bash
achilles --runner docker --sbom sbom.json /path/to/project
```

Verified end-to-end in the `tier2-verify` CI workflow against a project with
Go + npm manifests (the SBOM lists their components).
