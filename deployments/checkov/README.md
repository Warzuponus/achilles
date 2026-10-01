# Checkov (Infrastructure-as-Code static analysis)

[Checkov](https://www.checkov.io/) scans IaC — CloudFormation,
Kubernetes, Helm, ARM, Dockerfile, and more — for misconfigurations. **License:
Apache-2.0** — fully commercial-safe, invoked as a separate-process container.

## Role

A **second IaC scanner** alongside Trivy. Trivy runs in the default profile;
Checkov adds Checkov's own large policy set (the two overlap but each finds
things the other doesn't). Checkov is opt-in via the `full` profile.

## Why a custom image (not the official one)

Checkov is SARIF-native, so no normalizer is needed. But the official
`bridgecrew/checkov` image's entrypoint is a wrapper script (`/entrypoint.sh`),
which makes Achilles's argument handling ambiguous. We build a slim image with a
direct `checkov` entrypoint and a pinned version instead.

## Output

With `-o sarif --output-file-path <dir>`, Checkov writes a fixed-name
`results_sarif.sarif` into that directory (that's the file Achilles reads).

## Build

```bash
docker build -t achilles/checkov:3.3.8 deployments/checkov
```

Verified end-to-end in the `tier2-verify` CI workflow against an infrastructure-as-code
sample with misconfigured resources.
