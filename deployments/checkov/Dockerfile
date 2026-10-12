# Achilles — Checkov (IaC static analysis, Apache-2.0). Fully commercial-safe,
# invoked as a separate-process container. A second IaC scanner alongside Trivy
# (Terraform, CloudFormation, Kubernetes, Helm, ARM, Dockerfile, …).
#
# Checkov IS SARIF-native, so no normalizer is needed. The official image's
# entrypoint is a wrapper script (/entrypoint.sh); we build our own with a
# direct `checkov` entrypoint so Achilles's arg handling is unambiguous, and to
# pin the version.
#
# Build:
#   docker build -t achilles/checkov:3.3.8 deployments/checkov
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

ARG CHECKOV_VERSION=3.3.8
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"

# Callers pass Checkov flags, e.g.:
#   -d /mnt/src -o sarif --output-file-path /mnt/out --compact --quiet
# With SARIF output + --output-file-path <dir>, Checkov writes a fixed-name
# results_sarif.sarif into that directory. Checkov exits non-zero when it finds
# issues; Achilles keys success on the output file existing, not the exit code.
ENTRYPOINT ["checkov"]
