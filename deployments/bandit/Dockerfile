# Achilles — Bandit (Python SAST, Apache-2.0). Fully commercial-safe.
#
# Bandit has no official container and its SARIF formatter needs a git repo (it
# crashes outside one), so Achilles runs `bandit -f json` and normalizes the
# native JSON itself (internal/normalize/bandit.go). This image is just a pinned
# Bandit on a slim Python base.
#
# Build:
#   docker build -t achilles/bandit:1.9.4 deployments/bandit
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

ARG BANDIT_VERSION=1.9.4
RUN pip install --no-cache-dir "bandit==${BANDIT_VERSION}"

# Callers pass Bandit flags, e.g.:
#   -r /mnt/src -f json -o /mnt/out/results.json
# Bandit exits non-zero when it finds issues; Achilles keys success on the output
# file existing, not the exit code.
ENTRYPOINT ["bandit"]
