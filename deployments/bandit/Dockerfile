# Achilles — Bandit (Python SAST, Apache-2.0). Fully commercial-safe.
#
# Bandit has no official container and its SARIF formatter needs a git repo (it
# crashes outside one), so Achilles runs `bandit -f json` and normalizes the
# native JSON itself (internal/normalize/bandit.go). This image is just a pinned
# Bandit on a slim Python base.
#
# Build:
#   docker build -t achilles/bandit:1.9.4 deployments/bandit
FROM python:3.12-slim
# TODO: pin the base image by digest before release.

ARG BANDIT_VERSION=1.9.4
RUN pip install --no-cache-dir "bandit==${BANDIT_VERSION}"

# Callers pass Bandit flags, e.g.:
#   -r /mnt/src -f json -o /mnt/out/results.json
# Bandit exits non-zero when it finds issues; Achilles keys success on the output
# file existing, not the exit code.
ENTRYPOINT ["bandit"]
