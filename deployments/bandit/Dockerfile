# Achilles — Bandit (Python SAST, Apache-2.0). Fully commercial-safe.
#
# Bandit has no official container and its SARIF formatter needs a git repo (it
# crashes outside one), so Achilles runs `bandit -f json` and normalizes the
# native JSON itself (internal/normalize/bandit.go). This image is just a pinned
# Bandit on a slim Python base.
#
# Build:
#   docker build -t achilles/bandit:1.9.4 deployments/bandit
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

ARG BANDIT_VERSION=1.9.4
RUN pip install --no-cache-dir "bandit==${BANDIT_VERSION}"

# Callers pass Bandit flags, e.g.:
#   -r /mnt/src -f json -o /mnt/out/results.json
# Bandit exits non-zero when it finds issues; Achilles keys success on the output
# file existing, not the exit code.
ENTRYPOINT ["bandit"]
