# Achilles — ShellCheck (shell script static analysis). ShellCheck is GPL-3.0,
# so it is invoked STRICTLY as a separate-process container and never linked —
# which keeps it commercial-safe (see THIRD-PARTY.md). It has no SARIF formatter,
# so Achilles normalizes its native JSON (internal/normalize/shellcheck.go).
#
# We install the pinned upstream static binary (verified by sha256) on a Debian
# base that has bash + find, plus a wrapper that discovers scripts and redirects
# ShellCheck's stdout JSON to the output file.
#
# Build:
#   docker build -t achilles/shellcheck:0.11.0 deployments/shellcheck
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG SHELLCHECK_VERSION=v0.11.0
ARG SHELLCHECK_SHA256=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6
RUN curl -fsSL -o /tmp/sc.tar.gz \
      "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.gz" \
 && echo "${SHELLCHECK_SHA256}  /tmp/sc.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/sc.tar.gz -C /tmp \
 && mv "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" /usr/local/bin/shellcheck \
 && rm -rf /tmp/sc.tar.gz "/tmp/shellcheck-${SHELLCHECK_VERSION}"

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

# scan.sh <src-root> <out-json>. No network needed (works under strict-containment).
ENTRYPOINT ["/usr/local/bin/scan.sh"]
