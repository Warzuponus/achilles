# Achilles — Syft (SBOM generator, Apache-2.0). Fully commercial-safe, invoked as
# a separate-process container. Syft produces a CycloneDX software bill of
# materials (a package inventory), NOT security findings — it backs the
# `--sbom <path>` feature, not the scan/normalize pipeline.
#
# Installs the pinned upstream static binary (sha256-verified). No network needed
# at scan time (offline directory cataloging).
#
# Build:
#   docker build -t achilles/syft:1.46.0 deployments/syft
FROM debian:bookworm-slim
# TODO: pin the base image by digest before release.

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG SYFT_VERSION=1.46.0
ARG SYFT_SHA256=d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca
RUN curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
 && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/syft.tar.gz -C /tmp syft \
 && mv /tmp/syft /usr/local/bin/syft \
 && rm -f /tmp/syft.tar.gz

# Callers pass Syft args, e.g.:
#   scan dir:/mnt/src -o cyclonedx-json=/mnt/out/sbom.json -q
ENTRYPOINT ["syft"]
