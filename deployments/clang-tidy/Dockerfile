# Achilles — clang-tidy (C/C++ static analysis). clang-tidy is Apache-2.0 WITH
# LLVM exception; the SARIF converter (clang-tidy-sarif, sarif-rs) is MIT. Both
# invoked as separate processes → commercial-safe. clang-tidy has no native SARIF,
# so we pipe its output through clang-tidy-sarif.
#
# Build:
#   docker build -t achilles/clang-tidy:18 deployments/clang-tidy
#
# Notes:
#   * No network needed at scan time (works under strict-containment).
#   * clang-tidy takes FILES, not a directory, and wants a compile database for
#     real projects — the wrapper (analyze.sh) discovers sources and uses
#     compile_commands.json if present, else clang defaults.
FROM ubuntu:24.04
# TODO: pin the base image by digest before release.

RUN apt-get update \
 && apt-get install -y --no-install-recommends clang-tidy clang curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG CTS_VERSION=0.8.0
ARG CTS_SHA256=7198518c1d01830cf368c5f924df5ac177ce5ada4f6f54bcc4a1dd8841d07202
RUN curl -fsSL -o /usr/local/bin/clang-tidy-sarif \
      "https://github.com/psastras/sarif-rs/releases/download/clang-tidy-sarif-v${CTS_VERSION}/clang-tidy-sarif-x86_64-unknown-linux-gnu" \
 && echo "${CTS_SHA256}  /usr/local/bin/clang-tidy-sarif" | sha256sum -c - \
 && chmod +x /usr/local/bin/clang-tidy-sarif

COPY analyze.sh /usr/local/bin/analyze.sh
RUN chmod +x /usr/local/bin/analyze.sh

# analyze.sh <src-root> <out-sarif> [extra clang-tidy args]
ENTRYPOINT ["/usr/local/bin/analyze.sh"]
