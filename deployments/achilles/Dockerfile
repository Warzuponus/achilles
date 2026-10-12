# Achilles all-in-one image: the engine, the War Room, the fleet dispatcher AND the
# baseline scanners (Opengrep, gosec, Trivy, Gitleaks, osv-scanner), so a scan runs
# inside the container with `--runner local` — no docker socket, no docker-in-docker.
#
#   docker build -t achilles -f deployments/achilles/Dockerfile .
#   docker run --rm -v "$PWD":/work:ro achilles achilles --runner local /work
#
# For the full stack (War Room + PostgreSQL + a scan) use deploy/compose/.
#
# What is NOT in here: the heavy `--profile full` per-language tools (JVM, PHP, .NET,
# Python, clang). They need their own toolchains; see docs/containers.md.
#
# Supply chain: every downloaded binary is pinned by version AND sha256 and verified
# before it is unpacked. Checksums for Trivy and Gitleaks come from the projects'
# published checksum files; Opengrep publishes none, so its hashes were computed from
# the release asset at pin time (trust-on-first-use) — re-pin them when you bump it.
# Keep these versions in step with action.yml and configs/tools.yaml.

# WITH_GO=true (default) bundles the Go toolchain: gosec type-checks the packages it
# scans through `go`, so without it Go targets get NO gosec coverage (achilles then
# reports gosec as FAILED rather than silently clean — see `requires:` in
# configs/tools.yaml). Build with --build-arg WITH_GO=false for a ~250 MB smaller
# image that does not scan Go.
ARG WITH_GO=true
FROM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS go-true
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS go-false
RUN mkdir -p /usr/local/go
FROM go-${WITH_GO} AS gotoolchain

# ---- build the Go binaries and the two Go-based scanners ------------------------
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG GOSEC_VERSION=v2.27.1
ARG OSV_SCANNER_VERSION=v2.4.0
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags='-s -w' -o /out/achilles       ./cmd/achilles \
 && go build -trimpath -ldflags='-s -w' -o /out/achillesd      ./cmd/achillesd \
 && go build -trimpath -ldflags='-s -w' -o /out/achilles-fleet ./cmd/achilles-fleet \
 && go build -trimpath -ldflags='-s -w' -o /out/achilles-eval  ./cmd/achilles-eval
# `go install` refuses cross-compiled binaries when GOBIN is set, so each scanner is
# built from a throwaway module instead.
RUN set -eux; \
    for spec in "gosec github.com/securego/gosec/v2/cmd/gosec ${GOSEC_VERSION}" \
                "osv-scanner github.com/google/osv-scanner/v2/cmd/osv-scanner ${OSV_SCANNER_VERSION}"; do \
      set -- $spec; \
      mkdir "/tmp/$1" && cd "/tmp/$1"; \
      go mod init "tools/$1" >/dev/null 2>&1; \
      go get "$2@$3"; \
      go build -trimpath -ldflags='-s -w' -o "/out/$1" "$2"; \
    done

# ---- download + verify the non-Go scanners --------------------------------------
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS fetch
ARG TARGETARCH
ARG TRIVY_VERSION=0.72.0
ARG GITLEAKS_VERSION=8.30.1
ARG OPENGREP_VERSION=v1.25.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) TRIVY_ASSET=Linux-64bit; TRIVY_SHA=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea; \
             GL_ASSET=x64;  GL_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb; \
             OG_ASSET=x86;  OG_SHA=9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33 ;; \
      arm64) TRIVY_ASSET=Linux-ARM64; TRIVY_SHA=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467; \
             GL_ASSET=arm64; GL_SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080; \
             OG_ASSET=aarch64; OG_SHA=fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch trivy.tgz    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ASSET}.tar.gz" "$TRIVY_SHA"; \
    fetch gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ASSET}.tar.gz" "$GL_SHA"; \
    fetch opengrep     "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_${OG_ASSET}" "$OG_SHA"; \
    mkdir -p /out; \
    tar -xzf trivy.tgz    -C /out trivy; \
    tar -xzf gitleaks.tgz -C /out gitleaks; \
    install -m 0755 opengrep /out/opengrep

# ---- runtime ---------------------------------------------------------------------
# glibc base: the Opengrep release binary is a manylinux build.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin achilles

COPY --from=build /out/ /usr/local/bin/
COPY --from=fetch /out/ /usr/local/bin/
COPY --from=gotoolchain /usr/local/go /usr/local/go
COPY LICENSE THIRD-PARTY.md /usr/share/doc/achilles/

WORKDIR /app
COPY configs/ /app/configs/
RUN mkdir -p /data /work /out && chown -R achilles:achilles /app /data /out

# Fail closed: a scan whose scanners could not run must not look like a clean pass.
ENV ACHILLES_STRICT_TOOLS=true \
    HOME=/home/achilles \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER achilles

# Fail the build (not the first scan) if a bundled tool did not land.
RUN opengrep --version && trivy --version && gitleaks version && gosec -version \
 && osv-scanner --version \
 && for b in achilles achillesd achilles-fleet achilles-eval; do command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }; done \
 && rm -rf /home/achilles/.cache   # the version probes warm a ~225 MB cache we do not want in the layer

VOLUME ["/data"]
EXPOSE 8080
# No ENTRYPOINT: pick the binary (achilles | achillesd | achilles-fleet | achilles-eval).
CMD ["achilles", "--help"]
