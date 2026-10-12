# Achilles — govulncheck (Go vulnerability scanner, BSD-3-Clause). Fully
# commercial-safe. Reachability-aware: reports which vulnerable symbols the code
# actually calls, not just which vulnerable modules are in go.mod.
#
# govulncheck writes SARIF to stdout (no -o flag) and needs the Go toolchain to
# analyze source, so we ship it on a Go base with a small wrapper that redirects
# to the output file.
#
# Build:
#   docker build -t achilles/govulncheck:1.6.0 deployments/govulncheck
FROM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602
# Pinned by digest so a rebuild gets the same base; Dependabot proposes updates.

ARG GOVULNCHECK_VERSION=v1.6.0
RUN go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

# scan.sh <src-root> <out-sarif>. Needs network at scan time (vuln DB + modules).
ENTRYPOINT ["/usr/local/bin/scan.sh"]
