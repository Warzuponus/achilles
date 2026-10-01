# govulncheck (Go vulnerability scanner)

[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) is the
official Go vulnerability scanner. **License: BSD-3-Clause** — fully
commercial-safe, invoked as a separate-process container.

## Why it's valuable

It is **reachability-aware**: rather than flagging every advisory that touches a
module in `go.mod`, it reports which vulnerable symbols the code actually
*calls* (level `error`/`warning`), and separates merely-imported-but-unreachable
ones (level `note`). That is a much lower false-positive rate than plain SCA.

## Why a custom image + wrapper

- govulncheck needs the **Go toolchain** to analyze source, so it ships on a Go
  base image.
- It writes SARIF to **stdout** (there is no `-o` flag), while Achilles reads an
  output file — so `scan.sh` runs it in the module directory and redirects
  stdout to the output SARIF.
- Source mode needs **network** at scan time (the vuln DB at `vuln.go.dev` plus
  the module graph), so the config sets `network: default`.

## Build

```bash
docker build -t achilles/govulncheck:1.6.0 deployments/govulncheck
```

Verified end-to-end in the `tier2-verify` CI workflow against a Go module with a
known reachable vulnerability (`GO-2021-0113` via `golang.org/x/text@v0.3.5`).
