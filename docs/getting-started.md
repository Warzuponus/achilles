# Getting Started

This gets you from an empty shell to a scan you understand.

## 1. Install

Achilles is a single Go binary (Go 1.26, no cgo).

```bash
git clone https://github.com/Warzuponus/achilles.git && cd achilles
make build            # -> bin/achilles
sudo cp bin/achilles /usr/local/bin/   # optional: put it on PATH
```

Verify the spine without installing any scanners — this ingests an existing SARIF
file and runs the normalize → report path:

```bash
achilles --from-sarif internal/normalize/testdata/sample.sarif
```

## 2. Get the scanners on PATH

A real scan shells out to scanner tools. The **default profile** uses five:

| Tool | Covers | Install |
|------|--------|---------|
| Opengrep | multi-language patterns | `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh \| bash` |
| gosec | Go SAST | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| osv-scanner | dependency CVEs (SCA) | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` |
| Trivy | IaC / misconfig / secrets / SCA | [install script](https://github.com/aquasecurity/trivy) |
| Gitleaks | secret scanning | [release binary](https://github.com/gitleaks/gitleaks/releases) |

Missing tools **degrade gracefully** — Achilles skips them and scans with what's
present (it doesn't fail the run). To avoid installing anything, run everything in
containers instead: add `--runner docker` (uses the pinned images in
`configs/tools.yaml`). *Exception:* Opengrep has no public image and always runs
as a local binary, so keep it on PATH even in docker mode.

## 3. Your first scan

```bash
achilles /path/to/code
```

You'll get a human-readable report on stdout: the tools that ran, a per-severity
count, and each finding with its rule, location, and message. The run is also
recorded to the **Evidence Vault** at `.achilles/vault.jsonl`.

Write a shareable report instead of (or as well as) the terminal output:

```bash
achilles --html-report report.html /path/to/code   # open report.html in a browser
```

## 4. The core knobs

- **`--profile default|full`** — `default` is the five baseline tools above.
  `full` adds the heavy per-language analyzers (JVM/PHP/.NET/C++), which need
  their prebuilt images + language prerequisites (see `deployments/<tool>/`).
- **`--mode oss|commercial`** — the license gate. `commercial` (the strict one)
  refuses any tool not marked `commercialSafe`, so you can safely run on customer
  code. `oss` allows everything. Default is `oss`.
- **`--runner local|docker`** — run tools as binaries on PATH, or as pinned
  containers. Docker mode needs a Docker daemon.
- **`--vault <path>`** — where the append-only Evidence Vault is written
  (`.achilles/vault.jsonl` by default). It's the audit trail, the reproducibility
  record, and the learning corpus. Use `--vault-backend postgres` (any PostgreSQL,
  DSN in `$ACHILLES_VAULT_DSN`) when several processes — scans and the War Room —
  should share one store (see [Running in containers](containers.md)).
- **`--timeout 5m`** — overall scan timeout. Raise it for large repos or slow
  LLM steps.

## 5. Reading results & failing a build

By default Achilles **reports** but exits 0. To make it **gate**:

```bash
achilles --fail-on high /path/to/code    # exit 1 if any finding is >= high
```

To fail only on *newly introduced* findings (the usual CI setup), pair it with a
baseline or a diff — see [Reports & Gating](reports-and-gating.md).

## Where to go next

- Add AI verification + fix advice → [LLM Triage & Agents](llm-and-agents.md)
- Run it in CI → [CI & the Scan Hub](ci-and-hub.md)
- Every flag with examples → [CLI Reference](cli-reference.md)
