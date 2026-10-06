# Getting Started

This gets you from an empty shell to a scan you understand.

## 1. Install

Achilles is a single static Go binary (Go 1.27, no cgo). Its tool registry
(`configs/tools.yaml`) and baseline Opengrep rules are **embedded in the binary**, so
it runs from any directory with no repository checkout. Pick one:

**Install script** (Linux and macOS; verifies the release checksum, and the cosign
signature if `cosign` is installed):

```bash
curl -fsSLO https://raw.githubusercontent.com/Warzuponus/achilles/main/scripts/install.sh
less install.sh                                   # read it first
sh install.sh                                     # latest -> ~/.local/bin
VERSION=v0.1.0 INSTALL_DIR=/usr/local/bin sh install.sh
```

**Release binary** — download `achilles_<version>_<os>_<arch>.tar.gz` (`.zip` on
Windows) and `checksums.txt` from the
[Releases page](https://github.com/Warzuponus/achilles/releases), check it with
`sha256sum --check --ignore-missing checksums.txt`, and put `achilles` on your `PATH`.

**Docker** — the all-in-one image already contains the scanners:
`docker run --rm -v "$PWD":/work:ro ghcr.io/warzuponus/achilles achilles --runner local /work`
(see [Running in containers](containers.md)).

**`go install`** — `go install github.com/Warzuponus/achilles/cmd/achilles@latest`
(or `@v0.1.0`; `achilles --version` reports the module version).

**From source** — `git clone https://github.com/Warzuponus/achilles.git && cd achilles && make build`
(binary at `bin/achilles`). *Homebrew and Scoop packages are planned; they need a tap
repository (see the commented blocks in `.goreleaser.yaml`).*

Check it:

```bash
achilles --version
achilles --from-sarif internal/normalize/testdata/sample.sarif   # needs a checkout; no scanners needed
```

## 2. Get the scanners

A real scan shells out to scanner tools. The **default profile** uses five. Let
Achilles fetch them — it downloads the pinned upstream release for your platform,
verifies its sha256 (and refuses to install on a mismatch) and puts it in
`~/.achilles/bin` (override with `$ACHILLES_HOME`):

```bash
achilles tools install      # all five scanners + the community Opengrep rules
achilles doctor             # what is found where, versions vs the pinned ones, fixes
achilles tools list         # pinned versions and what is installed
```

| Tool | Covers | Notes |
|------|--------|-------|
| Opengrep | multi-language patterns | upstream publishes no checksums; the pinned digests were computed at pin time |
| gosec | Go SAST | needs `go` on PATH to type-check packages |
| osv-scanner | dependency CVEs (SCA) | needs network access to the OSV database |
| Trivy | IaC / misconfig / secrets / SCA | |
| Gitleaks | secret scanning | |

**Lookup order.** For each scanner Achilles uses `~/.achilles/bin` first (the pinned,
verified copy), then `PATH`. `achilles doctor` shows which one it found and exits
non-zero if a default-profile scanner is missing, printing the exact fix command.
If upstream publishes no download for your platform, doctor says so and points at the
manual install or the Docker image.

**Rules.** Opengrep's `-f` rules are, in order: the `rules:` directory from your tool
config if it exists on disk (a repo checkout uses `configs/rules`), otherwise the
baseline rules embedded in the binary (materialized into your user cache). The
community rule pack from `achilles tools install rules`
([opengrep-rules](https://github.com/opengrep/opengrep-rules), pinned commit, security
rules for the main languages only, in `~/.achilles/rules/`) is loaded **in addition**
as a second `-f`; the embedded baseline is always the offline fallback. Extra rule
YAML dropped directly into `~/.achilles/rules/` is merged into the embedded baseline.
The community pack is LGPL-2.1 with a **Commons Clause** (no selling), so it is
downloaded on demand, never bundled, and **not loaded under `--mode commercial`**.

A missing scanner is reported, not hidden: the scan prints `N tool(s) FAILED to run`
and lists them (add `--strict-tools` to make that exit 2). To avoid installing
anything, run the tools in containers instead: `--runner docker` (uses the pinned
images in `configs/tools.yaml`). *Exception:* Opengrep has no public image and always
runs as a local binary.

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
