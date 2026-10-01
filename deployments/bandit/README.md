# Bandit (Python SAST)

[Bandit](https://github.com/PyCQA/bandit) is the Python static-analysis security
tool from PyCQA. **License: Apache-2.0** — fully commercial-safe, and invoked as
a separate-process container.

## Why a custom image + JSON (not SARIF)

- There is no official Bandit container image, so we build a pinned one here.
- Bandit's SARIF formatter (`-f sarif`) resolves the repository via git and
  **crashes when run outside a git checkout** (as Achilles does, on a mounted
  read-only source tree). So Achilles runs `bandit -f json` and normalizes the
  native JSON with `internal/normalize/bandit.go` (registered as `format: bandit`).

## Build

```bash
docker build -t achilles/bandit:1.9.4 deployments/bandit
```

## How Achilles invokes it

Disabled by default; enabled in the `full` profile (or a verify config). See the
`bandit` entry in `configs/tools.yaml`:

```
-r {src} -f json -o {out}/results.json
```

Verified end-to-end in the `tier2-verify` CI workflow against a known-vulnerable
Python sample.
