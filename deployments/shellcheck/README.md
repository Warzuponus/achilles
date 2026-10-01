# ShellCheck (shell script static analysis)

[ShellCheck](https://www.shellcheck.net/) finds bugs and security issues in
shell scripts (sh/bash). **License: GPL-3.0** — invoked **strictly as a
separate-process container, never linked**, which keeps it commercial-safe (same
posture as TruffleHog; see [THIRD-PARTY.md](../../THIRD-PARTY.md)).

## Why a custom image + JSON + wrapper

- ShellCheck has **no SARIF** formatter, so Achilles runs `-f json` and
  normalizes it (`internal/normalize/shellcheck.go`, `format: shellcheck`).
- ShellCheck takes **files, not a directory**, and writes JSON to **stdout**, so
  `scan.sh` discovers `*.sh`/`*.bash` under the source root and redirects to the
  output file.
- The image installs the **pinned upstream static binary** (verified by sha256)
  on a Debian base that provides `bash` + `find`.

## Build

```bash
docker build -t achilles/shellcheck:0.11.0 deployments/shellcheck
```

Verified end-to-end in the `tier2-verify` CI workflow against a script with
unquoted-variable issues (SC2086).
