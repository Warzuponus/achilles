# clang-tidy (C/C++ static analysis)

C/C++ diagnostics (security, bug-prone patterns, CERT rules) via clang-tidy.
clang-tidy is **Apache-2.0 WITH LLVM-exception**; the SARIF converter
(`clang-tidy-sarif`, sarif-rs) is **MIT** — both run as separate processes, so
commercial-safe. clang-tidy has no native SARIF, so the image pipes it through
`clang-tidy-sarif`.

## Build
```bash
docker build -t achilles/clang-tidy:18 deployments/clang-tidy
```

## Notes / requirements
- **No network at scan time** — works under strict-containment (unlike the .NET/SCA tools).
- **clang-tidy takes files, not a directory** — `analyze.sh` discovers `.c/.cc/.cpp/.cxx`.
- **Compile database**: for real projects, generate `compile_commands.json`
  (`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, or `bear -- make`) at the source
  root; the wrapper uses it (`-p`). Without one, it analyzes with clang defaults
  (fine for simple sources, less accurate for code with heavy include/flag needs).
- Checks enabled: `clang-analyzer-*,bugprone-*,cert-*`.

## Enabling it
Declared **disabled** in [configs/tools.yaml](../../configs/tools.yaml)
(`id: clang-tidy`). Flip `enabled: true` after building the image.

## ✓ Verified end-to-end in CI
Proven by the [tier2-verify workflow](../../.github/workflows/tier2-verify.yml)
(`PASS[clang-tidy]`) — a C sample calling `system()` is flagged (`cert-env33-c`)
through the full Achilles path. `make verify-tier2` reproduces it on a Docker host.

Pinned: clang-tidy-sarif 0.8.0 (sha256 `7198518c…`); clang-tidy from Ubuntu 24.04.
