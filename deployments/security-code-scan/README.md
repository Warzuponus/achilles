# Security Code Scan (.NET SAST)

Vulnerability detection for C#/VB.NET (SQLi, XSS, XXE, weak crypto, path
traversal, …) via the `security-scan` dotnet global tool. LGPL-3.0 — invoked as a
separate process, so commercial-safe. Emits SARIF 2.1.

## Build
```bash
docker build -t achilles/security-code-scan:5.6.7 deployments/security-code-scan
```

## Requirements (the heaviest of the Tier-2 tools)
`security-scan` loads the project through **MSBuildWorkspace**, which means:
- **Needs the .NET SDK** (in the image).
- **Needs network egress** to restore NuGet packages → the config sets
  `network: default`, so this tool is **incompatible with strict-containment**.
- **Writes `obj/`** during load → the entrypoint (`scan.sh`) copies the read-only
  source to a writable workdir before restoring/scanning.
- **Needs a real project** (`.sln`/`.csproj`/`.vbproj`) — `scan.sh` discovers it.

Effective invocation (via the wrapper):
```
security-scan <discovered-project> --export=<out>/results.sarif --ignore-msbuild-errors
```

## Enabling it
Declared **disabled** in [configs/tools.yaml](../../configs/tools.yaml)
(`id: security-code-scan`). Flip `enabled: true` after building the image.

## ✓ Verified end-to-end in CI
Proven by the [tier2-verify workflow](../../.github/workflows/tier2-verify.yml)
(`PASS[security-code-scan]`) — a dependency-free C# project using `MD5` is flagged
(`SCS0006`, weak hashing) through the full Achilles path. `make verify-tier2`
reproduces it on a Docker host.

Pinned: security-scan 5.6.7 on `mcr.microsoft.com/dotnet/sdk:8.0`.
