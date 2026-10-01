# Psalm (PHP taint analysis)

Security **taint tracking** for PHP (user input → dangerous sinks: SQLi, XSS,
command injection). MIT-licensed — fully commercial-safe. Emits SARIF 2.1.0.
Source-based (unlike SpotBugs, no compile step needed), but see the config
requirement below.

## Build
```bash
docker build -t achilles/psalm:6.16.1 deployments/psalm
```
Bundles the pinned `psalm.phar` (6.16.1, sha256 `7ace71e4…`) on `php:8.3-cli`
with `ext-mbstring`.

## ⚠️ Needs the project's own psalm.xml
Psalm requires a config file and resolves `<projectFiles>` relative to it, so
Achilles points `--config` at the **target project's** `psalm.xml`. Most
Psalm-using PHP projects have one; a project without it won't scan (the run
errors and degrades to a partial scan). For accurate results, run
`composer install` in the target first so Psalm can resolve types/autoload.

Effective invocation:
```
psalm --config=<src>/psalm.xml --root=<src> --taint-analysis --no-cache --report=<out>/results.sarif
```

## Enabling it
Declared **disabled** in [configs/tools.yaml](../../configs/tools.yaml)
(`id: psalm`). Flip `enabled: true` after building the image and verifying.

## ✓ Verified end-to-end in CI
Proven by the [tier2-verify workflow](../../.github/workflows/tier2-verify.yml)
(`PASS[psalm]`) — a `$_GET → mysqli::query` taint sample is flagged (TaintedSql)
through the full Achilles path. To reproduce locally (`make verify-tier2`) or by hand:

1. `docker build -t achilles/psalm:6.16.1 deployments/psalm`
2. Make a tiny PHP project with a `psalm.xml` and a taint sink, e.g.
   `mysqli_query($db, $_GET['id'])` (unsanitized `$_GET` → SQL sink).
3. `docker run --rm -v "$PWD:/mnt/src:ro" -v "$PWD/out:/mnt/out" achilles/psalm:6.16.1 --config=/mnt/src/psalm.xml --root=/mnt/src --taint-analysis --no-cache --report=/mnt/out/results.sarif`
4. Confirm `out/results.sarif` is valid SARIF with a `TaintedSql`/`TaintedInput` finding.
5. If Psalm can't find the config or the report is empty, the fix is likely a
   working-dir or `--config`/`--root` adjustment (add workdir support to the
   runner). Then enable it in `configs/tools.yaml`.

Pinned: Psalm 6.16.1 (`psalm.phar`, sha256 `7ace71e4f698466e7e16810679a1895ea623060579aff46fcf9fd0f1c09abe00`).
