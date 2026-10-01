# Tier-2 verification harness

End-to-end proof for the scanners that need a language runtime + a built image
and so can't be verified on a plain dev laptop: **SpotBugs + find-sec-bugs** (JVM)
and **Psalm** (PHP). For each, the harness builds the image, runs a known-vulnerable
sample **through Achilles** (`--runner docker`), and asserts the expected finding
surfaces in the normalized SARIF.

```bash
make verify-tier2                 # both
verify/tier2/verify.sh psalm      # one
```

Requires only **docker + go + python3** — no host JVM or PHP (the Java sample is
compiled inside a JDK container). It runs in CI via
[.github/workflows/tier2-verify.yml](../../.github/workflows/tier2-verify.yml)
on GitHub's Docker-enabled runners, which is where these tools actually get proven.

## Layout
```
verify/tier2/
├── verify.sh                      the harness
├── findsecbugs.yaml               enables just findsecbugs (argv mirrors configs/tools.yaml)
├── psalm.yaml                     enables just psalm
├── findsecbugs/sample/Vuln.java   JDBC SQL injection → expect SQL_INJECTION_JDBC
└── psalm/sample/                  $_GET → mysqli::query → expect TaintedSql
    ├── psalm.xml
    └── src/vuln.php
```

## What a pass means
`PASS[findsecbugs]` / `PASS[psalm]` means the whole path works: config → generic
adapter → pinned image → tool → SARIF → normalize → report. Once green in CI, the
tool can be flipped to `enabled: true` in `configs/tools.yaml` with confidence.

If a run FAILs, the CI log shows the tool's real output — the test loop that lets
these get fixed without a local Docker/JVM/PHP setup.
