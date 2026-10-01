# SpotBugs + Find Security Bugs (JVM SAST)

Real **taint/dataflow** analysis for JVM languages (Java, Kotlin, Scala, Groovy)
— the depth Opengrep's pattern rules can't reach. LGPL-2.1, invoked as a separate
process, so it's commercial-safe (same posture as Opengrep). Emits SARIF 2.1.0.

## Why a Dockerfile (not a pinned public image)
find-sec-bugs ships as a `findsecbugs-cli` bundle (SpotBugs + plugin + a launcher)
that needs a JRE — there's no clean public container. So Achilles bundles it here.

```bash
docker build -t achilles/findsecbugs:1.14.0 deployments/spotbugs-findsecbugs
```

## ⚠️ It analyzes compiled bytecode, not source
SpotBugs reads `.class`/`.jar` files. **Build the project first**, then scan the
tree containing the build output:

```bash
mvn -q compile          # or: gradle classes
achilles --runner docker --config configs/tools.yaml .   # findsecbugs enabled
```

Scanning un-built source produces **zero** findings (nothing to analyze). This is
inherent to bytecode SAST; in CI, add a compile step before the scan.

## Enabling it
It's declared **disabled** in [configs/tools.yaml](../../configs/tools.yaml)
(`id: findsecbugs`). Flip `enabled: true` after you've built the image. The
effective command (via the `findsecbugs.sh` launcher, which preloads the plugin)
is:

```
findsecbugs.sh -effort:max -sarif=<out>/results.sarif <target>
```
(No `-textui`: the launcher already selects the text UI on a headless host;
passing it reaches the arg parser as an unknown option.)

## ✓ Verified end-to-end in CI
Proven by the [tier2-verify workflow](../../.github/workflows/tier2-verify.yml)
(`PASS[findsecbugs]`) — a JDBC SQLi sample is compiled and flagged through the
full Achilles path. To reproduce locally (`make verify-tier2`) or by hand:

1. `docker build -t achilles/findsecbugs:1.14.0 deployments/spotbugs-findsecbugs`
2. Compile a tiny vulnerable sample (e.g. a JDBC string-concatenation SQLi).
3. `docker run --rm -v "$PWD:/src:ro" -v "$PWD/out:/out" achilles/findsecbugs:1.14.0 -effort:max -sarif=/out/results.sarif /src`
4. Confirm `out/results.sarif` is valid SARIF with a finding (e.g. `SQL_INJECTION_JDBC`).
5. Then enable it in `configs/tools.yaml` and confirm Achilles normalizes it.

Pinned versions: SpotBugs 4.9.3, find-sec-bugs plugin 1.14.0
(`findsecbugs-cli-1.14.0.zip`, sha256 `ff546e16…`).
