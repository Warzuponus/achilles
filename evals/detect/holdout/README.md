# Held-out recall labels

Ground truth for applications that **no rule has been written against**. The five
apps in [`../real-apps/`](../real-apps/README.md) and OWASP Juice Shop are in-sample
now: rules were added after reading their misses, so their recall flatters the rules.
This set is there to say how the rules do on code they have not seen.

```bash
make build && ./bin/achilles tools install
go run ./cmd/achilles-eval --mode detect --ground-truth evals/detect/holdout \
  --scan-arg=--mode --scan-arg=commercial --markdown holdout.md   # own rules only
go run ./cmd/achilles-eval --mode detect --ground-truth evals/detect/holdout \
  --markdown holdout-oss.md                                       # with community rules
```

| File | Application | Commit | Labels |
|---|---|---|---|
| `dvna.json` | [DVNA](https://github.com/appsecco/dvna) (Node.js, Express, EJS) | `9ba473a` | 23 |
| `vampi.json` | [VAmPI](https://github.com/erev0s/VAmPI) (Python, Flask, connexion) | `f16052d` | 8 |

## The rule for this directory

- **Do not write or widen a rule after reading a miss here.** Record the gap, fix it
  from other code if it is a general pattern, and say in the change that the held-out
  set was looked at. Once a rule change was made because of what this set showed, the
  set is in-sample: move its files to `../real-apps/` and add a new held-out app.
- **Fixing a false positive is allowed.** Removing a wrong finding does not raise
  recall, so it does not spend the set. Say so in the change.
- **The labels are not changed after a scan,** except to fix a wrong line against the
  pinned commit. A label that a scanner reports somewhere else is a miss, not a label
  to move.

## How the labels were made

Same selection rule as `../real-apps/`: every flaw that the application's own
documentation describes and that has a specific location in the source.

- **DVNA:** the solution guide in `docs/solution/*.md`, one entry per sink it shows,
  checked against the pinned commit and the fix commits the guide links. Left out:
  the vulnerable `mathjs` version (a dependency, A9) and insufficient logging (A10),
  which have no location. The stack-trace entry is at the same `mathjs.eval` call the
  A9 page uses.
- **VAmPI:** the README's list of vulnerabilities, at the code the in-source comments
  mark (`# SQLi Injection`, `# Regex DoS`, ...). Left out: lack of rate limiting,
  which has no location. `debug=True` in `app.py` and the plaintext passwords are real
  but not documented as flaws, so they are not labelled.
- The labels were committed before any scanner was run on either app.

## Results

Measured on 2026-11-10 with Opengrep 1.25.0, gitleaks, osv-scanner and Trivy (no
Docker, so no Tier-2 tools), AI review off. See
[docs/benchmarking.md](../../../docs/benchmarking.md#held-out-applications) for the
reading.

| | Own rules | With community rules |
|---|---|---|
| **Overall** | **16.1%** (5 of 31) | **38.7%** (12 of 31) |
| DVNA | 4 of 23 | 11 of 23 |
| VAmPI | 1 of 8 | 1 of 8 |
