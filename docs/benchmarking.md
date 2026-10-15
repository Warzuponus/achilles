# Benchmarking detection

Achilles has two measurements, and they answer different questions:

| Benchmark | Question | Needs |
|---|---|---|
| Triage eval (`evals/triage`, `--mode context\|verdict`) | Given a finding, does the AI layer judge it correctly? | a model (verdict) or nothing (context) |
| **Detection benchmark** (`evals/detect`, `--mode detect`) | Of the vulnerabilities that are really in this code, how many does a scan report — and for the ones it misses, where were they lost? | the real scanners; a model only with `--ai` / `--judge` |

A vulnerability that no scanner reports never reaches triage, so a strong triage
score says nothing about it. Detection recall is the number that bounds everything
downstream. The approach — a labeled corpus of known vulnerabilities, deterministic
matching with an optional model judge, and loss-point analysis of the misses — is
adapted from the open-source VulnHunter project's benchmark harness; the schema,
matcher and prompts here are our own.

## Running it

```bash
make eval-detect                                    # scorecard on the committed fixtures
make eval-detect-gate                               # same, exit non-zero if recall regressed
make eval-detect DETECT_ARGS="--out evals/detect/baseline.json"   # refresh the baseline
```

Both targets build `bin/achilles` first and benchmark that binary. They are **not**
part of CI: they need the real scanners on `PATH` (`opengrep`, `gosec`, `gitleaks`,
`osv-scanner`, and `trivy` for the default registry), and `osv-scanner` queries the
OSV database over the network.

Directly:

```bash
go run ./cmd/achilles-eval --mode detect --verbose \
    --out run.json --markdown run.md \
    --baseline evals/detect/baseline.json --fail-on-regression
```

| Flag | Meaning |
|---|---|
| `--ground-truth PATH` | A target file or a directory of them (default `evals/detect/ground_truth`). `*.example.json` files are skipped in a directory. |
| `--detect-target a,b` | Run only these target ids. |
| `--achilles-bin PATH` | The binary to benchmark. Default: `./bin/achilles`, then `achilles` on `PATH`, else built from `./cmd/achilles` into the cache dir. |
| `--cache-dir DIR` | Where git targets are checked out (default `.achilles/detect-cache`). |
| `--line-tolerance N` | Lines a finding may sit outside a labeled range (default 3). |
| `--exclude`, `--no-default-excludes`, `--diff`, `--scan-baseline`, `--scan-config` | Passed to `achilles`, and understood by the loss-point analysis (a drop caused by them is named). |
| `--scan-arg ARG` | Any other `achilles` flag, repeatable. The analysis does not know what it does. |
| `--scan-timeout D` | Per-scan timeout (default 20m). |
| `--ai` | Also score the AI-reviewed result (see below). Needs `--llm-model` or `--model-config`, and a key; takes `--llm-base-url`, `--llm-provider`, `--llm-auth`, `--llm-judge-model`, `--llm-no-code`. |
| `--judge` | Let a model adjudicate same-place findings whose class/CWE disagrees. Reported separately; never use it in a gate. |
| `--repeat N` | Run the benchmark N times and report which entries flap. |
| `--out FILE` / `--markdown FILE` | Write the JSON scorecard / a Markdown report. `--out` carries run history forward from the file it overwrites when the configuration is unchanged (`--no-history` to skip). |
| `--baseline FILE` | Compare against an earlier JSON scorecard. |
| `--fail-on-regression` | With `--baseline`: exit non-zero if overall or any class's recall dropped by more than `--regression-tolerance` (default 0.02, i.e. 2 points). Entry flips are printed but do not fail the gate by themselves: scanners and advisory data move. |
| `--require-complete` | Exit non-zero if any scanner failed or was missing on any target. |

## Reading the scorecard

**Recall** is detected / scored entries. Entries whose label does not fit the
checkout (file missing, line past the end) are `invalid` and left out, not counted
as misses.

**Incomplete** means a scanner failed or was not installed on that target. The
recall there is a lower bound on what the scanners can do, not a measurement of
their reach. A missing scanner is a loss point (`tool-missing`) so an environment
gap cannot pass as a clean miss. On a machine without `trivy`, every target is
incomplete under the default registry; install it, or pass `--scan-config` with a
registry of the tools you actually run.

**Loss points** (the `lossPoints` histogram and the trace under each miss) say where
a miss was lost. They are derived from the scan's own artifacts, not from a
re-implementation of the pipeline:

- the SARIF report says what survived, and what the AI review suppressed;
- the Evidence Vault says which scanners produced output, which failed (the
  diagnostics record), every finding **before** the noise/baseline/diff filters,
  and the AI verdicts with their reasoning.

| If the loss point is... | the fix is probably... |
|---|---|
| `not-detected` | a rule: no scanner that covers this class reported anything nearby |
| `no-coverage` | a scanner: nothing that ran covers this language/class |
| `tool-missing` / `scan-incomplete` | the environment, before reading anything into the number |
| `class-mismatch` / `line-mismatch` | the label or the rule's metadata (try `--judge` to see which) |
| `noise-filter` | decide whether that path should be in scope; adjust `--exclude` or the label |
| `ai-dismissed` | the triage prompt, context or model: the trace has the verdict and its reasoning |

**Precision proxy.** The benchmark labels known vulnerabilities, not every line of
code, so a finding outside the labels is *unlabeled*, not a false positive. The
scorecard reports findings that matched a label, findings in labeled files that
matched none, and findings in files with no label. Use the triage eval for false-
positive behavior.

**With `--ai`** each target is scanned twice: with `--keep-dismissed` (what the
scanners found, verdicts attached) and without (what the AI review let through).
Recall is scored on the second; the first is reported beside it, and the gap is what
the AI review cost. It is real model spend, twice per target.

## The committed baseline

`evals/detect/baseline.json` was generated on the maintainer's machine with all five
default scanners installed (`opengrep`, `gosec`, `gitleaks`, `osv-scanner`, `trivy`)
and **`--mode commercial`**, so only the built-in Achilles rules were loaded, not the
community pack (3 runs; no entry flapped):

| | Recall |
|---|---|
| **Overall** | **91.7%** (22 of 24) |
| injection | 87.5% (7 of 8) |
| hardcoded-secret | 100% (5 of 5) |
| path-traversal, ssrf, weak-crypto, vulnerable-dependency | 100% (2 of 2 each) |
| xss, deserialization | 100% (1 of 1 each) |
| authz | 0% (0 of 1) |

| Target | Recall |
|---|---|
| go-service | 100% (6 of 6) |
| deps-manifest | 100% (2 of 2) |
| secrets-config | 100% (3 of 3) |
| py-webapp | 88% (7 of 8) |
| js-express | 80% (4 of 5) |

Loss points of the 2 misses: `not-detected` 1 (`JS-IDOR-1`), `noise-filter` 1
(`PY-THIRDPARTY-EVAL-1`).

The previous baseline, with only three built-in rules, was 45.8% (11 of 24); the
community pack took it to 75%. The rules in `configs/rules/achilles-*.yaml` account
for the difference, and every finding they added is on a labeled issue: the count of
findings in labeled files that matched no label did not grow. The scan surfaces 61
findings: 37 on a labeled issue and 24 elsewhere in the labeled files (unlabeled, not
necessarily false; see the precision proxy above). Before Achilles dropped repeated
scanner results (osv-scanner reports some advisories several times) and the two
credential rules were tightened, the same scan counted 85.

How to read it honestly:

- **The new rules were written with these fixtures in view.** They target the
  vulnerability classes in the fixtures, and the rule tests
  (`internal/config/testdata/rules/`) hold their own true and false cases, but a
  benchmark the rules were tuned on overstates what they catch elsewhere. Treat 91.7%
  as "the classes in the benchmark are covered", not as an estimate of real-world
  recall; external targets (below) are the stronger evidence.
- **The `noise-filter` miss is deliberate**: a `third_party/` file the default noise
  filter drops, kept to exercise that loss point.
- **`JS-IDOR-1` is a business-logic flaw** (no ownership check) that no pattern
  scanner is expected to find. The AI review and the research agents are the parts
  of Achilles that can.
- **24 entries is small.** One entry is 4.2 points, which is why the gate tolerance
  is 2 points: any lost entry fails it. It catches regressions in rules and tool
  wiring; it cannot rank two scanners that differ by a few points.
- The fixtures were written and labeled **before** looking at scanner output, but
  by the people who maintain the scanners.
- `deps-manifest` depends on live OSV advisory data. The two labeled advisories are
  long-standing, but a future database change could still move that target.

## Precision of the built-in rules on real code

The benchmark measures recall on code written to be vulnerable. To see what the
built-in rules (`configs/rules/achilles-*.yaml`) report on code nobody wrote for
them, they were run on their own, with no other scanner and no AI review, over a Go
module cache: 98,048 files of third-party code (the Azure, AWS and Google Cloud SDKs,
Kubernetes and kind, Envoy's control plane, goreleaser, the Go toolchain's own
sources, golang.org/x/tools and others), mostly Go, with JavaScript, Python, YAML and
JSON alongside. The files are what `go mod download` fetched for this repository's
tools; the run was on 2026-10-14 with Opengrep 1.25.0.

| | First run | After the fixes |
|---|---|---|
| Findings outside test paths | 349 | 86 |
| ...of which not what the rule is for | about 260 | 2 |
| Findings in test paths (`_test.go`, `testdata/`, `fixtures/`, ...) | 101 | 97 |

"Test paths" is a path heuristic. The 86 that remain outside it are mostly sample
secrets in test helpers it does not catch (gosec's own `testutils/g101_samples.go`
accounts for 43, webhook libraries' test keys for 9). Then come credentials in CI and
docker-compose files, `new Function()` and `localStorage`-to-`innerHTML` in
golang.org/x/tools' slide viewer, `exec()` of generated validator code, and code
compiled at runtime inside a vendored jQuery. The two wrong ones are an example
access token in a doc comment and a URL in a comment. (A third, the string of
value names Go's `stringer` writes into a `_<type>_name` constant, is now excluded
too.) The hits in test paths are mostly cryptographic test
vectors (private keys and shared secrets in the Go toolchain's `testdata/`), which
the secret rule is right about and which are not secrets anyone needs to rotate.
Achilles does not drop test code by default, since a real credential can sit there.

What the first run found, all fixed and pinned by `ok:` cases in
`internal/config/testdata/rules/`:

- `dom-xss` flagged every `innerHTML` assigned from a variable. Pages build their own
  HTML all the time, so it is now a taint rule: only data from the URL, referrer,
  cookies, `window.name`, web storage or `postMessage` counts.
- `hardcoded-secret` flagged identifiers that only look like secrets: enum values
  (`"ClientSecretCredential"`), header names (`"X-Amz-Security-Token"`), paths and
  gRPC method names, dotted names, `__Placeholder__` values, truncated examples,
  public key tokens, and Swagger example values. The first version of the fix also
  dropped the benchmark's `"hunter2-admin-pass"`, which the benchmark gate caught:
  the identifier exclusion now needs an upper-case letter, a `/` or a `.` in the
  value, as every identifier it was written for had.
- `credentials-in-url` flagged documentation of the URL syntax
  (`[username[:password]@]`) and `REDACTED:REDACTED`.
- One exclusion pattern backtracked past PCRE's limit on a long string such as
  `"application/vnd.github.giant-sentry-fist-preview+json"`, and Opengrep then
  dropped that exclusion for the whole file. It is rewritten with unambiguous,
  possessive quantifiers, and the test file carries the string that set it off.

This is precision only on code like this: no Ruby, PHP or Java application was in
the set, and a module cache has little web-request handling, so the taint rules
were barely exercised. It says nothing about recall.

## The built-in rules on deliberately vulnerable applications

The module cache above says little about web code. For that, the built-in rules
were run on their own, with Opengrep's intra-file taint on as Achilles runs it, over
five public training applications, shallow clones of their default branches on
2026-10-14:

| Application | Language | Commit |
|---|---|---|
| [OWASP RailsGoat](https://github.com/OWASP/railsgoat) | Ruby on Rails | `f5951f1` |
| [DVWA](https://github.com/digininja/DVWA) | PHP | `068d974` |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | Node.js | `c5cb68a` |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | Python (Django, Flask) | `19d17cc` |
| [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | Java (Spring) | `e7b1313` |

Every finding was read and judged by hand: a real flaw in the application, wrong
(the rule's claim does not hold), or in a vendored minified library or a test.

| | First run | After the fixes below |
|---|---|---|
| Findings | 134 | 144 |
| Real flaws | 112 | 136 |
| Wrong | 18 | 4 |
| In vendored minified code or tests | 4 | 4 |

The four still wrong: DVWA's "impossible" command-injection level, which validates
each octet of the address in branches the rule cannot follow (2); a DVWA page that
looks a file up in its own table by the requested key; and an `api_key` in a comment
in a vendored JavaScript gallery in RailsGoat.

What the first run got wrong or missed, and what changed:

- `java.ssrf` treated building a `URI` as making a request. WebGoat builds URIs from
  input to parse them and to set `Location` headers; 11 of its 12 findings were
  that. The sinks are now the calls that fetch (`new URL`, `HttpRequest`,
  `RestTemplate`, `WebClient`, Jsoup, Apache HttpClient, JAX-RS).
- WebGoat's SQL lessons pass the request parameter to a helper that builds and runs
  the query, and taint stopped at the call. Achilles now runs Opengrep with
  `--taint-intrafile`, which follows taint between functions in the same file: ten
  SQL-injection lessons, Zip Slip and the SSRF lesson were found that were not
  before. It costs time: 18s to 28s on WebGoat, and 192s to 481s on the 98,048-file
  module cache.
- Queries built in a variable and run later (WebGoat, PyGoat's `objects.raw()`), a
  RailsGoat `select("#{col}")`, a shell command interpolated in a Rails model from a
  value passed in by a controller, `params[:user].to_unsafe_h`, and NodeGoat's
  MongoDB `$where` were all missed; each now has a rule or pattern.
- Views were not scanned at all. An ERB rule now reports `raw`, `html_safe` and
  `<%==` on a value (RailsGoat's annotated header XSS and cookie XSS).
- `eval("...")` and `Function("...")` of a string literal, and a `prepareStatement`
  of two literals joined, were reported.

Still missed, and why: DVWA builds its XSS and file-inclusion output in one file and
echoes or includes it in another, and the rules follow taint within a file only.
DVWA's medium SQL-injection level escapes the input with `mysqli_real_escape_string`
but uses it unquoted, and the rule takes the escape as a fix. Its high level reads
the input from the session. RailsGoat's DOM XSS lives in inline scripts in ERB
templates. Business-logic flaws (access control, IDOR, CSRF, password reset logic),
ReDoS and vulnerable dependencies are for the AI review, the dependency scanners or
nobody: no pattern rule finds them.

None of these applications has a complete list of its flaws in a form that can be
scored, so this gives no recall figure. It shows what the rules report on real
application code, and that what they report is almost always right.

## External targets

Point the benchmark at pinned commits of public intentionally-vulnerable apps (OWASP
Juice Shop, NodeGoat, WebGoat) with `evals/detect/ground_truth/external.example.json`
as the template. The example carries no real commit SHA and the runner refuses it,
with instructions, until you pin one and verify every label against that commit. See
`evals/detect/README.md` for the steps.

## Ideas this does not do

- It does not label false positives; see the triage eval.
- It scores one finding to one label by location. It does not do taint-path
  matching, and it does not try to credit a scanner for finding "the same bug via a
  different sink".
- The loss-point analysis can only say what the scan's artifacts record. Flags it
  does not know about (`--scan-arg`) are reported as `dropped-unknown`, not guessed.
