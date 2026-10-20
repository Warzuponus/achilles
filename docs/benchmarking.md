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

That is precision: what the rules report on real application code, and that what
they report is almost always right. Recall on the same applications is next.

## Recall on the same applications

[`evals/detect/real-apps/`](../evals/detect/real-apps/README.md) labels the documented
vulnerabilities of the five applications above, at the same commits: 270 in all,
written from each application's own lessons, help pages and wiki before any scan
output was looked at. They include flaws no pattern rule can find (access control,
CSRF, authentication logic, information disclosure), so the overall figure is the
share of everything documented, not of what a scanner could reach.

Measured on 2026-10-18 with the binary scanners (Opengrep, gitleaks, osv-scanner,
Trivy; no Docker, so none of the Tier-2 tools) and AI review off. "Own rules" is
`--mode commercial`; "with community rules" is the default `--mode oss`.

| | Own rules, before | Own rules, after | With community rules, before | With community rules, after |
|---|---|---|---|---|
| **Overall** | **23.3%** (63) | **30.7%** (83) | **30.7%** (83) | **35.9%** (97) |
| Injection (61) | 31 | 33 | 36 | 36 |
| XSS (28) | 3 | 11 | 10 | 15 |
| Path traversal (11) | 4 | 4 | 4 | 4 |
| Weak crypto (21) | 5 | 6 | 7 | 8 |
| Hard-coded secret (12) | 1 | 3 | 1 | 3 |
| Open redirect (10) | 5 | 7 | 6 | 7 |
| Deserialization (6) | 5 | 6 | 5 | 6 |
| XXE (5) | 1 | 2 | 1 | 2 |
| File upload (3) | 0 | 3 | 0 | 3 |
| SSRF (4) | 3 | 3 | 3 | 3 |
| Access control, authentication, CSRF, info disclosure, misconfiguration, other (102) | 3 | 3 | 6 | 6 |

"After" is with the rules added on 2026-10-18: Python SQL injection by taint and
reflected XSS, Django and Jinja `|safe` and `autoescape off`, hard-coded Flask, Django
and JWT signing keys, Python XXE, Java open redirect and XStream, PHP HTML built from
request data, uploads saved under the client's file name and ECB/DES ciphers, and
JavaScript template engines with escaping off.

Read it with these limits in mind:

- **The "after" columns are in-sample.** The rules were written while reading these
  applications' misses. They are general patterns, not app-specific ones, but recall
  on code they were not written against will be lower than the gain here suggests.
- **Precision held.** With own rules only, the new rules added 52 findings to the five
  apps, 20 of them on labels. The rest were read by hand: nearly all are real flaws
  the labels do not list (request data in DVWA's HTML, `$_SERVER['PHP_SELF']` in form
  actions, DVWA's view-source page reflecting `id`). Two were wrong: command output
  and a username echoed on DVWA's "impossible" levels, which validate the input in
  ways the rule cannot follow.
- **What is still missed, by cause:** taint that crosses files (WebGoat's command
  injection runs in a service class the controller calls; DVWA includes the page
  chosen in another file); SQL escaped but used unquoted (DVWA medium); Opengrep
  dropping a second identical sink after a `switch` `break` (DVWA's SQLite branches);
  DOM XSS in inline `<script>` blocks; hard-coded passwords too short or plain to
  tell from test data; and logic flaws, which are for the AI review (`--hunt`) or a
  person.

## The OWASP Benchmark for Java

The [OWASP Benchmark](https://owasp.org/www-project-benchmark/) is 2,740 small Java
servlets in 11 categories, each either a real vulnerability (1,415) or a decoy built
to look like one (1,325), with an answer key. Its scorecard flags a test case when a
tool reports a finding with the category's CWE anywhere in that case's file, and
scores each category as true-positive rate minus false-positive rate: 0 is what
flagging at random gets, 100 is perfect. Because it has decoys, it measures false
positives as well as recall, which the vulnerable-app labels above cannot.

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava   # about 76 MB
go run ./cmd/achilles-eval --mode owasp --owasp-dir BenchmarkJava
```

Measured on 2026-10-18 at commit `bc5ffeb` with the binary scanners (no Docker, so
no SpotBugs/find-sec-bugs) and AI review off:

| | Recall | Decoys flagged | Score |
|---|---|---|---|
| Own rules, before (`--mode commercial`) | 11.6% | 6.9% | **4.7** |
| Own rules, after the 2026-10-18/19 Java rules | 90.6% | 20.9% | **69.7** |
| With community rules (`--mode oss`), before | 90.9% | 24.6% | 66.3 |
| With community rules, after | 94.0% | 26.9% | 67.1 |
| Own rules, after the 2026-10-20 weak-randomness fix | 91.3% | 20.1% | **71.2** |
| With community rules, after that fix | 94.0% | 26.1% | 67.9 |

The last two rows come from [the comparison with other tools](comparison.md), which
also explains the fix. All three columns are averages over the 11 categories, as the scorecard reports
them.

How to read it:

- **The "before" row is the out-of-sample result**, and it was poor: Achilles' own
  Java rules found SQL and command injection only. They missed classes written out
  in full (`new java.io.File(...)`, `java.security.MessageDigest`), and had no rule
  at all for XSS, LDAP or XPath injection, weak randomness, insecure cookies or trust
  boundaries.
- **The "after" rows are in-sample**: the new rules were written after reading the
  Benchmark's cases. They are general (each sink is a standard API, each source the
  servlet or Spring request), and on the five vulnerable apps above they added seven
  findings, all real (secrets and tokens drawn from `java.util.Random`), and one more
  labeled flaw, not a flood. But do not read 69.7 as what they score on code
  they were not written against.
- **Where the false positives come from:** most decoys keep the input out of the sink
  through a branch that is never taken (`if (7 * 42 - 106 > 200) bar = param;`) or a
  map key that is never read. A taint engine without constant folding follows both
  paths, so SQL injection (62.9% of decoys flagged), path traversal (32.6%) and trust
  boundaries (46.5%) score lowest. The AI review is meant for exactly this; it is not
  measured here.
- **Hashing** reads the algorithm name from a properties file in a third of its real
  cases, which no static rule can see (69% recall, 0% false positives).

### The Python edition

[BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) (version 0.1,
2026) is the same idea for Flask: 1,230 cases in 14 categories, 452 of them real. The
same command scores it (`--owasp-dir BenchmarkPython`). Measured on 2026-10-19 at
commit `f129148`, binary scanners, AI review off:

| | Recall | Decoys flagged | Score |
|---|---|---|---|
| Own rules, before (`--mode commercial`) | 31.5% | 12.0% | **19.5** |
| Own rules, after the 2026-10-19 Python rules | 69.1% | 18.8% | **50.3** |
| With community rules (`--mode oss`), before | 45.3% | 27.0% | 18.3 |
| With community rules, after | 75.2% | 33.4% | 41.8 |

- **"Before" is out of sample again**, and it showed the same kind of gap as Java:
  nothing for LDAP or XPath injection, open redirects, weak randomness, insecure
  cookies, trust boundaries or a Flask view that returns request data as HTML; and
  `codecs.open` and `pathlib`'s `/` were not path sinks. Achilles' Python rules had
  been written against PyGoat (Django), which has few of these.
- **"After" is in-sample.** On the five vulnerable apps the Python changes added six
  findings, all real (`eval` of request data in two PyGoat labs, three cookies set with
  `secure=False`, a one-time code from `random.randint`), and lost none.
- **The community pack adds recall and more false positives** here: with it, a third of
  the decoys are flagged and the score is lower than the own rules alone.
- **Still weak:** command injection (the few real cases pass the input through a
  helper in another file), code injection and XPath (decoys that keep the input out
  through a branch never taken), and path traversal through the Benchmark's helper
  classes.

Two things found on the way apply to every Python taint rule. Opengrep drops taint
across a slice (`request.args["q"][:100]` is clean to it; an index, `[0]`, is not),
so truncated input is missed. And `metavariable-regex` is anchored at the start of
the value, so a check meant to find a word inside a name has to begin with `.*`; three
rules got that wrong and are fixed, among them the JavaScript XSS rule's check for an
escaping function (`DOMPurify.sanitize` and `_.escape` were not recognized).

Opengrep's results vary slightly from run to run: one community-pack finding in
NodeGoat appeared in one of two identical scans, which moves the five-app figure with
the community pack between 35.6% and 35.9%. `achilles-eval --repeat` measures this.

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
