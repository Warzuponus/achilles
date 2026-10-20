# Achilles and other open-source SAST tools

How Achilles' rules compare with Semgrep, Bearer, Find Security Bugs and Bandit on
the [OWASP Benchmark](https://owasp.org/www-project-benchmark/), scored the same way,
on the same cases, on the same machine. Every number on this page comes from
[`evals/compare/run.sh`](../evals/compare/run.sh) and
[`evals/compare/tables.sh`](../evals/compare/tables.sh); [Reproduce](#reproduce) has
the commands.

**Read this first: Achilles' scores here are in-sample.** Its Java and Python rules
were rewritten on 2026-10-18/19 after reading these Benchmark cases. Before that,
they scored **4.7** on Java and **19.5** on Python
([Benchmarking](benchmarking.md#the-owasp-benchmark-for-java)), below every other
tool on this page for Java. None of the other tools was tuned on these cases by us.
The new rules are general (standard sinks, standard request sources) and added only
real findings on five deliberately vulnerable apps, but a score on the cases the
rules were written against says less than a score on code they have never seen.

## Results

Measured on 2026-10-20 on a 4-vCPU Linux machine (Intel Xeon, 2.1 GHz, 15 GB). AI
review was off for Achilles: it needs a model and a key, and it is the part meant to
remove decoys, so it is not measured here.

| Benchmark | Tool | Recall | Decoys flagged | Precision | Score | Score, related CWEs | Seconds |
|---|---|---|---|---|---|---|---|
| Java | Achilles, own rules | 91.3 | 20.1 | 81.8 | **71.2** | 71.2 | 66 |
| Java | Achilles, with community rules | 94.0 | 26.1 | 79.0 | **67.9** | 67.9 | 201 |
| Java | Semgrep CE | 79.0 | 44.1 | 66.9 | **34.9** | 44.0 | 72 |
| Java | Bearer | 70.1 | 32.0 | 72.0 | **38.1** | 39.2 | 78 |
| Java | Find Security Bugs | 90.3 | 54.0 | 65.2 | **36.3** | 36.3 | 77 |
| Python | Achilles, own rules | 69.1 | 18.8 | 77.9 | **50.3** | 49.7 | 15 |
| Python | Achilles, with community rules | 75.2 | 33.4 | 71.0 | **41.8** | 40.8 | 128 |
| Python | Semgrep CE | 36.5 | 26.3 | 49.3 | **10.2** | 15.7 | 50 |
| Python | Bearer | 4.0 | 1.2 | 62.5 | **2.8** | 2.8 | 44 |
| Python | Bandit | 25.0 | 15.7 | 81.2 | **9.3** | 16.5 | 4 |

- **Recall** is the share of real vulnerabilities flagged, and **decoys flagged** the
  share of safe look-alikes flagged, both averaged over the categories as the
  Benchmark's scorecard does.
- **Score** is recall minus decoys flagged: 0 is what flagging at random gets, 100 is
  perfect. It counts a finding only when its CWE is the category's, which is the
  Benchmark's own rule.
- **Score, related CWEs** also accepts CWEs that tools commonly report for the same
  flaw (CWE-326 for weak crypto, CWE-327 for a weak hash, and so on). Semgrep and
  Bandit gain the most from it: Semgrep files weak ciphers under CWE-326 and Bandit
  files weak hashes under CWE-327.
- **Precision** is the share of flagged cases that are real, pooled over all cases.
  The scorecard does not report it.
- **Seconds** is wall-clock time for one scan of all cases (2,740 Java, 1,230 Python).
  Achilles' time includes the other scanners it runs on every scan (gitleaks,
  osv-scanner, trivy), which find nothing here. Find Security Bugs' time leaves out
  compiling the Benchmark, which it needs. Times moved by up to a third between
  identical runs (Achilles' own rules on Java took 55 to 82 seconds), so read them as
  rough.

### Score per category

| Java | Achilles own | Achilles + community | Semgrep CE | Bearer | Find Security Bugs |
|---|---|---|---|---|---|
| cmdi/78 | 67.3 | 45.6 | 5.7 | 14.8 | 0 |
| crypto/327 | 100 | 100 | 0 | 76.7 | 100 |
| hash/328 | 69 | 69 | 69 | 69 | 69 |
| ldapi/90 | 67 | 56.3 | 8.8 | 18.1 | 0 |
| pathtraver/22 | 56.1 | 52.6 | 11.7 | 0 | 0 |
| securecookie/614 | 100 | 100 | 100 | 100 | 100 |
| sqli/89 | 30.2 | 30.2 | 19.7 | 5 | 0 |
| trustbound/501 | 40.2 | 40.2 | 9.9 | 3.3 | 0.8 |
| weakrand/330 | 100 | 100 | 100 | 100 | 100 |
| xpathi/643 | 78.3 | 78.3 | 28.3 | 18.3 | 0 |
| xss/79 | 75.1 | 75.1 | 30.4 | 13.7 | 29.7 |

| Python | Achilles own | Achilles + community | Semgrep CE | Bearer | Bandit |
|---|---|---|---|---|---|
| cmdi/78 | **-46.2** | 0 | 0 | 0 | 0 |
| codeinj/94 | 14.7 | 14.7 | 0 | 0 | 0 |
| deserialization/502 | 44.4 | 66.7 | 66.7 | 38.9 | 52.8 |
| hash/328 | 100 | 100 | 0 | 0 | 0 |
| ldapi/90 | 43.8 | 43.8 | 0 | 0 | 0 |
| pathtraver/22 | 31.5 | 31.5 | 1.1 | 0 | 0 |
| redirect/601 | 45.4 | 45.4 | 2.9 | 0 | 0 |
| securecookie/614 | 100 | 0 | 0 | 0 | 0 |
| sqli/89 | 100 | 100 | 100 | 0 | 0 |
| trustbound/501 | 39.2 | 39.2 | 0 | 0 | 0 |
| weakrand/330 | 100 | 100 | 0 | 0 | 77.8 |
| xpathi/643 | 22.1 | 22.1 | 0 | 0 | 0 |
| xss/79 | 44.7 | 22.3 | -27.6 | 0 | 0 |
| xxe/611 | 65 | 0 | 0 | 0 | 0 |

## Where Achilles loses

- **Out of sample, it lost badly.** The 4.7 (Java) and 19.5 (Python) above are what
  Achilles' rules scored before they were written against these cases. On Java that
  was below Semgrep CE, Bearer and Find Security Bugs as measured here.
- **Python command injection is the worst score on this page: -46.2.** Achilles flags
  all 7 decoys (its `subprocess-shell-true` rule fires on any `shell=True`, whatever
  reaches it) and misses 6 of 13 real cases (an argument list built as
  `["sh", "-c", ...]` with no `shell=True`, and input passed through a helper in
  another file). Every other tool scores 0 here, flagging all or nothing.
- **Python deserialization:** Semgrep CE (66.7) and Bandit (52.8) beat Achilles' own
  rules (44.4). The community pack closes the gap.
- **Its own community mode scores lower than its own rules alone**, on both
  benchmarks (Java 71.2 to 67.9, Python 50.3 to 41.8). The pack adds recall and more
  false positives: it flags every Python `secure`-cookie and XXE decoy. That is the
  default in `--mode oss`.
- **It is slower.** With the community pack, a Java scan took 201 seconds against
  Semgrep CE's 72, because Achilles runs several scanners and two rule sets on every
  scan. Bandit scans the Python cases in 4 seconds, Achilles in 15.
- **The Benchmark rewards what static rules can see and nothing else.** No tool here
  reads the Java hashing cases that take the algorithm from a properties file (all
  score 69), and most decoys are a branch never taken, which none of them folds away.
  SQL injection in Java is weak for every tool (30.2 at best) for that reason.

## What was compared, and how

Every tool scanned the Benchmark's test-case directory, and every report was scored by
the same code: `achilles-eval --mode owasp`, which flags a test case when a finding
with the category's CWE is reported anywhere in its file (the Benchmark's own rule).
For a report written by another tool, `--owasp-sarif` scores that SARIF file instead
of running Achilles. The CWE is read from a rule's tags (`external/cwe/cwe-89`, or
Semgrep's `CWE-89: ...`), from a rule's relationship to the CWE taxonomy (SpotBugs),
or from a result's `cwe` property. Bearer's SARIF carries no CWE and Bandit 1.9.4
writes no SARIF, so their JSON reports are converted by the jq filters
[`bearer.jq`](../evals/compare/bearer.jq) and [`bandit.jq`](../evals/compare/bandit.jq),
which copy each finding's file and CWE and nothing else.

| Tool | Version | Rules | Command (simplified) |
|---|---|---|---|
| Achilles, own rules | this commit | its own rules (`configs/rules`), opengrep 1.25.0 | `ACHILLES_SETTINGS=<file with "mode: commercial"> achilles-eval --mode owasp --owasp-dir <checkout>` |
| Achilles, with community rules | this commit | the above plus [opengrep-rules](https://github.com/opengrep/opengrep-rules) `f1d2b56` (security rules only, as `achilles tools install` keeps them) | the same with `mode: oss` |
| [Semgrep CE](https://github.com/semgrep/semgrep) | 1.181.0 | [semgrep-rules](https://github.com/semgrep/semgrep-rules) `17e31e1`, the whole `java/` or `python/` directory | `semgrep scan --metrics=off --config semgrep-rules/java --sarif -o java.sarif <testcode>` |
| [Bearer](https://github.com/Bearer/bearer) | 1.51.1 | [bearer-rules](https://github.com/Bearer/bearer-rules) v0.48.4 | `bearer scan <testcode> --disable-default-rules --external-rule-dir bearer-rules/rules --format json --output java.json` |
| [Find Security Bugs](https://github.com/find-sec-bugs/find-sec-bugs) | 1.14.0 (SpotBugs 4.9.3) | its own detectors | `findsecbugs.sh -effort:max -auxclasspath <deps> -sarif=java.sarif target/classes/.../testcode` |
| [Bandit](https://github.com/PyCQA/bandit) | 1.9.4 | its own plugins | `bandit -r <testcode> -f json -o python.json` |

The Benchmarks are pinned: BenchmarkJava `bc5ffeb` (version 1.2) and BenchmarkPython
`f129148` (version 0.1).

Choices that affect the numbers:

- **Semgrep** ran the public rule repository rather than a Registry ruleset such as
  `p/java`, so the rules are pinned; the Registry draws its community rulesets from
  this repository but picks a subset. Semgrep's paid engine (cross-file analysis) and
  its paid rules are not included.
- **Bearer** fetches its rules at run time by default; here they come from the pinned
  rules repository instead. On Python it found little.
- **Find Security Bugs** is wired into Achilles (`--profile full`), but it reads
  compiled classes, so it was run on its own on the compiled Benchmark with the
  project's classpath. It reports an injection wherever a value that is not a constant
  reaches a sink, which flags every decoy in five categories.
- **Bandit** is wired into Achilles as an opt-in Python scanner and is scored on its
  own here.
- Not included: CodeQL (its license is not open source), and Achilles' AI review.

## Fixed along the way

Running this exposed two problems, fixed in the same change:

- **Achilles' Java weak-randomness rule missed `new java.util.Random().nextBytes(buf)`**,
  which fills an array instead of returning a value (18 real cases), and flagged a
  `Random` parameter that held a `SecureRandom` (24 decoys). It now treats `nextBytes`
  as tainting its argument, treats the generator itself as the source so one passed to a
  helper still counts, and no longer trusts a parameter's declared `Random` type, since
  `SecureRandom` is a subclass. Weak randomness went from 83.0 to 100 and the Java
  average from 69.7 to 71.2. On WebGoat the rule's findings did not change (7 before
  and after).
- **The scorer read no CWE from SpotBugs reports**, which put it in a SARIF
  relationship rather than a tag, so Find Security Bugs first scored 0. It reads both
  now.

## Reproduce

From the repository root, with these on `PATH`:

- `go` and `jq`;
- the Achilles scanners and community rules: `go build -o bin/achilles ./cmd/achilles && bin/achilles tools install`,
  with `~/.achilles/bin` on `PATH`;
- Semgrep and Bandit: `pip install semgrep==1.181.0 bandit==1.9.4`;
- `bearer` 1.51.1 from its [release](https://github.com/Bearer/bearer/releases/tag/v1.51.1);
- `findsecbugs.sh` from
  [`findsecbugs-cli-1.14.0.zip`](https://github.com/find-sec-bugs/find-sec-bugs/releases/tag/version-1.14.0)
  (sha256 `ff546e16e596ade5b6534a6da87881e569429bf46dfd8faed63ca63cdd69b4f8`), plus a
  JDK and Maven to compile BenchmarkJava.

```bash
bash evals/compare/run.sh       # clones both Benchmarks at their pinned commits, scans, scores
bash evals/compare/tables.sh    # prints the tables above
```

A missing tool is reported as skipped, not scored; `TOOLS="semgrep bandit"` runs a
subset. Each scorecard is in `.achilles/compare/out/<benchmark>-<tool>.txt`, and
`achilles-eval --mode owasp --owasp-dir <checkout> --owasp-sarif <report.sarif>` scores
any other tool's SARIF report the same way.
