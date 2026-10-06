# Detection benchmark

The triage eval ([`../README.md`](../README.md)) asks whether the AI layer judges a
finding correctly. It cannot say whether the scanners find the bug in the first
place: a vulnerability nobody reports never reaches triage. This benchmark measures
that earlier question — **recall on code with known vulnerabilities** — and, for
every miss, **where in the pipeline it was lost**.

```bash
make eval-detect          # run the real scanners over the fixtures, print the scorecard
make eval-detect-gate     # the same, failing if recall dropped against baseline.json
make eval-detect DETECT_ARGS="--out evals/detect/baseline.json"   # refresh the baseline
```

It runs the real `achilles` binary, so the scanners must be installed (`opengrep`,
`gosec`, `gitleaks`, `osv-scanner`, ...; `osv-scanner` also needs network). A scanner
that is absent is **reported as a loss point (`tool-missing`) and the target is
marked incomplete** — it is never counted as a clean miss. Full usage, flags and
the interpretation of the numbers: [`docs/benchmarking.md`](../../docs/benchmarking.md).

## Layout

```
evals/detect/
  ground_truth/            one JSON file per target (the labels)
    py-webapp.json  js-express.json  go-service.json  deps-manifest.json  secrets-config.json
    external.example.json  format example for pinned public apps (never scored)
  fixtures/                the deliberately vulnerable code the local targets point at
  baseline.json            the committed scorecard that `eval-detect-gate` compares against
```

The fixtures are **never built, run or shipped**. The Go fixture is its own module
(`fixtures/go-service/go.mod`), so `go build ./...` and `go vet ./...` in the parent
module skip it; the self-scan passes `--exclude evals`, so it never sees them either.
Every credential-shaped string in them is invented and grants access to nothing.

## Ground-truth schema (`schemaVersion: 1`)

One JSON object per file (the loader also accepts an array of them, which the
external example uses). Unknown fields are rejected, so a misspelled `startLine`
cannot silently become line 0.

```json
{
  "schemaVersion": 1,
  "id": "py-webapp",
  "description": "Flask-style service with the classic web weaknesses.",
  "source": { "path": "../fixtures/py-webapp" },
  "vulnerabilities": [
    {
      "id": "PY-SQLI-1",
      "class": "injection",
      "cwe": ["CWE-89"],
      "file": "app.py",
      "startLine": 19,
      "endLine": 19,
      "description": "User-controlled name is interpolated into a SQL string via an f-string.",
      "note": "optional reviewer context, never sent to a model"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Target id: letters, digits, `.`, `_`, `-`. Unique across files. |
| `source` | Where the code is. Either `{"path": "..."}` (a local directory, relative to the JSON file unless absolute) or `{"url": "...", "commit": "<40-hex SHA>", "subdir": ""}`. |
| `vulnerabilities[].id` | Unique within the target. |
| `.class` | Free text, but these are understood by the matcher: `injection`, `xss`, `path-traversal`, `hardcoded-secret`, `weak-crypto`, `ssrf`, `authz`, `deserialization`, `vulnerable-dependency`. Anything else matches on CWE overlap only. |
| `.cwe` | Zero or more `CWE-<n>`. |
| `.file` | Relative to the scan root (the checkout, or `source.subdir` inside it). Slash-separated, no `..`. |
| `.startLine`, `.endLine` | 1-based, inclusive. Checked against the scanned tree at run time: an entry whose file is missing or whose `startLine` is past the end is reported as `invalid` and excluded from recall, rather than scored as a miss. For the committed fixtures `go test ./internal/eval` fails on a stale label. |
| `.package` | Required for `vulnerable-dependency`: dependency scanners report the manifest, not a line, so the package name ties a finding to the entry. |
| `.description` | Required. A label nobody can review is not ground truth. |

## Matching rule

A scanner finding matches an entry when **all three** hold:

1. **Same file.** Both paths are normalized to scan-root-relative, slash-separated
   form (absolute paths, `file://` URIs and `./` are handled).
2. **Lines overlap** `[startLine - tol, endLine + tol]` (`--line-tolerance`, default
   3). A finding with no line at all (osv-scanner points at the manifest) matches by
   file alone, but only a `vulnerable-dependency` entry, and only if its `package`
   appears in the finding's message or rule id.
3. **CWE or class agrees.** Either the CWE sets intersect, or the entry's class is
   one the finding is compatible with. Compatibility is inferred from the finding's
   CWEs (for example 78/89/95 are all `injection`), its tool (`gitleaks` is
   `hardcoded-secret`; `osv-scanner` is `vulnerable-dependency`), and its rule id
   (gosec `G304`, or a token such as `sqli`/`ssrf`/`pickle` in the id).

One guard: a finding that lands squarely on one entry cannot also credit a
neighbouring entry just because it falls inside the tolerance. (A scanner that finds
the secret on line 5 is not credited with the ones labeled on lines 3 and 4.)

A same-place finding that fails rule 3 is **ambiguous**. By default it is not
counted and the miss is traced as `class-mismatch`. With `--judge`, a model may
adjudicate those pairs; its detections are counted separately ("judge-assisted") and
the judge is never consulted when nothing was reported nearby. Judging is opt-in and
never used by a gate.

## Loss points

Every missed entry is assigned exactly one, derived from the scan's own artifacts
(the SARIF report and the Evidence Vault — raw outputs, findings recorded before any
filter, verdicts, diagnostics), never from a re-implementation of the pipeline:

| Loss point | Meaning |
|---|---|
| `not-detected` | Scanners that cover the entry ran cleanly and reported nothing nearby: a real detection gap (add or widen a rule). The trace lists what ran, failed and was skipped. |
| `no-coverage` | No scanner that ran claims this language/class. |
| `tool-missing` | A scanner that covers the entry is not installed. The target is incomplete; the miss may be environmental. |
| `scan-incomplete` | A covering scanner failed to run or its output was unreadable. |
| `scan-failed` | The whole scan failed; nothing was learned. Counted as a miss, never dropped from the denominator. |
| `class-mismatch` | Flagged at the right place, but as a different class/CWE (the judge can adjudicate). |
| `line-mismatch` | A compatible finding exists in the file, outside the line tolerance. |
| `noise-filter` | Reported, then dropped by the vendored/generated/minified filter or `--exclude`. |
| `baseline-suppressed` | Reported, then suppressed by a `--scan-baseline` file. |
| `diff-filtered` | Reported, then dropped by `--diff`. |
| `ai-dismissed` | Reported, then dismissed by the AI review. The trace carries the verdict, confidence and reasoning. |
| `dropped-unknown` | Reported but absent from the final report, and no known filter explains it. |

## Scorecard

Per class and overall: **recall**; the loss-point histogram; per-target tables with
the trace of every miss; and a precision *proxy*. Findings outside any label are
**unlabeled, not false positives** — the benchmark labels known bugs, not every line
of code, so it cannot tell a false alarm from a real bug nobody listed. The report
counts findings that matched a label, findings in labeled files that matched none,
and findings in files with no label at all.

With `--ai` the scan runs twice per target: once with `--keep-dismissed` (what the
scanners found, with verdicts attached) and once without (what the AI review let
through). Both recalls are reported; the gap is the AI review's cost in recall, and
`ai-dismissed` misses say which findings it removed and why. It costs two scans of
model spend per target.

`--repeat N` runs the whole benchmark N times, and `--out` carries run history
forward from the file it overwrites (when the configuration is unchanged), so
`unstable` lists entries detected in some runs and missed in others — the number
that says whether a recall change is signal or noise.

## External targets (pinned commits)

[`ground_truth/external.example.json`](ground_truth/external.example.json) shows how
to point at public intentionally-vulnerable apps (OWASP Juice Shop, NodeGoat,
WebGoat). It deliberately carries **no real commit SHA**: its `commit` fields are
placeholders and the runner refuses them with instructions. To use one:

1. Copy the target object to its own file, `ground_truth/juice-shop.json`.
2. Clone the repository, pick the commit, run `git rev-parse <ref>` and paste the
   full 40-character SHA into `source.commit`. Branches and tags are refused: a
   moving target silently invalidates every line number.
3. Check every entry's `file` and line range against that exact commit, and delete
   the `EXAMPLE`/`note` text. Entries whose file or line does not exist are reported
   as `invalid` rather than scored as misses.
4. `make eval-detect` fetches the commit (shallow first, full clone as a fallback)
   into `.achilles/detect-cache/` and reuses it while it is at the pinned commit.

`*.example.json` files in `ground_truth/` are skipped when a directory is loaded;
pass one explicitly with `--ground-truth` to see the refusal.

## Adding a fixture

1. Write the vulnerable code under `fixtures/<name>/`. Make it look like real code,
   and **write the labels before you look at what the scanners report**: a fixture
   tuned to what Achilles already finds measures nothing. Include things you expect
   to be hard — a business-logic flaw, a class with thin rule coverage — and say so
   in `note`.
2. Add `ground_truth/<name>.json`. `go test ./internal/eval` validates every committed
   label against its fixture, so a stale one fails loudly.
3. Go fixtures need their own `go.mod`: a `testdata/` directory would hide the code
   from gosec's `./...`.
4. Do not commit a real credential, a private-key block, or a `/Users/<name>` path:
   `scripts/check-tree.sh` fails on those, tests included.
5. Run `make eval-detect`, read the traces, then refresh the baseline with
   `make eval-detect DETECT_ARGS="--out evals/detect/baseline.json"` and say why in
   the commit.
