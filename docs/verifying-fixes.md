# Verifying proposed fixes

`--remediate` asks the model for a unified diff per confirmed finding. A model can
write a patch that looks right and does not work, so Achilles checks each diff
instead of taking it on faith. This is `--verify-fixes`, on by default whenever
`--remediate` produced a diff (`--verify-fixes=false` turns it off).

## What it does

For each finding that has a diff, Achilles:

1. Copies the scan target to a temporary directory.
2. Applies the diff there with `git apply`. Your working tree is never touched.
3. Re-runs **only the scanner that reported the finding**, through the same
   scanner registry and runner (local or Docker) as the main scan, over the
   patched copy.
4. Compares the re-scan with the original:
   - the original finding must be gone, and
   - the scanner must not report anything new.
5. Deletes the temporary copy, whatever the outcome.

Each tool's findings on the unpatched target are computed once and reused for
every fix from that tool. Up to two fixes are verified at a time.

## How "gone" and "new" are decided

A patch moves lines, so a finding is matched loosely. In the patched copy, the
original finding still counts as present if the same scanner reports, **in the same
file**, either the same fingerprint or the same rule within 10 lines of the
original line. This leans towards `not_fixed`: a second instance of the same rule
nearby will keep a fix from verifying.

A finding in the patched copy counts as **new** if neither its fingerprint nor its
rule and file appear among the findings the scanner reported before (or among the
findings the main scan kept or dismissed). So an extra instance of a rule that
already fires in that file is not reported as new; a rule that did not fire there
before is.

## What it proves, and what it does not

It proves that the diff applies cleanly and that the scanner which raised the
finding no longer raises it, and raises nothing new, on the patched code.

It does **not** prove that:

- the change is correct or complete (a patch can silence a rule without removing
  the weakness, for example by deleting the flagged code);
- the program still builds, passes its tests or behaves the same;
- other scanners, or other rules of the same scanner in other files, are happy;
- the finding was a real vulnerability in the first place.

Treat `verified` as "the scanner no longer complains", not "safe to merge". Review
and test every fix. Achilles still never merges anything.

## Statuses

| Status | Meaning |
|---|---|
| `verified` | The diff applied, the finding is gone and the scanner reported nothing new. |
| `not_fixed` | The diff applied but the scanner still reports the finding. |
| `introduces_new` | The finding is gone but the scanner reports new findings; they are listed in `newFindings` (at most 20). |
| `patch_failed` | The diff was rejected as unsafe (see below) or does not apply cleanly to the code. The scanner is not run. |
| `skipped` | Verification was not attempted: the target is over the size cap, the finding is in an excluded directory, or the reporting tool cannot be re-run (a shadow rule, or a tool no longer registered). Says nothing about the patch. |
| `error` | Verification started but the baseline or re-scan failed (tool crash, timeout, unreadable output). Never treated as verified. |

## Safety and size caps

The diff comes from a model that read untrusted code, so it is checked before git
sees it. A diff is rejected (`patch_failed`) if it:

- names an absolute path, a `..` segment, or anything under `.git`;
- uses a quoted/escaped path or a backslash;
- is a binary patch, or creates or changes a symlink;
- names no files, touches more than 20 files, or is larger than 256 KiB.

The copy skips `.git`, `node_modules`, `vendor`, `.achilles`, `.terraform`, virtualenvs
and common build-output directories (`dist`, `build`, `target`, `out`, `.next`,
`.gradle`, `__pycache__`), and never follows or recreates symlinks or special files.
A finding inside a skipped directory is reported as `skipped`.

If the target is larger than **200 MiB** or more than **50,000 files**, the result is
`skipped: target too large`, not an error, and the scan carries on.

Two things to be aware of: the re-scan runs the same scanner commands as the main
scan, on a copy under the system temp directory (set `TMPDIR` to change where); and
`git apply` runs in that copy, so keep `TMPDIR` outside any git repository.

## Where the result shows up

- `remediation.verification` in the JSON scan data, and in the Evidence Vault as a
  `remediation` record (source `verifyfix`) that supersedes the one written at
  triage time.
- One summary line on stderr, for example
  `fix verification: 3 verified, 1 not fixed, 1 patch failed`.
- The "Suggested fix" section of GitHub issues: "Verified: the scanner that
  reported this no longer reports it after applying this patch" or "Not verified:
  ...".
- `--fix-pr`: only `verified` diffs are applied. Every other diff is reported on
  stderr with its status and reason, never skipped silently. With
  `--verify-fixes=false`, diffs are applied as before and the run says they were
  not re-scanned.
