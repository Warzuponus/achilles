# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release (`v0.1.0`) is pending.

### Added
- **One-flag AI scan:** `--ai` turns on triage, fix suggestions, the repo review and
  the dependency advisor, and writes `report.html`, `report.md` and `achilles.sarif`
  into `--report-dir`.
- **LLM provider presets** (`--llm-provider openai|openrouter|ollama|anthropic`) and a
  pre-scan check of the LLM setup: missing key, a key sent to the wrong provider, an
  API key over plain http, or a missing model all fail before any scanning.
- **AI verdicts now change the result.** A confident false positive is moved out of the
  gate, the counts and the issues, and listed in its own report section (and as a
  suppressed SARIF result). `--keep-dismissed` restores the old behavior.
- **Honest reports:** every report states whether the scan was complete (failed scanners
  are named, including in the HTML report and SARIF) and how many findings the AI review
  covered.
- **Privacy controls for LLM calls:** credentials are masked in prompts, credential
  findings are never sent to the model or dismissed by it, `--llm-no-code` sends no
  source, and the destination host is printed before any code leaves the machine.
- **Prompt-injection hardening:** every prompt tells the model the code under review is
  untrusted data (`triage/v3`).
- **Standalone binary:** the tool registry and baseline rules are embedded, so
  `achilles` runs from any directory. New `--version`, `achilles doctor` and
  `achilles tools install|list` (hash-pinned scanner downloads, fail-closed on a
  mismatch), plus an optional community Opengrep ruleset.
- **Release automation:** goreleaser config, a tag-triggered release workflow with
  signed checksums, and `scripts/install.sh`.
- **Hardened GitHub issue filing** (`internal/issues`): severity threshold, per-run cap,
  grouping modes, dry run, de-duplication across runs, reopen-on-regression, closing of
  resolved or AI-dismissed findings, fix suggestions in the body, secret redaction, and a
  refusal to publish vulnerability details in a public repository without
  `--allow-public-issues`.
- **GitHub Action rewritten:** downloads the release binary instead of compiling,
  inputs for the LLM key, provider, model, issues and report upload, a job summary, and
  a three-line example workflow.
- Issue and pull-request templates, `NOTICE`, and this changelog.

- **Verify fixes by re-scan** (`--verify-fixes`, on by default with `--remediate`): each
  proposed patch is applied to a temp copy and the scanner that reported the finding is
  re-run. `--fix-pr` applies only verified patches; reports and issues show the status.
- **Deep verification** (`--deep-verify N`, `--deep-max-steps`): a bounded, read-only,
  secrets-blocked tool loop that lets the model read and search the repository to settle
  findings a single-file review could not. It can confirm freely but can only support a
  dismissal with cited evidence, and never overrides a confident true positive.
- **Gate-structured verdicts** (`triage/v4`): the model answers designed-behavior,
  reachable, attacker-controlled, sanitized and new-capability separately; comments and
  names are treated as claims, not evidence. Entry-point hints (routes, handlers, CLI
  args) from the finding's own file are added to the prompt.
- **Self-consistency sampling** (`--llm-samples`): borderline verdicts are re-asked and
  the majority wins; a split is `uncertain` and is never dismissed.

- **Detection benchmark** (`achilles-eval --mode detect`, `make eval-detect`): scans
  ground-truth corpora and scores recall by vulnerability class, tracing every miss to where
  it was lost (not detected, tool missing, noise filter, dismissed by the AI review, and so
  on). A committed hermetic fixture baseline gates regressions. See
  [Benchmarking Detection](docs/benchmarking.md).

### Changed
- **Docs for a first-time reader.** The README loses its build-diary sections (phase
  status, an internal pipeline sketch, a partial package list) and gains a short case for
  using Achilles over the scanners alone, a stable/experimental split, the Go 1.27.2 and
  gosec limit, and a note on how the project was built. `TEST_PLAN.md` now says what is
  tested, where, and what is not, instead of a per-phase checklist. `DESIGN.md` drops its
  dated progress notes and a planned package layout that never existed, and says which
  parts are intent rather than code. `CONTRIBUTING.md` gains a map of the code.
- Brakeman is described by its actual license (the Brakeman Public Use License), not
  CC BY-NC-SA. It stays excluded from `--mode commercial`.
- **Images:** a release tag now also moves `latest` and `vX.Y` (and their `-slim`
  forms). Only the exact version tag was pushed before, so the documented
  `docker run ghcr.io/warzuponus/achilles` pulled a tag that did not exist.
- **Action:** pinned to a commit or branch rather than a release tag, it now says that
  it is installing the latest release and how to pin the binary too.
- `--timeout` bounds the scanners only; the AI phases have their own `--llm-budget`
  (default 45m) and run `--llm-concurrency` findings in parallel, most severe first.
- A rejected key or exhausted credits now stops the run immediately instead of failing
  every finding in turn.
- Finding paths are repo-relative whatever scanner reported them (Opengrep reported
  absolute paths).
- The action defaults to `mode: oss`, matching the CLI.
- `--config` defaults to the embedded registry instead of `configs/tools.yaml` in the
  current directory.

### Security
- **The scanned repository's own scanner configuration is no longer applied silently.**
  Files such as `.gitleaks.toml`, `.trivyignore`, `.semgrepignore` and `osv-scanner.toml`
  can remove findings before Achilles sees them, and a pull request can add a secret and
  the allowlist entry hiding it together. Every such file in effect is now named on
  stderr and in the human, Markdown and HTML reports; with `--diff`, a change that
  modifies one gets a warning at the top of each report. New `--no-repo-config`
  (`$ACHILLES_NO_REPO_CONFIG`) refuses them: files Achilles would pass are not passed, and
  a scanner that reads one on its own is reported as incomplete, which fails
  `--strict-tools`. It does not cover inline suppression comments; SECURITY.md says so.
- **Pull-request comments treat scan text as untrusted.** The summary comment
  (`--pr-comment`, also the Markdown report) and inline review comments (`--pr-review`)
  posted scanner messages, rule ids, file names and model reasoning as they came. They are
  now masked for credentials, kept to one line, and cannot inject HTML, forge hidden
  markers, notify people with `@mentions` or break out of a table cell.
- **Achilles only updates or trusts its own comments.** The sticky summary was found by
  looking for its marker anywhere in any comment, so a comment from anyone containing the
  marker was adopted and rewritten on each run, leaving its author able to edit "the
  Achilles summary". Inline comments had the same weakness in reverse: a planted marker
  suppressed the comment for that finding. A comment now counts only if it starts with the
  marker and was written by the account the token acts as (or by a bot account, for tokens
  that cannot name themselves). The search also covers every page of comments.
- **Retention no longer loosens the vault's permissions.** The file vault is created
  readable by its owner only, but a purge replaced it with a file created at the default
  mode, readable by every local user. The code and docs also called the vault
  "tamper-evident"; it has no hash chain or signature and no longer claims to.
- **The code shown to the model can only come from the scanned tree.** The step that adds
  the lines around a finding read whatever path the scanner reported: a `..` path, an
  absolute path elsewhere, or a symlink in the repository pointing at a file in your home
  directory was followed, and its contents were sent to the model and written to reports.
  Reads now go through an OS-enforced root at the scan target; anything outside falls back
  to the snippet the scanner itself provided.
- **Credential masking covers more shapes.** Text sent to a model, written to reports and
  issues, or shown in the War Room now also masks: the password in a URL
  (`postgres://user:password@host`), `Authorization: Basic` and opaque `Bearer` tokens,
  Stripe `sk_live_`/`rk_live_` keys, `secretKey`/`SECRET_KEY`/`secret_access_key`
  assignments, Slack and Discord webhook URLs, and PGP private key blocks. A placeholder
  in a password position (`%s`, `${VAR}`, `{password}`) is left alone, so a reviewer can
  still tell a templated credential from a hardcoded one.
- The toolchain floor moves to Go 1.27.2 and `golang.org/x/text` to v0.43.0, clearing 13
  known vulnerabilities that `govulncheck` showed this code reaching (HTTP/1 and HTTP/2
  request handling, `html/template`, `mime/multipart`, TLS, and an `x/text` panic). CI
  now runs `govulncheck` on every change, and the tests run under the race detector.

- The War Room no longer loads JavaScript from a CDN. It used to fetch htmx and Alpine.js
  from unpkg, one of them at a floating version and neither with an integrity hash, so
  the page was inert offline and a CDN compromise would have run in a page showing every
  finding. Alpine was unused and htmx did one form post; both are replaced by a small
  script embedded in `achillesd`. Every response now carries a Content-Security-Policy
  (scripts from the War Room's own origin only), `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`.

- Release archives and the container image now carry the notices their licenses
  require. `NOTICE` was in neither (Apache-2.0 section 4 requires it); the image
  redistributes the Opengrep binary (LGPL-2.1) with no copy of that license; and no
  distribution carried the license text of the Go modules linked into the binaries.
  The archives add `NOTICE` and `third_party/licenses/`; the image adds those plus a
  license directory per bundled scanner under `/usr/share/doc/achilles/licenses/`, and
  the image build fails if one is missing. CI fails if the committed license texts do
  not match the linked modules.

- The image workflow passed a manually entered version straight into a shell script in
  a job that can write packages. It now arrives through the environment and is
  validated.

### Changed (toolchain)
- Built and tested with Go 1.27 (`go 1.27`, `toolchain go1.27.2`): `go.mod`, every workflow, the
  action, and the container base images (digest-pinned) move together. Building from source now
  needs Go 1.27; release binaries and the images are unaffected for users.

### Removed
- `.github/workflows/scan-hub.yml` is now an example,
  [`examples/workflows/scan-hub.yml`](examples/workflows/scan-hub.yml). As repository
  CI it hard-coded one provider, one model and `mode: commercial`, needed three
  secrets, and every fork inherited it. The example uses the published action and
  takes the provider key and model from the hub repository's own settings. **If you
  ran hub scans from this repository, copy the example into a repository of your own.**
- `make eval-verdict-ollama`. `make eval-verdict` takes the endpoint and routing file
  as arguments instead of a hard-coded provider.
- The `Docs to Pages` workflow. The guides remain in `docs/`, and `make docs-html` still builds
  the single-page `docs/site.html`.

### Fixed
- **War Room:** an unknown path rendered the dashboard with a 200 (the route for `/`
  matched everything). It is now a 404.
- **`--runner docker` and Opengrep.** Opengrep has no container image, and the docs said
  it runs as a local binary under `--runner docker`. The code handed it to `docker run`
  with an empty image name instead, so it failed on every such scan. It now runs as the
  local binary and prints a line saying it is not in a container. A tool with neither an
  image nor a binary gets a clear error instead of Docker's "invalid reference format".
- **Windows.** The file vault had no cross-process lock on Windows, so two processes
  writing one vault produced records with duplicate ids; it now locks with `LockFileEx`.
  The whole test suite passes on Windows and runs there in CI on every change (three
  packages failed before, one of them by hanging for ten minutes). A `.gitattributes`
  keeps checkouts LF on every platform.
- **`--llm-provider anthropic` failed on every request.** Triage sends `temperature: 0`
  and Anthropic's OpenAI-compatible endpoint rejects an explicit temperature on current
  Claude models, so the run aborted after five failures with no report. Temperature is
  now left out for that endpoint. The preset remains experimental and is labelled so in
  the flag help, the action and the docs.
- **A scanner that could not analyze the code was reported as a complete scan.** gosec
  exits 0 and writes a valid report when a package will not type-check, silently skipping
  its taint and other type-based rules. This is not hypothetical: Go 1.27.2 changed a
  compiler format that no gosec release (through v2.29.0) can read, so gosec loses that
  analysis for every package when the `go` on PATH is 1.27.2 or newer. A tool can now
  declare the phrases that mean "I could not analyze everything" (`incompleteWhen` in the
  registry); its findings are kept, the scan is marked incomplete in every report, and
  `--strict-tools` fails. gosec skips `testdata/` directories, as the go tool does. The
  self-scan and the image pin the Go that gosec scans with to 1.27.1 until gosec
  supports the new format.
- **Fix verification failed on almost every `--ai` run.** It re-used the scanners'
  `--timeout` clock after the AI review, so once scan plus review took longer than that
  timeout every fix was reported as `error` ("deadline exceeded"). Verification now has
  its own clock, `--verify-timeout` (15m), and `--sbom` gets a fresh `--timeout`.
- **`--timeout` and Ctrl-C did not stop scanners.** Only the top process was killed: a
  scanner's worker process kept running and kept the scan waiting, and a Docker
  container kept scanning after its client was killed. Each tool now runs in its own
  process group which is killed as a whole, containers are named and killed, the wait is
  bounded, and a tool cut off mid-run is reported as failed instead of having its exit
  code interpreted. Ctrl-C is handled: everything stops, temporary files are removed,
  and the run exits 2.
- The `--fail-on` gate exited from inside the pipeline, skipping cleanup of temporary
  rule directories. It now returns normally and exits 1 from `main`.
- **Flags after the target path were silently ignored.** `achilles . --ai` ran a plain
  scan and `achilles . --fail-on high` ran with no gate and exited 0. Flags are now
  accepted before or after the path, an unknown flag anywhere is an error, and so is a
  second path.
- **Baselines and issue de-duplication could break at random.** When a scanner supplied
  more than one fingerprint under keys Achilles does not know, one was picked by Go map
  order, so it differed between runs. The choice is now deterministic.
- **Trivy's secret findings were sent to the model and could be dismissed, and found
  secrets were copied into the vault.** Credential findings were recognised by tool name
  and rule-id keywords, which Trivy's rules (`github-pat`, `slack-web-hook`, ...) do not
  match. Findings now carry the category the scanner itself declares, so a Trivy secret
  is withheld from the model and can never be dismissed. Separately, a credential
  finding's matched text is no longer kept anywhere: it is dropped from the finding once
  its fingerprint is taken, removed from the scanner output stored in the vault and
  written by `--sarif-out`, and credential findings are never used as `--rag` examples.
- **The War Room audit export served the vault unredacted.** `GET /runs/{id}/audit`
  returned raw scanner output (a secret scanner's report is a list of secrets), credential
  snippets and full LLM transcripts, and the run page only pattern-masked a credential
  finding's snippet. Raw scanner output is no longer served, credential snippets are
  withheld on both the page and the export, and every other string is masked.
- **`--fix-pr` pushed the whole working tree.** It switched your checkout to the fix
  branch and committed with `git add -A`, so an untracked `.env`, the scan's own vault
  (every prompt and response) and its reports went into the pull request. It now builds
  the branch in a temporary git worktree, leaves your checkout and anything uncommitted
  alone, and commits exactly the files the fixes change.
- **A model-written fix could change any file.** A patch could add a workflow step, a
  build target or a new file alongside the real fix and still pass the re-scan. A fix may
  now change only the file its finding is in, may not create, delete, rename or chmod
  files, and may never touch CI or git control files. The check runs before the re-scan
  and again before `--fix-pr` applies anything, including with `--verify-fixes=false`.
  A model can no longer mark its own patch as verified in its reply.
- **The AI review could rule out a known CVE.** Dependency findings (osv-scanner,
  govulncheck, Trivy vulnerabilities) went through the same prompt as code findings,
  with a lockfile line or nothing at all as "code context", and a confident false
  positive took them out of the gate. They are no longer sent to the model (which also
  removes two paid calls per CVE), never receive or inherit a verdict, are skipped by
  `--deep-verify` and `--calibrate`, and can never be dismissed. Reports count them
  separately.
- **Trivy never ran its IaC / misconfiguration checks.** It was invoked as plain
  `trivy fs`, which runs only the vulnerability and secret scanners. The registry now
  passes `--scanners vuln,misconfig,secret`, and gives Trivy network access under
  `--runner docker`, where it previously could not download its database and always
  failed.
- **`--fail-on critical` could never fire, and a typo failed everything.** No scanner
  result was ever mapped to `critical`: only the SARIF level was read, and the
  `security-severity` score that Trivy and others publish was ignored, so a CVSS 9.8 was
  reported as high. Scores are now read (9.0+ critical, 7.0+ high, 4.0+ medium), taking
  the more severe of level and score. A result with no level at all was `unknown`, which
  no threshold matches, so Gitleaks findings could not fail a gate; they are now high,
  and other level-less results get the SARIF default (medium). `--fail-on` rejects a
  value that is not a severity instead of treating it as "below everything".
- **Three `fp` labels could silence a rule forever.** Feedback-driven calibration ran on
  every triage, ruled out all future findings of a rule after three false-positive labels
  at 80%, never expired, and applied at any severity, with no model looking at the code.
  It is now opt-in (`--calibrate`), needs ten distinct labeled findings at 90%, ignores
  labels older than 180 days, never applies above medium severity or to credential
  findings, counts each finding once by its latest label, and says in the run log and in
  every report how many verdicts came from feedback instead of a review.
- **The adversarial judge could silently drop real findings.** Two cases: a verdict of
  `uncertain` that the judge "refuted" was ruled out even when the judge was arguing the
  finding is real, and any true positive was ruled out on the judge's bare yes/no. Now
  (`triage/v5`) a refuted `uncertain` verdict is never ruled out, and a true positive is
  ruled out only when the judge states a confidence of at least 0.7, quotes context that
  Achilles verifies it actually sent, and the triage pass was below 0.9. Anything less is
  reported as **disputed by judge** and stays in the gate. Model-reported confidences are
  normalized to 0..1 (a reply of `85` is 0.85, not "above every threshold").
- Opengrep under `--runner docker` asked Docker for an empty image; it now runs as the
  local binary, as documented.
- Opengrep crashed under a non-UTF-8 locale when reading non-ASCII community rules.
- Release binaries reported a "-dirty" commit: goreleaser's untracked `dist/` made Go stamp
  the build as modified. A commit injected by the release process is now trusted, and
  `/dist/` is git-ignored.
- The full container image build ran the runner out of disk; the workflow now frees space first.
- osv-scanner exiting with "No package sources found" (a tree with no dependency
  manifests) was reported as a failed tool, marking every such scan "incomplete" and
  failing it under `--strict-tools`. It is now an empty result (`nothingToScan` in the
  tool registry).
- Documentation referred to a release tag and install paths that did not exist.
