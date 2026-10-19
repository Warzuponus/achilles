# CI & the Scan Hub

Ways to run Achilles in GitHub Actions, from simplest to most powerful. For every
way to run it (workstation, containers, CI, scheduled), see [DEPLOY.md](../DEPLOY.md).

## Option A — AI-verified scan of your repo, with issues (start here)

Copy [`examples/workflows/achilles.yml`](../examples/workflows/achilles.yml) to
`.github/workflows/achilles.yml`, then set one **secret** (`LLM_API_KEY`, your
provider's key) and one **variable** (`LLM_MODEL`). That is the whole setup:

```yaml
permissions:
  contents: read
  issues: write
steps:
  - uses: actions/checkout@v4
  - uses: Warzuponus/achilles@v0.3.0
    with:
      llm-api-key: ${{ secrets.LLM_API_KEY }}
      llm-provider: openrouter          # or openai | ollama | anthropic, or llm-base-url
      llm-model: ${{ vars.LLM_MODEL }}
      issues: "true"
```

What it does, in order: downloads the release binary and the hash-pinned scanners
(no compiling), scans, has the model review every finding, writes `report.html`,
`report.md` and `achilles.sarif`, uploads them as the `achilles-report` artifact,
adds a summary to the job page, and opens one GitHub issue per confirmed finding.
Re-runs update those issues instead of duplicating them, close them when the finding
is fixed, and reopen them if it comes back. A finding you close by hand stays closed.

Each issue carries the AI's reasoning and a suggested fix (a patch when one could be
made safely). Issue filing is capped (`issues-max`, default 25 new per run, most
severe first) and never publishes vulnerability details in a **public** repository
unless you set `allow-public-issues: "true"`. Findings about credentials get an issue
that names only the rule and location, never the secret.

| Input | Default | Meaning |
|-------|---------|---------|
| `llm-api-key`, `llm-model` | — | both are needed for the AI review; with neither, only the scanners run |
| `llm-provider` / `llm-base-url` | — | which endpoint; see [LLM Triage & Agents](llm-and-agents.md) |
| `issues`, `issues-min-severity`, `issues-max` | `false`, `medium`, `25` | issue filing |
| `fail-on` | — | fail the job if a finding at or above this severity remains after the AI review |
| `upload-sarif` | `false` | also fill the Security tab (private repos need GitHub Advanced Security) |
| `llm-no-code` | `false` | send the model no source code |
| `version` | the tag you pinned | a release tag, `latest`, or `source` |
| `args` | — | extra `achilles` flags, appended last |

**Run it on `push`, `schedule` or `workflow_dispatch`, not on pull requests from
forks.** A forked PR cannot read your secrets (the AI review would not run), and
`pull_request_target` would give the key and a write token to code you have not
reviewed, which the scanners and the model would then read. Pin the action to a tag
or commit, as above. The action supports Linux and macOS runners.

## Option B — per-PR gate (no LLM, no secrets)

[`examples/workflows/scan-example.yml`](../examples/workflows/scan-example.yml) runs
on pull requests, annotates the diff, and fails only on newly introduced
high-severity findings. It needs no secret, so it works on fork PRs:

```yaml
- uses: Warzuponus/achilles@v0.3.0
  with:
    fail-on: high
    args: --diff origin/${{ github.base_ref }} --baseline .achilles/baseline.json
```

## Option B2 — routed open models

[`examples/workflows/scan-ollama-example.yml`](../examples/workflows/scan-ollama-example.yml)
shows per-task model routing (a cheaper model to triage, a stronger one to judge) over
Ollama Cloud, via `--model-config`. Same inputs as Option A.

## Option C — the central scan hub

Scan **other** repos from one hub repository, so the LLM key lives in one place and
targets need **no secret and no workflow**. This is the GitHub-Actions expression of
the fleet model. Copy
[`examples/workflows/scan-hub.yml`](../examples/workflows/scan-hub.yml) into
`.github/workflows/` of the repository you want to be the hub (a private repository
of your own; it does not run from `examples/`).

### One-time setup (org/repo admin)

1. **Create a GitHub App** in the org: repository permission **Contents: Read**
   only, no webhook, "Only on this account."
2. **Install it** on the repos you want scannable — only those get read access.
3. In the hub repository (Settings → Secrets and variables → Actions) add:
   - secret `SCANNER_APP_ID` — the App's ID
   - secret `SCANNER_APP_PRIVATE_KEY` — the App's **private key** (the `.pem` contents,
     from the App's *Private keys* section — **not** the client secret)
   - secret `LLM_API_KEY` — your LLM provider's key
   - variable `LLM_MODEL` — a model that provider serves

Set the private key reliably with:
```bash
gh secret set SCANNER_APP_PRIVATE_KEY -R <owner>/<hub-repo> < your-app.private-key.pem
```

### Running it

Actions → **Achilles scan hub** → *Run workflow* → enter the target repo name
(e.g. `example-app`). The workflow:

```yaml
- uses: actions/create-github-app-token@v1   # short-lived, scoped to just the target
  id: tok
  with:
    app-id: ${{ secrets.SCANNER_APP_ID }}
    private-key: ${{ secrets.SCANNER_APP_PRIVATE_KEY }}
    owner: ${{ github.repository_owner }}
    repositories: ${{ inputs.target_repo }}
- uses: actions/checkout@v4
  with:
    repository: ${{ github.repository_owner }}/${{ inputs.target_repo }}
    token: ${{ steps.tok.outputs.token }}
    path: target
# then an AI-verified scan of ./target; the report is uploaded as an artifact
```

Inputs: `target_repo` (required, repo name only — the owner is this repository's owner)
and `ref` (optional branch/tag/SHA; blank = the default branch). Secrets:
`SCANNER_APP_ID`, `SCANNER_APP_PRIVATE_KEY`, and the LLM key `LLM_API_KEY`.

**Least privilege by design:** a per-run token scoped to exactly the target repo
(not a personal PAT). By default results are artifacts of the hub run and nothing is
written back to the target. Tick **`file_issues`** when you run the hub to also open
issues in the target: the workflow then mints a second token that adds Issues: Write
on that one repo, so grant the App **Issues: Write** first (it is not needed
otherwise). To also post SARIF to a target's Security tab, grant **Code scanning:
Write** and add an upload-sarif step.

Download the report from **the run → Artifacts → `achilles-report`**: it holds
`report.html`, `report.md` and `achilles.sarif`. There is no cloud vault: the
artifacts are the record.

## GitLab CI

Achilles writes the report formats GitLab reads from job artifacts, so it runs as an
ordinary job. A complete example is in
[`examples/gitlab/.gitlab-ci.yml`](../examples/gitlab/.gitlab-ci.yml):

```yaml
achilles:
  stage: test
  image: ghcr.io/warzuponus/achilles:latest   # pin a release tag
  script:
    - >-
      achilles
      --gitlab-sast gl-sast-report.json
      --gitlab-secret-detection gl-secret-detection-report.json
      --gitlab-dependency-scanning gl-dependency-scanning-report.json
      --gitlab-code-quality gl-code-quality-report.json
      --fail-on high
      .
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
      secret_detection: gl-secret-detection-report.json
      dependency_scanning: gl-dependency-scanning-report.json
      codequality: gl-code-quality-report.json
```

| Flag | GitLab report | Holds | Where GitLab shows it |
|------|---------------|-------|-----------------------|
| `--gitlab-sast` | `artifacts:reports:sast` | findings in code | merge request security widget, pipeline Security tab, vulnerability report (Ultimate) |
| `--gitlab-secret-detection` | `artifacts:reports:secret_detection` | credential findings, never the matched text | the same places (Ultimate) |
| `--gitlab-dependency-scanning` | `artifacts:reports:dependency_scanning` | dependency advisories (osv-scanner, Trivy, govulncheck), each with its package, version and manifest; Trivy's fixed version as the solution | the same places (Ultimate) |
| `--gitlab-code-quality` | `artifacts:reports:codequality` | every finding, credential messages masked | merge request widget and diff, on every tier |

What to know:

- **Without Ultimate, use the Code Quality report.** GitLab accepts the security
  reports on any tier but only displays them on Ultimate. The Code Quality report is
  the one every tier shows on a merge request, which is why it carries all findings,
  dependency advisories included.
- **`when: always`** uploads the reports when `--fail-on` fails the job, which is the
  run you most want them from.
- **Only findings that count are written**: the ones the gate sees. Findings the AI
  review dismissed are left out; with `--keep-dismissed` they are written and marked
  with GitLab's "likely false positive" flag, with the reason. Each finding carries
  the AI verdict and reasoning in its details, and a fix that passed re-scan
  verification is attached as a remediation.
- **An incomplete scan says so.** If a scanner could not run, the report's scan
  status is `failure` and a message names the tool; the findings from the scanners
  that did run are still there.
- **Dependency advisories** go in the dependency scanning report, each with the
  package, version and manifest taken from the scanner's message (an advisory that
  names no package is reported as `unknown`), and in the Code Quality report.
- **Vulnerabilities keep their history when code moves.** Each finding in the
  security reports carries a tracking signature built from Achilles' fingerprint,
  which hashes the matched code rather than its line, so GitLab (Ultimate) keeps a
  vulnerability's status, comments and linked issue when an edit above it shifts
  its line, instead of resolving it and reporting a new one.
- **A summary note on the merge request**, on every tier: add
  `--gitlab-mr-comment $CI_MERGE_REQUEST_IID` in merge request pipelines and store a
  token as a masked CI/CD variable named `ACHILLES_GITLAB_TOKEN`: a project access
  token with the `api` scope and the Reporter role is enough (`CI_JOB_TOKEN` cannot
  write notes). Achilles posts the Markdown summary once and updates that same note on
  every later run. It only ever edits a note that starts with its marker and was
  written by the token's own user, so a note someone else plants is left alone. The
  project and API URL come from `CI_PROJECT_ID` and `CI_API_V4_URL`; outside GitLab CI
  pass `--gitlab-project` (and the API defaults to gitlab.com). With `--ai`, nothing is
  posted if the AI review did not finish.
- **Schema.** The security reports declare version 15.0.0 of GitLab's
  [security report schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas),
  the oldest of the 15.x line, and use only fields present in every 15.x version.
  Secret findings name the scanned commit (`$CI_COMMIT_SHA`, or `--source-commit`).
- **Only new findings on a merge request:** add
  `--diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME` in merge request pipelines
  (fetch that branch first, or set `GIT_DEPTH: "0"`), and a committed baseline as
  described in [Reports & Gating](reports-and-gating.md).

The GitHub-specific outputs (`--github`, `--pr-comment`, `--pr-review`,
`--file-issues`, `--fix-pr`) have no GitLab counterpart yet.

## Keeping history across CI runs

By default a CI scan's Evidence Vault is ephemeral — it lives and dies with the
job, and the scan hub publishes its results as workflow artifacts (HTML report,
SARIF, Markdown, threat model) with **no central vault**. There are two ways to keep
history:

- **Baselines.** Commit `.achilles/baseline.json` (see
  [Reports & Gating](reports-and-gating.md)) and let the gate fail only on findings
  that are new relative to it. This needs no shared storage.
- **A shared PostgreSQL vault.** Point `--vault-backend postgres` at a database your
  runner can reach (DSN in `ACHILLES_VAULT_DSN`, supplied from a repository secret)
  and use `--vault-tenant <project>` to group the repos. The War Room running on
  your own machine or server against the same database then shows those scans. This
  works for self-hosted runners that can see your database; GitHub-hosted runners
  need the database to be reachable from the internet, which you should only do
  deliberately and over TLS. It is not set up by any of the bundled workflows.

If you do write to a vault from CI, the vault is load-bearing: if those writes fail
the run exits non-zero rather than silently reporting success.

## Which option?

| You want… | Use |
|-----------|-----|
| AI-verified results and issues for one repo | A |
| Block risky PRs, no LLM, no secrets | B (per-PR gate) |
| Deep AI analysis with per-task models | B2 (routed full scan) |
| One place to scan many repos, no per-repo setup | C (scan hub) |
| Many repos on a schedule, from one machine | [Fleet](fleet.md) |
| A GitLab pipeline | [GitLab CI](#gitlab-ci) |
