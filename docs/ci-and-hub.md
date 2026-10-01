# CI & the Scan Hub

Three ways to run Achilles in GitHub Actions, from simplest to most powerful.
For every way to run Achilles (workstation, containers, CI, scheduled), see [DEPLOY.md](../DEPLOY.md).

## Option A — per-PR gate (in the repo being scanned)

Copy [`.github/workflows/scan-example.yml`](../.github/workflows/scan-example.yml)
into a repo. It runs on pull requests, annotates the diff, uploads SARIF to code
scanning, and fails only on newly-introduced high-severity findings. The core step:

```yaml
- uses: Warzuponus/achilles@main
  with:
    target: "."
    mode: "commercial"
    args: >-
      --diff origin/${{ github.base_ref }}
      --baseline .achilles/baseline.json
      --sarif-report achilles.sarif
      --github
      --fail-on high
```

The composite action installs the binary + the baseline scanners
(Opengrep, gosec, osv-scanner, Trivy, Gitleaks) for you. No LLM key needed.

## Option B — routed LLM full scan

Copy [`.github/workflows/scan-ollama-example.yml`](../.github/workflows/scan-ollama-example.yml)
for a scheduled, LLM-assisted scan using multi-model routing.

1. Add **one** repo/org secret: **`ACHILLES_LLM_API_KEY`** (your Ollama Cloud key).
   *Do this yourself — never hard-code a key in a workflow.*
2. The workflow sets `ACHILLES_LLM_BASE_URL=https://ollama.com/v1`, writes the
   routing inline (mirrors [`configs/models.ollama.yaml`](../configs/models.ollama.yaml)),
   and runs the agents + HTML report:

```yaml
env:
  ACHILLES_LLM_API_KEY: ${{ secrets.ACHILLES_LLM_API_KEY }}
  ACHILLES_LLM_BASE_URL: https://ollama.com/v1
# ... args: --model-config models.ollama.yaml --review --sca-advice
#           --threat-model tm.otm.json --html-report achilles-report.html
```

It uploads `achilles-report.html` (and SARIF/threat-model) as run artifacts.
Because full LLM scans are heavier than a gate, it runs on a schedule /
`workflow_dispatch`, not every PR.

## Option C — the central scan hub

Scan **other** repos from the Achilles repo, so the key + routing live in one place
and targets need **no secret and no workflow**. This is the GitHub-Actions
expression of the fleet model.
Workflow: [`.github/workflows/scan-hub.yml`](../.github/workflows/scan-hub.yml).

### One-time setup (org/repo admin)

1. **Create a GitHub App** in the org: repository permission **Contents: Read**
   only, no webhook, "Only on this account."
2. **Install it** on the repos you want scannable — only those get read access.
3. Add two secrets to `Warzuponus/achilles`:
   - `SCANNER_APP_ID` — the App's ID
   - `SCANNER_APP_PRIVATE_KEY` — the App's **private key** (the `.pem` contents,
     from the App's *Private keys* section — **not** the client secret)
   - (`ACHILLES_LLM_API_KEY` is already the scan-hub's LLM key.)

Set the private key reliably with:
```bash
gh secret set SCANNER_APP_PRIVATE_KEY -R Warzuponus/achilles < your-app.private-key.pem
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
# then a routed scan of ./target → achilles-report.html uploaded as an artifact
```

Inputs: `target_repo` (required, repo name only — the owner is this repository's owner)
and `ref` (optional branch/tag/SHA; blank = the default branch). Secrets:
`SCANNER_APP_ID`, `SCANNER_APP_PRIVATE_KEY`, and the LLM key `ACHILLES_LLM_API_KEY`.

**Least privilege by design:** a per-run token scoped to exactly the target repo
(not a personal PAT), and results are artifacts of the hub run — nothing is written
back to the target. To also post SARIF to a target's Security tab, grant the App
**Code scanning: Write** on that repo and add an upload-sarif step.

Download the report from **the run → Artifacts → `achilles-<repo>` → `achilles-report.html`**
(the same artifact also holds `achilles.sarif`, `achilles-report.md` and the threat
model). There is no cloud vault: the artifacts are the record.

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
| Block risky PRs, no LLM | A (per-repo gate) |
| Deep AI analysis on a schedule, per repo | B (routed full scan) |
| One place to scan many repos, no per-repo setup | C (scan hub) |
| Many repos on a schedule, from one machine | [Fleet](fleet.md) |
