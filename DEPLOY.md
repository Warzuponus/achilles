# Achilles — Deployment

Achilles is **local-first**: it runs on your own machine or in your own GitHub Actions,
needs no cloud account, and has no authentication layer. This guide covers the four
ways to run it. See [DESIGN.md](DESIGN.md) for architecture and
[README.md](README.md) for flags.

| I want to… | Use |
|------------|-----|
| scan a repo from my workstation | [A. The CLI](#a-the-cli-on-a-workstation) |
| a War Room UI, a shared database, or a local LLM, on my machine | [B. Docker / docker compose](#b-docker--docker-compose) |
| gate pull requests, run LLM scans in CI, scan other repos from one place | [C. GitHub Actions](#c-github-actions) |
| scan many repos on a schedule, unattended | [D. Scheduled scans](#d-scheduled-scans-with-the-fleet) |

## What is and is not verified

Be explicit about the evidence behind each path:

| Path | Evidence |
|------|----------|
| CLI + file vault | Unit and integration tests in CI (`make test`); the repo scans itself on every PR ([self-scan.yml](.github/workflows/self-scan.yml)). |
| Docker image + compose stack | [quickstart.yml](.github/workflows/quickstart.yml) runs the full compose quickstart (build, start, scan the bundled sample with `--strict-tools`, check the findings in the War Room, check the Host and cross-origin protections) on every relevant change. |
| GitHub Action + per-PR gate | [ci.yml](.github/workflows/ci.yml) runs the action from the checkout (`version: source`) against the bundled sample with `--strict-tools` on every PR; the example workflows are the reference consumers. The release-binary download path, which is what users get by default, is **not exercised by CI**: check it by hand after each release ([CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainers)). |
| Scan hub | An example workflow, not exercised by CI: it needs a GitHub App you create (below). Treat the setup steps as a checklist to verify in your own organisation. |
| Fleet on cron / Kubernetes | The fleet binary is tested ([fleet.md](docs/fleet.md)); the `CronJob` and cron snippets are **patterns, not tested manifests**. |
| Multi-user / network exposure | **Not a supported configuration.** There is no authentication. See [Security model](docs/containers.md#security-model-no-authentication). |

---

## A. The CLI on a workstation

The simplest setup: one Go binary, scanners on `PATH` (or `--runner docker`), results
in a local file vault.

```bash
make build                           # -> bin/achilles
./bin/achilles --html-report report.html /path/to/code
```

- The Evidence Vault is a JSONL file at `.achilles/vault.jsonl` (`--vault` to
  move it). It is the audit trail and the learning corpus.
- Group related repos into a **project**. With the file backend a project is a
  directory the War Room can find: scan with
  `--vault .achilles/tenants/<project>/vault.jsonl`. With PostgreSQL use
  `--vault-tenant <project>` (default `default`).
- To browse results in the War Room, run it over the same vault root:

  ```bash
  ./bin/achilles --vault .achilles/tenants/default/vault.jsonl /path/to/code
  ./bin/achillesd --vault-root .achilles/tenants      # http://127.0.0.1:8080
  ```

  `achillesd` listens on loopback only. It has **no authentication**; read
  [Security model](docs/containers.md#security-model-no-authentication) before
  binding it to anything else.
- LLM triage, the review agents and model routing are opt-in and work with any
  OpenAI-compatible endpoint, including a local Ollama:
  [LLM Triage & Agents](docs/llm-and-agents.md).

Full walkthrough: [Getting Started](docs/getting-started.md);
every flag: [CLI Reference](docs/cli-reference.md).

---

## B. Docker / docker compose

One image holds `achilles`, `achillesd`, `achilles-fleet`, `achilles-eval` and the
baseline scanners. The compose stack runs PostgreSQL (the shared Evidence Vault) and
the War Room, plus optional `scan`, `fleet` and `ollama` profiles:

```bash
cd deploy/compose
docker compose up -d --build
docker compose --profile scan run --rm scan
# open http://127.0.0.1:8080
```

The War Room is published on `127.0.0.1` only. Everything about this path — the image
variants, what the stack looks like, scanning your own code, local models,
Kubernetes notes, the security model and troubleshooting — lives in
**[docs/containers.md](docs/containers.md)**; it is not repeated here.

---

## C. GitHub Actions

GitHub's code-scanning UI (the repo's Security tab) is the front end; Achilles is
the scanner and the gate. No Achilles server is involved, and each run's Evidence
Vault is ephemeral (it lives inside that run) unless you point it at a PostgreSQL
database you operate.

### The action

[`action.yml`](action.yml) is a composite action. It downloads the release binary
(checksum-verified; nothing is compiled), installs the hash-pinned scanners with
`achilles tools install`, scans, writes `report.html`, `report.md` and
`achilles.sarif`, uploads them as the `achilles-report` artifact, and can open
GitHub issues for findings. The full input table and the safe-trigger rules are in
[CI & the Scan Hub](docs/ci-and-hub.md#option-a--ai-verified-scan-of-your-repo-with-issues-start-here).

The shortest useful setup is [`examples/workflows/achilles.yml`](examples/workflows/achilles.yml):
one secret (your LLM key), one variable (the model name), and `permissions: issues: write`.

Reference it as `uses: Warzuponus/achilles@<tag>`. Pin a tag or a commit SHA.

### Per-PR gate (no LLM, no secrets)

Copy [`examples/workflows/scan-example.yml`](examples/workflows/scan-example.yml):
inline annotations on the diff, a SARIF artifact, and a gate that fails only on
**newly introduced** findings (`--diff` + `--baseline` + `fail-on`). It needs no
secret, so it works on fork PRs too.

```yaml
permissions:
  contents: read
  security-events: write   # only for upload-sarif
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # for --diff against the base ref
      - uses: Warzuponus/achilles@v0.1.0
        with:
          fail-on: high
          upload-sarif: "true"
          args: >-
            --diff origin/${{ github.base_ref }}
            --baseline .achilles/baseline.json
```

Uploading SARIF to the Security tab is free on public repos but needs GitHub
Advanced Security on private ones. Without it the upload step cannot publish; you
still get annotations, the gate, and the report as a downloadable artifact.

Regenerate a baseline after intentional changes:
`achilles --write-baseline .achilles/baseline.json .`

### Routed LLM scan

[`scan-ollama-example.yml`](examples/workflows/scan-ollama-example.yml) is a scheduled,
LLM-assisted scan with per-task model routing (see
[`configs/models.ollama.yaml`](configs/models.ollama.yaml)). Add **one** secret,
`ACHILLES_LLM_API_KEY`, in the repository settings (never paste a key into a
workflow). The endpoint is configuration (`ACHILLES_LLM_BASE_URL`); point it at any
OpenAI-compatible service. Details: [CI & the Scan Hub](docs/ci-and-hub.md).

### The scan hub (scan other repos from one place)

[`examples/workflows/scan-hub.yml`](examples/workflows/scan-hub.yml) scans **other**
repositories from one hub repository, so the LLM key lives in one place and targets
need no secrets and no workflow. It is an example: copy it into `.github/workflows/`
of a private repository of your own. Results are **workflow artifacts** (HTML report,
SARIF, Markdown summary) of the hub run — there is no cloud vault. Nothing is
written back to the target unless you tick `file_issues` (the App then also needs
**Issues: Write**).

Cross-repo read is granted by a **GitHub App** (short-lived, per-repo tokens, not a
personal token). One-time setup by an org or repo admin:

1. Create a GitHub App in the org: repository permission **Contents: Read** only,
   no webhook. Note the App ID; generate a private key (`.pem`).
2. Install the App on the repositories you want scannable — only those get read
   access.
3. In the hub repository → Settings → Secrets and variables → Actions, add:
   - secret `SCANNER_APP_ID` — the App ID
   - secret `SCANNER_APP_PRIVATE_KEY` — the full `.pem` contents
   - secret `LLM_API_KEY` — the LLM key
   - variable `LLM_MODEL` — a model your provider serves
4. Run it: Actions → *Achilles scan hub* → *Run workflow* with
   - `target_repo` — the repository name (the owner is this repository's owner)
   - `ref` — optional branch, tag or SHA (blank = default branch)
5. Download the report from the run → Artifacts → `achilles-report`.

To also post SARIF to a target's Security tab, the App needs **Code scanning:
Write** on that repo and the workflow an upload-sarif step; central artifacts are
the default, lower-privilege path. To scan a list of repos, add a matrix over the
`target_repo` input.

---

## D. Scheduled scans with the fleet

`achilles-fleet` scans many repos (local paths or git URLs it clones itself) into
per-project vaults. It runs on any machine with the image or the binaries; the
config format, git credentials and flags are in **[docs/fleet.md](docs/fleet.md)**.
Three ways to schedule it:

**docker compose profile** (self-scheduling; re-runs every `FLEET_EVERY`, default
24h):

```bash
cd deploy/compose
cp ../../configs/fleet.example.yaml fleet.yaml     # edit projects and targets
docker compose --profile fleet up -d
```

**cron** (one run, then exit; exit code 1 if any scan failed):

```cron
0 2 * * *  cd /srv/achilles && ACHILLES_VAULT_DSN=... ACME_GIT_TOKEN=... \
  achilles-fleet --config fleet.yaml --runner local --vault-backend postgres --workspace /tmp/fleet
```

**Kubernetes `CronJob`**: the same image and flags; `fleet.yaml` from a `ConfigMap`,
git tokens and `ACHILLES_VAULT_DSN` from a `Secret`, an `emptyDir` for the
workspace, `concurrencyPolicy: Forbid`. A full manifest is in
[docs/fleet.md](docs/fleet.md#scheduling); run it as the image's non-root user.

To review the results, run the War Room (path B) against the same PostgreSQL
database, or use `achilles --metrics --vault-backend postgres` for a rollup.

---

## LLM and secrets (all paths)

- The LLM client is **OpenAI-compatible**: OpenAI, Azure OpenAI, Ollama, vLLM,
  LiteLLM, OpenRouter or a gateway. Switch with `--llm-base-url` and `--llm-auth`;
  no code change. See [LLM Triage & Agents](docs/llm-and-agents.md).
- Keys come from the environment only: `ACHILLES_LLM_API_KEY` (or
  `OPENAI_API_KEY`). In Actions, use repository secrets; in compose, `.env`; for a
  local model, no key.
- The vault connection string is `ACHILLES_VAULT_DSN`, also environment-only.
- Triage and research are **opt-in**; without an LLM, Achilles is a deterministic
  scanner plus gate.

## Licensing reminder

Keep AGPL tools (TruffleHog) invoked only as separate-process containers, never
imported — see [THIRD-PARTY.md](THIRD-PARTY.md). This holds in every deployment.
