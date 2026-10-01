# Fleet

`achilles-fleet` scans many of your own repos in one run: it reads a fleet
definition (projects → targets) and dispatches an `achilles` scan for each target
into that project's **own** Evidence Vault. A *project* is just a namespace for
grouping related repos (the fleet file and the vault layout call it a `tenant`; it
is the same thing). It's a separate binary from `achilles` on purpose — the OSS
engine stays the single source of scanning truth; the fleet layer is just
orchestration. For scheduling it on a machine, see
[DEPLOY.md](../DEPLOY.md) → *Scheduled scans*.

## The fleet definition

```yaml
# fleet.yaml
tenants:
  - id: acme
    mode: commercial      # license mode for this project's scans
    profile: default      # scan profile
    targets:
      - /work/acme/api
      - /work/acme/web
  - id: globex
    mode: commercial
    profile: full
    targets:
      - /work/globex/monolith
```

See [`configs/fleet.example.yaml`](../configs/fleet.example.yaml).

## Git-source targets (no pre-existing filesystem)

A target is either a **path** (a plain string, as above) or a **git source** that
`achilles-fleet` clones itself. That is what lets a k8s pod, a CI job or a
bare `docker run` start with an empty filesystem and still scan repos:

```yaml
tenants:
  - id: acme
    targets:
      - /work/acme/api                                  # path (unchanged)
      - url: https://example.com/acme/example-app.git   # public repo, remote HEAD
      - url: https://example.com/acme/example-private.git
        ref: main                                       # branch | tag | full commit sha
        depth: 1                                        # default 1 (shallow)
        auth: {tokenEnv: ACME_GIT_TOKEN}                # env var NAME, not the token
      - url: git@example.com:acme/example-infra.git
        auth: {sshKeyEnv: ACME_DEPLOY_KEY}              # env var holding the PEM key
```

| Field | Notes |
|-------|-------|
| `url` | Required. `https://…`, `ssh://…`, `git@host:path`, or `file://…` (local mirrors / hermetic tests). **Anything else is rejected**, as is any URL with embedded credentials (`user:pass@`) or a query string. |
| `ref` | Optional branch, tag or full commit sha. Default: the remote's `HEAD`. |
| `depth` | Optional, default `1`. Raise it if a scan needs git history (`--diff`, blame). |
| `auth.tokenEnv` | Name of an env var holding an HTTPS access token. https URLs only. |
| `auth.sshKeyEnv` | Name of an env var holding the PEM private key *content*. ssh URLs only. |

Config is validated at load time with the project and target number in the error;
unknown keys (a typo like `tokenenv`) are errors rather than silent
unauthenticated clones.

**How a source is scanned.** For each job `FetchingRunner` creates a private
(`0700`) directory under `--workspace` (default: the OS temp dir), fetches the
source into it with the `git` binary (`init` + shallow `fetch` of the ref +
`checkout`; no submodules, no LFS), runs the normal scan against the checkout, and
**always** deletes the directory — on success, scan failure, fetch failure,
timeout, or SIGINT/SIGTERM. Fetching is bounded by `--fetch-timeout` (default 5m).
Path targets bypass all of this.

**Credentials.** The token or key is read from the environment variable named in
the config and travels only in the environment of the `git` process:

- *HTTPS token* → `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`
  injecting an `Authorization: Basic …` `http.extraHeader` (needs git ≥ 2.31). It
  is never in argv (`ps`), the URL, an on-disk git config, a log line, an error
  message or the Evidence Vault, and HTTP redirects are disabled while a token is
  in play so the header can't be replayed to another host. The header uses
  `x-access-token` as the username, which GitHub accepts; GitLab and most other
  hosts accept a personal/project access token the same way.
- *SSH key* → written `0600` into the job's private directory, passed via
  `GIT_SSH_COMMAND` (`BatchMode`, `IdentitiesOnly`), and deleted as soon as the
  fetch ends — before the scanner runs. Host keys use `StrictHostKeyChecking=accept-new`:
  hosts already in `known_hosts` are verified (a changed key fails), new hosts are
  trusted on first use. To pin hosts, bake `/etc/ssh/ssh_known_hosts` into the image.
- Prompts are disabled (`GIT_TERMINAL_PROMPT=0`), the user's/system git config is
  ignored (no stray `insteadOf` or credential helper), and `git` sees only a small
  allow-list of environment variables (`PATH`, `HOME`, proxy and CA vars) —
  `ACHILLES_LLM_API_KEY` and other projects' tokens are not passed to it. Any
  secret value (and any `user:pass@` that git echoes back) is scrubbed from error
  text before it is returned.

**Identity in the vault.** The run's `scan_meta` record stores the stable,
credential-free repo URL as `target` (not the throwaway checkout path, so
`--metrics` counts one target per repo) plus the resolved `commit` sha. The CLI
flags behind this are `achilles --target-label` / `--source-commit`.

With `--runner docker`, the workspace must be a path the Docker daemon can
bind-mount (in a container without a Docker daemon, use `--runner local`).

## Running it

```bash
make build   # builds bin/achilles AND bin/achilles-fleet

achilles-fleet \
  --config fleet.yaml \
  --achilles ./bin/achilles \
  --vault-backend file \
  --vault-root .achilles/tenants \
  --runner local \
  --concurrency 4
```

Each project's findings land at `<vault-root>/<id>/vault.jsonl` (file backend)
or under the key `tenant-<id>` (postgres backend) — the same layout the
War Room UI reads, so fleet-written data shows up there and in
`achilles --metrics`. Scans run in a bounded concurrent pool and are
failure-isolated: one project failing doesn't stop the rest.

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `fleet.yaml` | the fleet definition |
| `--achilles` | `achilles` | path to the engine binary |
| `--vault-backend` | `file` | `file` or `postgres` (postgres: DSN from `$ACHILLES_VAULT_DSN`, inherited by each scan) |
| `--vault-root` | `.achilles/tenants` | per-project vault root (file backend) |
| `--runner` | `docker` | tool runner passed to each scan: `local` or `docker` |
| `--concurrency` | `0` (=numCPU) | max concurrent scans |
| `--workspace` | OS temp dir | parent dir for ephemeral git-source checkouts |
| `--fetch-timeout` | `5m` | max time to fetch one git source |
| `--every` | `0` (off) | re-run the whole dispatch on this interval until SIGINT/SIGTERM |

## Scheduling

By default `achilles-fleet` runs once and exits (`1` if any scan failed), which
is what k8s `CronJob`s and host cron expect. Prefer that: let the
platform own the schedule. For a plain container with no scheduler, `--every`
loops the full dispatch instead:

```bash
achilles-fleet --config /fleet/fleet.yaml --runner local --every 24h
```

Runs never overlap (the interval counts from the end of one run to the start of the
next). SIGINT/SIGTERM cancels in-flight scans and fetches (their workspaces are
still removed) and exits `0`; a run with failures is reported but doesn't stop the
loop. The config is read once at start, so restart the container to pick up edits.

**Kubernetes `CronJob`** (git sources, tokens from a Secret):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: {name: fleet-nightly}
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: fleet
              image: registry.example.com/acme/achilles-fleet:latest
              args: ["--config", "/fleet/fleet.yaml", "--runner", "local",
                     "--vault-backend", "postgres", "--workspace", "/work"]
              envFrom: [{secretRef: {name: fleet-git-credentials}}]  # ACME_GIT_TOKEN, ACHILLES_VAULT_DSN, …
              volumeMounts:
                - {name: fleet-config, mountPath: /fleet}
                - {name: work, mountPath: /work}
          volumes:
            - {name: fleet-config, configMap: {name: fleet-config}}
            - {name: work, emptyDir: {}}
```

**docker compose** (self-scheduling, no cron):

```yaml
services:
  fleet:
    image: registry.example.com/acme/achilles-fleet:latest
    command: ["--config", "/fleet/fleet.yaml", "--runner", "local",
              "--vault-root", "/vaults", "--every", "24h"]
    environment:
      ACME_GIT_TOKEN: ${ACME_GIT_TOKEN}
    volumes: ["./fleet.yaml:/fleet/fleet.yaml:ro", "vaults:/vaults"]
    restart: unless-stopped
volumes: {vaults: {}}
```

## Routed LLM analyses across the fleet

The fleet can run the LLM agents per project and forward multi-model routing. The
API key is **not** put on any command line — each scan inherits
`ACHILLES_LLM_API_KEY` from the environment.

```bash
export ACHILLES_LLM_API_KEY=<key>
achilles-fleet \
  --config fleet.yaml --achilles ./bin/achilles \
  --vault-root .achilles/tenants --runner local \
  --llm-base-url https://ollama.com/v1 \
  --llm-model glm-5.2 \
  --model-config configs/models.ollama.yaml \
  --analyses triage,review,sca-advice
```

| Flag | Description |
|------|-------------|
| `--llm-base-url` | OpenAI-compatible endpoint forwarded to each scan |
| `--llm-model` | default/fallback model |
| `--model-config` | per-task routing YAML (see [LLM Triage & Agents](llm-and-agents.md)) |
| `--llm-auth` | credential mode forwarded to each scan: `key`, `api-key` or `none` |
| `--analyses` | comma-separated: `triage`, `review`, `sca-advice` |

`--analyses` is restricted to those three — vault-recording agents with no output
path. Threat-model (needs a per-file path) and auto-fix (writes side effects) are
deliberately **excluded** from fleet fan-out. Setting `--analyses` requires
`--llm-model`.

## Reviewing fleet results

- **Cross-project rollup:** `achilles --metrics --vault-backend postgres` (DSN in
  `$ACHILLES_VAULT_DSN`), or point `--vault` at one project's file, summarizes
  findings by severity/tool/rule and feedback FP-rate.
- **War Room:** `achillesd` serves a per-project UI plus a `/admin/fleet`
  cross-project rollup. The dashboard header has a **project switcher** listing every
  project with data — discovered from the backend (`tenant-` keys in PostgreSQL, or
  `<root>/<id>/vault.jsonl` dirs), so projects created by a scan appear even though
  scans never register themselves. Selecting one sets `?tenant=<id>` and persists it
  in a cookie. The War Room has no authentication; see
  [Running in containers](containers.md#security-model-no-authentication).

## Running it on a schedule

The fleet runs on any machine that has the image or the binaries: a compose
profile (`docker compose --profile fleet up -d`), host cron, or a Kubernetes
`CronJob` as shown above. See [DEPLOY.md](../DEPLOY.md) → *Scheduled scans*.
