# Running in containers

Achilles runs anywhere Docker does — a laptop, a VM, Kubernetes. Nothing here needs a
cloud account. This guide covers the bundled image, the compose stack, and how the
pieces are secured.

## Five-minute quickstart

You need Docker with Compose v2 and ~2 GB of disk (the image bundles the scanners).

```bash
git clone https://github.com/Warzuponus/achilles.git && cd achilles/deploy/compose
docker compose up -d --build                    # PostgreSQL + War Room
docker compose --profile scan run --rm scan     # scan the bundled vulnerable sample
```

Open <http://127.0.0.1:8080> (change the port with `WARROOM_PORT`). There is no
login: the port is published on your machine's loopback only (see
[Security model](#security-model-no-authentication)). The dashboard lists
the run; open it to see findings from Opengrep and gosec, and submit verdicts that feed
the learning loop.

This exact sequence is run in CI on every relevant change
([quickstart.yml](../.github/workflows/quickstart.yml) via `deploy/compose/smoke.sh`).

**Scan your own code**

```bash
TARGET=/path/to/your/repo TENANT=my-app docker compose --profile scan run --rm scan
```

The repo is mounted read-only; findings land in the War Room under the `my-app`
project (a project groups the repos you scan; `TENANT` is the compose variable that
names it).
Pass more flags by editing the `scan` service's `command` (e.g. `--fail-on high`,
`--html-report`, `--triage` with an LLM — see [LLM Triage & Agents](llm-and-agents.md)).

## What's in the image

`deployments/achilles/Dockerfile` builds one image with `achilles`, `achillesd`,
`achilles-fleet`, `achilles-eval` and the baseline scanners — Opengrep, gosec, Trivy,
Gitleaks, osv-scanner — so scans run **inside** the container with `--runner local`.
There is no docker socket and no docker-in-docker. Each downloaded binary is pinned by
version and sha256 and verified at build time.

| Variant | Build | Contains | Scans Go? |
|---------|-------|----------|-----------|
| full (default) | `docker build -f deployments/achilles/Dockerfile .` | scanners + Go toolchain | yes |
| slim | `--build-arg WITH_GO=false` | scanners only (~250 MB smaller) | no — gosec **fails loudly** |

Published images (when releases are cut) are `ghcr.io/<owner>/<repo>:<version>` and
`:<version>-slim`, for amd64 and arm64.

Not included: the heavy `--profile full` per-language tools (SpotBugs, Psalm, Security
Code Scan, clang-tidy, Bandit, Checkov, …). They need their own runtimes (JVM, PHP,
.NET, Python, a C toolchain). Build their images from `deployments/<tool>/` and use
`--runner docker` on a host with a Docker daemon, or extend the Dockerfile for the
languages you need.

Network: Trivy fetches its vulnerability database and osv-scanner queries OSV, so scans
need outbound HTTPS. Air-gapped use is not supported today.

## A scan that could not run is not a clean scan

The image sets `ACHILLES_STRICT_TOOLS=true` (`--strict-tools`). If a scanner is
missing, cannot run, or its output cannot be parsed, the run **fails with exit 2**
instead of printing "no findings". Exit codes: `0` ok, `1` findings at/above
`--fail-on`, `2` the run itself failed (including an incomplete scan).

Tools that shell out to something else declare it in `configs/tools.yaml`
(`requires: [go]` for gosec), so a missing prerequisite is reported as that tool's
failure rather than as an empty report. Outside the image the flag is opt-in, so
existing CI keeps working; the human report still never says "Clean scan" when a
tool failed.

## How the compose stack is wired

```
 you ──▶ 127.0.0.1:8080 ──▶ warroom (achillesd --allow-remote) ──▶ postgres
        (loopback only)                                           not published
 scan / fleet jobs ───────────────────────────────────────────────▶ postgres
```

- **PostgreSQL** is the Evidence Vault (`--vault-backend postgres`). The connection
  string reaches containers as `ACHILLES_VAULT_DSN` — an environment variable, never a
  flag, because it carries a password. Data lives in the `pgdata` volume; back it up
  with `pg_dump`. Projects are keys (`tenant-<id>`) in one table; use separate databases
  if you need isolation that survives a bug.
- **The War Room is published on `127.0.0.1` only** (`127.0.0.1:${WARROOM_PORT}:8080`),
  so only processes on your machine can reach it. Inside the container it must listen
  on `0.0.0.0` for Docker's port mapping to work, so the compose file starts it with
  `--allow-remote` — the explicit opt-in `achillesd` requires to bind a non-loopback
  address. Do not change the published address to `0.0.0.0` or remove the `127.0.0.1:`
  prefix unless you have put your own authenticating proxy in front (below).
- The default database password is a placeholder for a port that is never published.
  Set `POSTGRES_PASSWORD` in `.env` if you publish or share the database.

## Security model: no authentication

**The War Room has no authentication.** Anyone who can reach its port can read every
finding and can submit feedback, create projects, purge data and view the fleet
rollup. Achilles is built for one person scanning their own repositories, and it
protects that case by limiting who can reach the port rather than by identifying
users:

- `achillesd` listens on **loopback** (`127.0.0.1:8080`) by default and **refuses to
  bind any other address without `--allow-remote`**.
- In compose, the port is published on **`127.0.0.1` only**.
- The `Host` header must be `localhost`, `127.0.0.1` or `::1`, or a name you list
  with `--allowed-hosts a,b`. This defeats DNS-rebinding, where a web page tries to
  reach your local server under an attacker's hostname.
- State-changing requests are protected against cross-site requests (Go's
  `http.CrossOriginProtection`): a cross-origin `POST` is rejected, so another site
  open in your browser cannot submit feedback or purge data on your behalf.
- Secrets in findings are redacted before they reach the UI or API.

What this does **not** give you: any separation between people. Do not bind the War
Room to a LAN or public address, and do not forward its port, expecting a login to
protect it. Achilles ships none.

### Sharing the War Room

Preferably don't. If you must, put **your own authenticating reverse proxy** in front of it (Authelia,
Caddy or nginx with basic auth, your SSO gateway, a VPN, an SSH tunnel) and
add the hostname people will use to `--allowed-hosts`. Keep the War Room itself
unreachable except through that proxy. The proxy, not Achilles, is then responsible
for who gets in; every person it admits can see every project and change any data.

## Recurring scans: the fleet

`achilles-fleet` scans many repos (grouped into projects), including **git URLs** it clones into an
ephemeral workspace (no pre-existing filesystem needed). In compose:

```bash
cp ../../configs/fleet.example.yaml fleet.yaml   # edit projects and targets
docker compose --profile fleet up -d             # re-runs every FLEET_EVERY (default 24h)
```

Credentials for private repos come from environment variables *named* in `fleet.yaml`
(`auth.tokenEnv`), passed to the container from your secret store — see
[Fleet](fleet.md). For SSH sources add `openssh-client` to the image.

## Local models

```bash
docker compose --profile ollama up -d
docker compose exec ollama ollama pull <model>
# in .env:
#   ACHILLES_LLM_BASE_URL=http://ollama:11434/v1
#   ACHILLES_LLM_AUTH=none
#   ACHILLES_LLM_MODEL=<model>
```

Then add `--triage` (etc.) to the `scan` service's command. Any OpenAI-compatible
endpoint works; quality varies by model — see
[Any OpenAI-compatible provider](llm-and-agents.md#any-openai-compatible-provider).
CPU-only models are slow: raise `ACHILLES_LLM_TIMEOUT`.

## Kubernetes

The same image and flags map directly:

- **War Room**: a `Deployment` running `achillesd --addr :8080 --allow-remote
  --vault-backend postgres`, with `ACHILLES_VAULT_DSN` from a `Secret`. There is no
  authentication, so keep the Service cluster-internal and reach it with
  `kubectl port-forward` (use `--allowed-hosts` for any other hostname), or put your
  own authenticating proxy in front — see [Sharing the War Room](#sharing-the-war-room).
- **Scans**: a `CronJob` running `achilles-fleet --config /etc/achilles/fleet.yaml
  --vault-backend postgres --runner local --workspace /tmp/fleet` (no `--every`; the
  CronJob is the scheduler), `fleet.yaml` from a `ConfigMap`, git credentials from a
  `Secret`. Give the pod outbound HTTPS and an `emptyDir` for `/tmp`.
- Run as the image's non-root user (uid 10001); the root filesystem can be read-only
  apart from `/tmp` and `$HOME`.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `port is already allocated` | something else uses 8080 — set `WARROOM_PORT` |
| scan exits 2: `gosec needs go on PATH` | you built the slim variant and scanned Go; use the full image |
| scan exits 2: a tool `failed` | read the line above it; usually no network for Trivy/osv-scanner |
| War Room shows no runs | the scan wrote to a different `TENANT` (project); pick it in the project switcher |
| `403 host not allowed` | you browsed to the War Room under a hostname or IP other than `localhost` / `127.0.0.1` / `::1`; add that name with `--allowed-hosts` (and keep the port private) |
| a form submission is rejected with `403` | the request came from another origin (a different site, or a proxy that rewrites `Origin`); open the War Room directly at its own address |
| `achillesd` refuses to start with a non-loopback `--addr` | you set `--addr` to something other than loopback; add `--allow-remote` only if the port is not reachable by others |
