# Security policy

Achilles is a security tool that runs scanners over source code, handles LLM API
credentials, and serves a web UI. Reports of vulnerabilities in it are welcome.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead:
**Security tab → "Report a vulnerability"** on this repository. Include what you found,
how to reproduce it, the version or commit, and the impact you expect.

You can expect an acknowledgement within a few days. This is a volunteer-maintained
project, so there is no guaranteed SLA, but confirmed vulnerabilities are prioritized
and fixed ahead of features, and you will be credited in the advisory unless you
prefer otherwise.

## Scope

In scope: the Achilles binaries (`achilles`, `achillesd`, `achilles-fleet`,
`achilles-eval`), the container image and compose files, and the GitHub Action.
Areas of particular interest:

- the War Room's local-only protections (`achillesd`) — getting it to accept a
  request it should refuse: a `Host` header outside the allowlist (DNS rebinding), a
  cross-origin state-changing request, or binding a non-loopback address without
  `--allow-remote`; and reading one project's data through another;
- the fleet's git fetching and credential handling (`internal/fleet`);
- anything that leaks LLM API keys, vault connection strings or git credentials to
  logs, argv, the Evidence Vault or error text;
- command or argument injection through configuration, findings or repository content;
- the Evidence Vault's integrity guarantees (append-only, project separation).

Out of scope: findings in the third-party scanners Achilles runs (report those
upstream), issues that need an already-compromised host or a malicious operator, and
the **absence of authentication** in the War Room — that is a documented design
decision (see below), not a vulnerability.

## Security model: the War Room has no authentication

Achilles is built for one person scanning their own repositories. `achillesd` ships
**no login, no roles and no per-user access control**. Anyone who can reach its port
can read every finding and can submit feedback, create projects, purge data and view
the fleet rollup. It is protected by being reachable only from your own machine:

- it listens on loopback (`127.0.0.1:8080`) by default and refuses any other address
  unless you pass `--allow-remote`;
- the docker compose stack publishes the port on `127.0.0.1` only;
- the `Host` header must be `localhost`, `127.0.0.1` or `::1`, or a name listed in
  `--allowed-hosts` — this defeats DNS rebinding;
- state-changing requests are protected against cross-site requests (cross-origin
  `POST`s are rejected);
- secrets found in code are redacted before they reach the UI or API: a credential
  finding's matched text is withheld outright, other text is pattern-masked, and the
  audit export never serves raw scanner output. The Evidence Vault on disk is the
  unredacted record, so protect that file (it is created owner-only).

Feedback recorded through the War Room is ordinary analyst feedback: with
`--calibrate` (off by default) enough false-positive labels on a rule will rule that
rule's low- and medium-severity findings out of later scans. Anyone who can reach the
port can therefore influence those scans, which is one more reason to keep it local.

Do not bind it to a LAN or public address, or forward its port, expecting a login to
protect it. To share it, put your own authenticating reverse proxy in front of it (and
add the proxy's hostname to `--allowed-hosts`), or don't share it. See
[docs/containers.md](docs/containers.md#security-model-no-authentication).

## Security model: AI verdicts are advice, not a security boundary

The AI review reads code from the repository it is judging, and by default a
confident "false positive" verdict takes a finding out of the `--fail-on` gate, the
issues Achilles files, and the headline counts (it stays listed in a separate
section of every report, and in SARIF as a suppressed result). That makes the
scanned repository an adversary: a comment in the code can try to talk the model into
dismissing a real vulnerability. Mitigations in place: every prompt tells the model,
first, that repository text is untrusted data, and marks where each piece of it
begins and ends with an id that is random per request, so text in the code cannot
pose as the end of the code or as an instruction; a second adversarial pass tries to refute
each verdict; findings about credentials are never sent to the model and never
dismissed; low-confidence and overturned verdicts are never dismissed; and the
second pass can rule a finding out only by quoting code that Achilles verifies was in
the prompt, never on its say-so.

None of that is a guarantee. **Do not rely on the AI review to gate code from authors
you do not trust**: for that, run with `--keep-dismissed` (the gate then uses raw
scanner severity) or do not enable `--triage`. Reports of a prompt-injection that
reliably flips a verdict are in scope.

Code near each finding is sent to the LLM endpoint you configure, with credentials
masked. `--llm-no-code` sends no source at all, and a local model (`--llm-provider
ollama`) keeps everything on your machine.

Filing findings as GitHub issues publishes vulnerability details to everyone who can
read the repository. Achilles refuses to do so in a public repository unless you pass
`--allow-public-issues`.

## Security model: the scanned repository can configure the scanners

Scanners read ignore lists and configuration from the repository they scan:
`.gitleaks.toml` and `.gitleaksignore`, `.trivyignore` and `trivy.yaml`,
`.semgrepignore`, `osv-scanner.toml`, and inline comments such as `#nosec`,
`nosemgrep` and `gitleaks:allow`. That is how a team records "we looked at this and
it is fine". It also means a pull request can add a secret and the allowlist entry
that hides it in the same change.

What Achilles does about it:

- Every such file that is present is named on stderr and in the reports, so a
  suppression is never silent.
- With `--diff`, a change that modifies one of those files gets a warning in the
  output and at the top of every report.
- `--no-repo-config` refuses them: files Achilles would pass to a scanner are not
  passed, and a scanner that reads one on its own (most do) is reported as
  **incomplete**, which fails a `--strict-tools` run. Its findings still count; its
  silence is not treated as evidence.

What it does not do: `--no-repo-config` does not neutralize inline suppression
comments, and it cannot make a scanner ignore a file it loads by itself. If you gate
code from authors you do not trust, review changes to those files and comments as
part of the change, or scan a checkout from which they have been removed.

## Deploying safely

See [docs/containers.md](docs/containers.md). In short: keep the War Room on
loopback; provide secrets (LLM keys, `ACHILLES_VAULT_DSN`, git tokens) through
environment variables or your secret store, never flags or committed files; and
change the default `POSTGRES_PASSWORD` if you ever publish the database port.

## Supported versions

Only the latest release (and `main`) receive security fixes.
