# MCP Server

`achilles mcp` lets an assistant that speaks the
[Model Context Protocol](https://modelcontextprotocol.io) read the Evidence Vault:
what the scans found, what the AI review concluded and why, and what fix was
proposed. You can then ask, in the editor or terminal where you work, things like
"what did the last scan find in the auth package?" or "why was the SQL injection in
`db/query.go` kept?" without opening a report.

It is experimental: the protocol handling is covered by tests, but it has not been
exercised against every client.

## Setting it up

The client starts the server; you do not run it yourself. Point it at the vault your
scans write to (by default `.achilles/vault.jsonl` in the directory you scan from).

Claude Code:

```bash
claude mcp add achilles -- achilles mcp --vault /path/to/project/.achilles/vault.jsonl
```

Any client configured with JSON (a project's `.mcp.json`, for example):

```json
{
  "mcpServers": {
    "achilles": {
      "command": "achilles",
      "args": ["mcp", "--vault", "/path/to/project/.achilles/vault.jsonl"]
    }
  }
}
```

Use an absolute path: clients do not all start servers in the project directory. For
a shared PostgreSQL vault, pass `--vault-backend postgres --vault-tenant <project>`
and provide the connection string in `ACHILLES_VAULT_DSN` through the client's `env`
setting.

The transport is stdio. There is no network listener and nothing to authenticate:
the server can read what the user who started the client can read.

## Tools

| Tool | What it returns |
|------|-----------------|
| `list_scans` | the scans in the vault, newest first: when, what was scanned, how many findings, and which tools failed or could not analyze everything |
| `list_findings` | the findings of one scan (default: the newest), most severe first, each with its verdict if it was reviewed. Filters: `min_severity`, `status` (`open`, `confirmed`, `dismissed`, `unreviewed`), `limit`, `offset` |
| `get_finding` | one finding in full, by fingerprint: the scanner's message, the code around it, the verdict and its reasoning, the proposed fix and whether re-scanning verified it, recorded feedback, and how many scans reported it |
| `rule_health` | per rule, how analysts have labeled its findings, and whether `--calibrate` would rule the rule out |

`list_findings` returns the findings as the scanners reported them in that run, before
any baseline or `--diff` filter, so it can list more than the scan's own report did.

## What it will not do

**It does not write.** No tool records feedback, dismisses a finding, starts a scan or
changes a file, and the server's handle on the vault refuses writes. This is on
purpose. The assistant on the other end has just read text that came out of a scanned
repository, and that text can contain instructions. If a tool could change what
Achilles believes about a finding, hostile code could talk its own finding away
through the assistant. Record feedback with `achilles --feedback`, or in the War Room.

**It does not serve secrets.** A credential finding is listed, because someone has to
rotate the credential, but without its matched text and without the code around it.
Other text passes through the same masking the War Room applies.

**It does not trust what it serves, and neither should the assistant.** Scanner
messages, model reasoning, code and diffs are copied from scanned repositories and from
models that read them. Every result says so, and the server tells the client at
start-up to treat that text as data. That reduces the risk of a prompt injection
reaching the assistant through a finding; it does not remove it. Use the server with
repositories and assistants you would be comfortable pairing anyway, and keep the
assistant's own permissions tight.

**It bounds its answers.** Lists are capped (50 findings by default, 200 at most) and
long text is cut, so one answer cannot fill an assistant's context.

## Notes

- A scan that lists `incompleteTools` did not cover everything. An empty list of
  findings from it is not evidence of safety, and the server says the same to the
  client.
- If the vault cannot be read, a tool answers with an error rather than an empty
  result.
- The server reads the vault as it is at each call, so a scan that finishes while the
  client is open is visible to the next question.
- It speaks protocol revisions 2024-11-05, 2025-03-26 and 2025-06-18, and offers only
  the tools capability.
