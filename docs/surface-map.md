# Surface map and risk-ordered review (`--prioritize surface`, `--plan-out`)

Before the scanners run, Achilles can map where the target is exposed: where
attacker-influenced input enters, where it could do damage, what guards it, what is
worth stealing, and where the code talks to an LLM. It scores every file from that
map and uses the score to decide **which findings the AI review and deep
verification look at first**. When `--llm-budget` or `--max-cost` runs out, what was
left unreviewed is then the least exposed code, not just the least severe.

No model is called. The map is a line-level pattern match over the source, so it
costs seconds and no tokens, and it runs the same way with `--llm-no-code`.

```bash
# Review the most exposed findings first, and keep the map
achilles --triage --deep-verify 10 --prioritize surface --plan-out plan.json ./src

# Only the map, no AI at all
achilles --plan-out plan.json ./src
```

## What it can and cannot change

The map **only orders work**. It never removes a finding, never lowers a severity,
never skips a scanner and is never a reason to dismiss a finding. Every finding is
still reviewed when the budget allows, and a finding the budget did not reach is
reported as unreached, exactly as with severity order. A wrong map therefore costs
ordering, never coverage.

`--prioritize severity` (the default) is the order Achilles has always used: most
severe first.

## What the map looks for

| Kind | Examples | Where it comes from |
|------|----------|---------------------|
| Entry points | HTTP routes and handlers, request input, gRPC services, message consumers, CLI arguments | the same detector that feeds the entry-point hints in triage |
| Dangerous operations | SQL execution, running programs, `eval`, deserialization, file access, outbound requests, unescaped HTML, redirects, XML parsing | per-language patterns |
| Guards | authentication and authorization checks, CSRF protection, validation and escaping, rate limiting | coarse patterns across languages |
| Assets | credentials, personal data, sessions and tokens; credential files by name (never opened) | |
| AI surface | LLM SDK calls, tool definitions given to a model, MCP servers and clients, vector stores, prompt construction | |
| Deployment files | Dockerfiles, Compose, Terraform, Helm, Kubernetes manifests, CI workflows | by name (Kubernetes by content) |

Dependency and build trees (`node_modules`, `vendor`, `dist`, `third_party`, ...),
`.git`, the Evidence Vault and credential files are skipped, the same set the deep
verifier refuses to read. The walk stops at 20,000 files or 256 MiB and says so on
stderr when it does; files past that point score 0 and keep severity order.

## How a file is scored

Each file gets a score from 0 to 1, with the reasons in the plan:

| Signal | Adds |
|--------|------|
| takes network input (route, handler, request input, consumer) | 0.45 |
| takes only command-line or local input | 0.15 |
| has a dangerous operation (more for each extra kind, up to two) | 0.25 to 0.35 |
| network input and a dangerous operation in the same file | 0.10 |
| ... and no guard seen anywhere in that file | 0.10 |
| handles credentials, personal data or sessions | 0.10 |
| calls an LLM or exposes tools to one | 0.10 |
| test file or `testdata/` | score × 0.25 |

A finding's priority is its severity rank (critical 5 ... info 1) times
`1 + 0.5 × score`. So a medium finding in the most exposed file (4.5) is reviewed
before a high one in a file with no surface (4), while nothing below high can ever
overtake a critical. `--deep-verify` uses the same priority, but only to order
findings inside each of its tiers: which findings qualify, and in which tier, does
not change.

These weights are a starting point. They are not yet tuned against the detection
benchmark.

Read the scores as hints. A handler is often registered in another file, so a file
with no entry point can still be reachable, and a guard seen somewhere in a file
does not mean the flagged line is behind it.

## The plan file

`--plan-out` writes one JSON document (also recorded in the Evidence Vault as a
`scan_plan` record whenever the map is built):

```json
{
  "version": 1,
  "target": "src",
  "filesRead": 412,
  "summary": {"entries": 38, "sinks": 91, "controls": 22, "assets": 17, "ai": 3},
  "hotspots": [
    {"file": "api/admin.py", "score": 1,
     "reasons": ["takes network input", "dangerous operation: exec, sql",
                 "input and dangerous operation in the same file", "no guard seen in this file"]}
  ],
  "aiFiles": ["agent/bot.py"],
  "infra": [{"file": "Dockerfile", "kind": "dockerfile"}],
  "facts": [{"kind": "sink", "class": "sql", "file": "api/admin.py", "line": 7, "summary": "SQL execution"}]
}
```

It carries kinds, files, line numbers and fixed summaries (route paths are bounded
and scrubbed), never source text and never the absolute path of the target. At most
500 hotspots and 5,000 facts are kept; `factsDropped` counts the rest.

## Where this is going

This is the first step of a pre-scan modelling phase. Later steps will add a
committed threat-context file, scanner choice from the map, an optional grounded
LLM pass that names components and trust zones, and hypothesis checks for missing
controls by the deep verifier.
