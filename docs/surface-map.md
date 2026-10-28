# Surface map, threat context and scan plan (`--prioritize surface`, `--plan-out`, `--all-tools`)

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

# Every scanner the plan would skip, too
achilles --all-tools ./src
```

The same map, together with the repository's [threat-context
file](#the-threat-context-file), sets the [scan depth](#scan-depth) and the [tool
plan](#the-tool-plan): which scanners are worth running on this target.

## What it can and cannot change

The map **orders work and chooses scanners**. It never removes a finding, never
lowers a severity and is never a reason to dismiss a finding. Every finding is still
reviewed when the budget allows, and a finding the budget did not reach is reported
as unreached, exactly as with severity order.

The only scanners the [tool plan](#the-tool-plan) skips are ones with nothing to
analyze on this target, each named with a reason you can check, and `--all-tools`
turns every skip off.

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
| Deployment files | Dockerfiles, Compose, Terraform, Helm, Kubernetes, CloudFormation, ARM and Bicep templates, Serverless, CI workflows | by name, or by the head of a YAML or JSON file |

Dependency trees (`node_modules`, `vendor`, `third_party`, ...), `.git`, the Evidence
Vault and credential files are skipped, the same set the deep verifier refuses to
read. Build output (`dist`, `build`, `target`, `out`, `bin`, `obj`) is not scored;
it is only looked through for compiled JVM bytecode, which FindSecBugs needs. The
map also counts files per language and notes the project files some scanners need
(`go.mod`, `psalm.xml`, a .NET project, a Rails app, IaC files, GitHub workflows).
The walk stops at 20,000 files, 256 MiB or 200,000 directory entries and says so on
stderr when it does; files past that point score 0 and keep severity order, and the
tool plan then skips nothing.

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
| crown jewel ([threat context](#the-threat-context-file)) | 0.30 (a crown jewel with no other hint still gets it) |
| out of scope ([threat context](#the-threat-context-file)) | score × 0.25 |

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

## The threat-context file

Some things only the owners of the code know: whether a compromise would hurt the
business, whether it holds confidential data, which paths matter most and which are
never deployed. A repository says so in `.achilles/threat-context.yaml` (or `.yml`).
`achilles init` writes one with every question commented out:

```yaml
businessCritical: true     # would an outage or a compromise hurt the business or someone's safety?
confidentialData: true     # does it store or process confidential or regulated data?
externallyFacing: true     # can people outside the organisation reach it?
autonomous: false          # does it act without a person approving each step (agents, jobs)?
multiAgent: false          # do several AI agents work together in it?

crownJewels: [internal/auth/, api/admin/]   # reviewed first
outOfScope: [examples/, scripts/]            # reviewed last
```

Leave a question out if you do not know; an unanswered question is never read as
"no". Path patterns are relative to the repository root: `dir/` or `dir/**` is
everything under `dir`, a pattern with no slash (`fixtures`, `*.pb.go`) matches a
file or directory name anywhere, and anything else is matched against the whole
path (`cmd/*/main.go`, `services/*/internal/`).

Out-of-scope code is still scanned and its findings are still reported. It is
reviewed last, and a scanner whose languages appear only there is skipped. To drop
findings in a path altogether, use `exclude` in `.achilles.yaml`.

The file is committed with the code, so the change under review can edit it. It
can therefore only shape the scan of that code: reorder the review, skip a scanner
with nothing to analyze, add an installed opt-in scanner. It never turns on a model,
a network call or an output. Achilles says on stderr when it read one; when it
caused a skip it is listed with the repository's configuration in every report, and
under `--diff` a change to it is flagged. `--no-repo-config` ignores it. A file
with an unknown key, a value that is not true or false, or a bad pattern fails the
run, because a misspelled question that quietly counted as unknown would change the
scan without anyone noticing.

## Scan depth

The five questions pick a depth, after the OWASP MAESTRO playbook's decision tree:

| Depth | When |
|-------|------|
| full | business critical, or confidential data |
| standard | externally facing, autonomous or multi-agent, or any question unanswered |
| lightweight | all five answered "no" |

Only "externally facing" is ever inferred, and only towards yes: network entry
points outside tests and out-of-scope paths count as evidence that it is. An answer
in the file always wins. Nothing in the code can prove a system is not business
critical, so without a context file the depth is at least standard.

Today the depth is advisory: at full depth the plan recommends `--profile full`, and
the depth and its reasons are in the plan and every report.

## The tool plan

The plan is made when it is asked for (`--plan-out`, `--prioritize surface`), when
the repository has a threat-context file, under `--profile full`, or with
`--all-tools`. Otherwise the run is exactly what it was before.

It **skips** a scanner the profile turns on when it has nothing to analyze:

| Scanner | Skipped when |
|---------|--------------|
| gosec, govulncheck | Go code but no `go.mod` outside tests and out-of-scope paths |
| Psalm | no `psalm.xml` at the repository root (Achilles runs Psalm with it) |
| FindSecBugs | no compiled `.class`, `.jar` or `.war` in build output |
| Security Code Scan | no `.csproj`, `.vbproj` or `.sln` |
| Railroader | not a Rails app (no `config/routes.rb` or `config/application.rb`) |
| Checkov | no infrastructure-as-code files |
| any language-specific scanner | its languages appear only in tests or out-of-scope paths |

A scanner asked for by name (`--with`, `--secrets-history`) is never skipped, and a
map that stopped early skips nothing. Opengrep, Trivy, Gitleaks and OSV-Scanner
are never skipped.

It **adds** an opt-in scanner whose files are present, only when the repository has
a threat-context file (or under `--all-tools`) and the scanner can be launched
(installed, or an image under `--runner docker`): today that is zizmor, for GitHub
Actions workflows. Otherwise it **recommends** it, with the flag that runs it.

Every decision is printed on stderr and shown in the human, Markdown and HTML
reports, in the JSON report's `toolPlan`, and as a note-level SARIF notification:

```
Scan plan: depth full (businessCritical = yes (context file)).
  - skipped checkov: no infrastructure-as-code files (Terraform, ...) (--all-tools runs it)
  - added zizmor: the repository has GitHub Actions workflows, which zizmor audits (the threat-context file is present)
  - recommends --profile full: scan depth is full (...); the full profile adds the per-language analyzers
```

`--all-tools` runs every scanner the plan would skip and adds every opt-in scanner
whose files are present. It does not change the profile: combine it with
`--profile full` for the heavy per-language analyzers.

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
  "facts": [{"kind": "sink", "class": "sql", "file": "api/admin.py", "line": 7, "summary": "SQL execution"}],
  "networkEntries": 31,
  "languages": {"python": {"files": 120, "inScope": 84}},
  "markers": ["github-workflows", "iac"],
  "context": {"businessCritical": true, "crownJewels": ["api/admin/"], "file": ".achilles/threat-context.yaml"},
  "depth": {"level": "full", "reasons": ["businessCritical = yes (context file)"],
            "answers": [{"question": "businessCritical", "value": "yes", "source": "context"}]},
  "toolPlan": {"depth": "full", "contextFile": ".achilles/threat-context.yaml",
               "decisions": [{"tool": "checkov", "action": "skipped", "reason": "no infrastructure-as-code files", "fix": "--all-tools"}]}
}
```

It carries kinds, files, line numbers and fixed summaries (route paths are bounded
and scrubbed), never source text and never the absolute path of the target. At most
500 hotspots and 5,000 facts are kept; `factsDropped` counts the rest.

## Where this is going

The surface map and the threat context are the first two steps of a pre-scan
modelling phase. Later steps will add an optional grounded LLM pass that names
components and trust zones, and hypothesis checks for missing controls by the deep
verifier (advisory until verified).
