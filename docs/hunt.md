# Hunt mode (`--hunt`)

Every other part of Achilles starts from a finding: a scanner reports something,
and the model reviews it. Hunt mode starts from an **entry point** instead. The model
follows the data an attacker controls from an HTTP route, request handler or message
consumer, with the same read-only tools as [deep verification](deep-verify.md), and
reports what it can trace to a dangerous operation. It can find what no rule
describes: a missing authorization check, an ID passed straight to a query three
files away.

It is **opt-in**, **read-only**, **bounded**, and **reviewed**. A model that hunts
also imagines, so everything a hunt reports is a candidate. The triage model and the
adversarial judge review each candidate like any scanner finding. Only a candidate
they confirm with high confidence becomes a finding that gates the build. The rest are
listed apart, as leads.

```bash
achilles --triage --llm-model <model> --hunt 10 /path/to/code
achilles --triage --llm-model <model> --hunt 10 --dry-run /path/to/code   # count entry points and estimate only
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--hunt N` | `0` (off) | Hunt from up to `N` entry points. |
| `--hunt-max-steps K` | `10` | Most tool calls per entry point. Hard ceiling 20. |

It needs `--triage` (or `--ai`): a candidate nobody reviews is never reported as a
finding. It **refuses to run with `--llm-no-code`**, for the same reason deep
verification does. `--model-config` may route a `hunt` task to its own model or
endpoint; otherwise the `deep` route is used, then the triage model.

## Where a hunt starts

Entry points are found by pattern match, the same way the [entry-point
hints](llm-and-agents.md#entry-point-hints) are, over every file the tools may show:
no protected or secret-bearing paths, no `node_modules`, `vendor` or virtualenvs, and
no test files (an entry point in a test is a fixture). HTTP routes come first, then
request input and gRPC, then consumers. Seeds are spread across files, so ten seeds
come from ten different files when there are that many. With `--diff`, only the
files the change touched are hunted.

## What a hunt may report

The model ends a hunt with one `report` action:

```json
{"action":"report","candidates":[{
  "location":"app/db.py:42",
  "class":"sql-injection",
  "severity":"high",
  "title":"the id query parameter reaches cursor.execute",
  "reasoning":"…",
  "route":["app/views.py:17 request.args['id'] read","app/db.py:42 concatenated into SQL"]
}]}
```

An empty `candidates` list is a good answer, and the prompt says so: most entry
points have nothing to report. Each candidate is checked before it goes anywhere:

- its `location`, and every step of its `route`, must be a line a tool showed the
  model, using the line numbers the tool printed. A candidate at a line it never saw
  is dropped and counted;
- `class` is reduced to a fixed vocabulary (`sql-injection`, `command-injection`,
  `path-traversal`, `ssrf`, `xss`, `missing-authorization`, `idor`, and so on; anything
  else is `other`). It becomes the rule ID, `hunt/<class>`, with the matching CWE;
- severity is capped at `high`: how bad it is, is for the review to assess;
- at most three candidates per entry point;
- a candidate within two lines of something a scanner already reported in the same
  file is dropped as a duplicate.

## What happens to a candidate

A kept candidate becomes a finding with tool `achilles-hunt`, its route as the
[source-to-sink path](llm-and-agents.md#source-to-sink-paths), and a fingerprint from
the text of its line, so it keeps its identity when code above it moves. It then goes
through correlation, triage, the judge and (with `--deep-verify`) deep verification
like every other finding.

After the review:

- **Confirmed** (a high-confidence true positive, or one the judge overturned into
  view): it stays in the findings, gates the build, can get a fix and an issue, and is
  exported to SARIF like any other.
- **Not confirmed** (uncertain, low confidence, refuted, dismissed, or not reviewed
  because the review stopped): it moves to `hunted` in the scan data. Reports list it
  in its own section, "Hunt candidates the AI review did not confirm". It never gates
  the build, never opens an issue, and is left out of SARIF: a lead from one run
  should not become a code-scanning alert that a second run, which hunts differently,
  then closes.

## Cost

Each entry point costs at most what one deep verification costs at the same step
budget, plus the review of what it reports. `--dry-run` counts the entry points it
would start from and prints the upper bound. The hunt shares the AI review's
`--llm-budget` clock and `--max-cost` cap: it runs first, so a long hunt leaves less
time for the review. Every hunt, with its trace of tool calls, is recorded in the
Evidence Vault with source `hunt`.
