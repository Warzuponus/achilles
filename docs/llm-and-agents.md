# LLM Triage & Agents

Achilles uses LLMs to *interpret* scanner output — verify findings, propose fixes,
and produce holistic analysis — and it can route each task to a different model.
All of it is **opt-in**; with no LLM configured, Achilles is a pure scanner.

## Setup

Achilles talks to any **OpenAI-compatible** endpoint. You need a key and a model.
The shortest path is `--ai`, which turns on triage, fix suggestions, the repo
review and the dependency advisor, and writes `report.html`, `report.md` and
`achilles.sarif` into `--report-dir` (default `achilles-report/`):

```bash
export ACHILLES_LLM_API_KEY=...        # your provider's key (or OPENAI_API_KEY)
achilles --ai --llm-provider openrouter --llm-model <model> /path/to/code
```

`--llm-provider` is a shortcut for the base URL:

| Provider | `--llm-provider` | Base URL | Key |
|----------|------------------|----------|-----|
| OpenAI | `openai` (default) | `https://api.openai.com/v1` | required |
| OpenRouter | `openrouter` | `https://openrouter.ai/api/v1` | required |
| Ollama (local) | `ollama` | `http://localhost:11434/v1` | none |
| Anthropic (experimental) | `anthropic` | `https://api.anthropic.com/v1` | required |

**The `anthropic` preset uses Anthropic's Messages API natively**, with a small client
of Achilles' own (no SDK, no new dependency), for any `--llm-base-url` on
`api.anthropic.com`. What that changes over an OpenAI-compatible endpoint:

- The JSON schema of each verdict is enforced (structured outputs), instead of asked
  for in the prompt and repaired.
- The system prompt, which is the same for every finding in a run, is cached, so after
  the first call it is billed at the cached-input rate. Achilles' cost meter still
  counts those tokens at the full input price, so `--max-cost` errs on the safe side.
- Replies are streamed, so a long thinking phase does not trip a proxy's idle timeout.
  The output budget defaults to 16,000 tokens (`ACHILLES_LLM_MAX_TOKENS`), since
  current Claude models think before they answer and the thinking counts against it.
- No `temperature` is sent; current Claude models fix their sampling.
- A refusal (`stop_reason: refusal`) is an error for that finding, not an empty
  verdict.
- Overload (529), rate limits (429, honouring `Retry-After`), server errors and a stream
  that drops before it finishes are retried, `ACHILLES_LLM_MAX_RETRIES` times (2 by
  default). A partial answer is never used.
- The key is `ACHILLES_LLM_API_KEY`, sent as `x-api-key`. `ANTHROPIC_API_KEY`,
  `ANTHROPIC_BASE_URL` and the like are not read, so they cannot redirect the key
  Achilles has checked.

- Each verdict schema is adapted to what structured outputs accept: every object gets
  `additionalProperties: false`, and length and range constraints are dropped (the
  decoded answer is still validated).

It is still marked experimental: its unit tests run against a fake of the Messages
API. Live tests (`TestLive*` in `internal/triage/llm`, skipped unless
`ACHILLES_TEST_ANTHROPIC_API_KEY` is set) and the `Live Anthropic` workflow run it
against the real service. OpenRouter (`--llm-provider openrouter --llm-model
anthropic/<model>`) remains an exercised path for Claude models.

Anything else (vLLM, LiteLLM, Azure OpenAI, a gateway) is `--llm-base-url`. An
explicit `--llm-base-url` always wins over a provider preset. There is deliberately
no default model: model names change faster than this project, so pick one that
your provider serves and pass it with `--llm-model` (or `ACHILLES_LLM_MODEL`).

Achilles checks the setup **before it scans**: a missing key for a hosted endpoint, a
key that plainly belongs to a different provider than the endpoint (it will not send
an OpenRouter or Anthropic key to OpenAI), an API key over plain `http`, or a missing
model all stop the run immediately with the fix. If the provider rejects the key or
has no credits mid-run, the run stops after the first rejection instead of failing
every finding in turn.

The key is read from the environment only — it never appears on a command line or
in the vault.

### What leaves your machine

With AI features on, the code around each finding (the enclosing function, a few
callers in the same file, and git-blame author and date) is sent to the LLM endpoint,
and Achilles prints the destination host before it starts. Before sending:

- credentials in the code and messages are masked (cloud keys, tokens, private keys,
  `password = "..."` style assignments);
- findings **about** credentials are never sent to the model at all, and are never
  dismissed by it. That covers Gitleaks, anything a scanner itself classes as a secret
  (Trivy's secret results), and rules or CWEs that name a credential. The matched text
  of such a finding is not kept either: not on the finding, not in the stored scanner
  output, and not as a `--rag` example;
- `--llm-no-code` sends only rule names, messages and file locations. Verdicts made
  without seeing code are weak, so in this mode the AI never dismisses a finding;
- a local model (`--llm-provider ollama`) keeps everything on your machine.

### Time and parallelism

`--timeout` (default 5m) bounds the scanners. The AI phases have their own
`--llm-budget` (default 45m) and review `--llm-concurrency` findings (default 4) at a
time, most severe first, so if the budget runs out what was reviewed is what matters
most. Whatever was not reached is reported as such, in the log and in every report,
and stays in the gate: an unreviewed finding is never treated as a dismissed one.

### What the AI review can and cannot tell you

Be honest about it when you read the verdicts. The model sees one file's worth of
context per finding, not the whole program: "reachable" is its judgment from that
context, not a proof. `--review` and `--threat-model` reason from scan statistics
(languages, dependencies, which rules fired), not by reading your source. On the
project's own small labeled corpus the shipped routing scores well, but the corpus is
18 synthetic Go and Python cases, so treat accuracy numbers as indicative.
Findings the AI dismissed are always listed so you can audit them.

## Measuring whether triage actually works

Everything below is only worth having if it is *measurably* better than the
scanner's raw output. `achilles-eval` scores the triage layer against a labeled
corpus ([`evals/`](../evals/README.md)) so a change to prompts, context, or model
routing can be proven instead of asserted:

```bash
make eval-context                                    # hermetic: no model, no key
make eval-verdict EVAL_MODEL=<model> EVAL_ARGS="--model-config <routing.yaml> --repeat 3"   # needs a key; spends money
```

**Eval the routing, not a model.** The verdict target drives a committed
`--model-config`, because triage and judge deliberately use *different* models,
so a score belongs to the pair, and the report names both. Measuring some model you
don't actually run tells you nothing about production.

**Context mode** is hermetic. For each case it builds the prompt Achilles would
send and checks whether the deciding evidence is inside it — answering *did we
give the model what it needed?* with no API call, so it runs in CI and gates
against regressions (`make eval-gate`).

**Verdict mode** runs the real triage→judge path against a live model and scores
verdicts against the labels. Its headline is **balanced accuracy**, which weights
both classes equally (scored on whether the review *confirmed* a finding; the report
also prints what was actually *dismissed* from the gate, which is the number users
feel): a triager that confirms everything scores 100% on a
true-positive-only corpus and 50% here. It also reports TP recall, FP suppression,
a calibration gap (`|mean confidence − accuracy|`, so an overconfident model is
visible), and — with `--repeat` — which cases the model answers inconsistently on
the same input.

Both modes write JSON with `--out` and diff against a previous run with
`--baseline`, which is how you show a change helped.

## Knowing the bill first: `--dry-run` and `--max-cost`

LLM spend scales with findings, so a large repo — or the fleet fanning a scan out
across tenants — can run up a real bill before anyone notices. Achilles estimates
the cost **before the first model call**:

```bash
achilles --triage --remediate --llm-model <m> \
  --price-config configs/prices.yaml --dry-run .
```

```
LLM cost estimate (pre-flight; no model has been called)
  TASK           MODEL              CALLS    IN TOKENS   OUT TOKENS        USD
  judge          gpt-4o-mini            2          867          240     0.0062
  remediation    gpt-4o-mini            2          363         1200     0.0191
  triage         gpt-4o-mini            2          404          500     0.0087
  TOTAL                                 6         1634         1940     0.0340
```

`--dry-run` runs the whole deterministic pipeline (scan, normalize, noise filter,
diff, baseline, correlate), writes local reports, applies `--fail-on`, and then
stops: **no model call and no outward-facing action** — no PR comment, no inline
review, no issues, no fix PR, no research or rule mining.

`--max-cost <usd>` is the guardrail for real runs. If the estimate exceeds it,
Achilles prints the breakdown and exits non-zero **without calling any model**:

```
achilles: estimated LLM spend $0.0340 exceeds --max-cost $0.0100; no model was
called (raise the cap, narrow the scan with --diff/--baseline, or route cheaper models)
```

The cap also holds **during** the run, against what is actually spent. Every chat
call (the review, the judge, fix suggestions, deep verification, the repo review, the
dependency advisor, the threat model, research) is priced from the token usage the
endpoint reports, and once the total reaches the cap no further call is started:

```
achilles: --max-cost stopped the AI review: 12 finding(s) were not reviewed (most severe were reviewed first). ...
achilles: LLM spend counted against --max-cost: $1.0042 of $1.0000 over 187 call(s); 31 further call(s) were NOT made
```

Findings the review did not reach stay in the report, marked as unreviewed, exactly
as when the time budget runs out. Calls already in flight finish, so the total can
pass the cap by at most what `--llm-concurrency` calls cost. A model with no price
is not called at all while a cap is set. Embedding calls for `--rag` are not counted.

**You supply the prices.** Achilles ships no built-in price table: prices change
without notice, differ per provider for the same model name, and are often
negotiated, so a cap computed from prices we guessed would be worse than no cap.
Copy [`configs/prices.example.yaml`](../configs/prices.example.yaml), fill in your
provider's published numbers, and pass it with `--price-config`. Tokens are always
estimated (we can compute those from our own prompts); dollars appear only for
models you have priced, and `--max-cost` **refuses to run** rather than enforce a
cap it cannot compute.

What the estimate does and does not cover:

- **Reflected:** the surfaced finding set only (post-noise, post-diff,
  post-baseline), correlated duplicates costing nothing, and (with `--calibrate`)
  findings the calibrator rules out without an LLM call.
- **Upper bound:** with `--remediate`, every triaged finding is counted, since
  which ones turn out high-confidence is unknowable in advance.
- **Excluded, and named in the output:** the one-per-scan whole-repo agents
  (`--review`, `--sca-advice`, `--threat-model`), `--research`/`--mine-rules`, and
  the extra prompt tokens `--rag` adds.
- **Approximate:** tokens are counted at ~4 characters each and output sizes are
  per-task defaults. Compare against `--diagnostics` after a real run.

The cap is checked **pre-flight only** — it does not abort a run mid-way if actual
spend outpaces the estimate.

## Cross-tool correlation (before triage)

Achilles runs overlapping engines on purpose, so the same defect often arrives from
two or three tools — Opengrep and gosec on one Go line, two secret scanners on one
credential, two dependency scanners on one advisory. Before triage, findings from
**different tools** at the same **file and line** that are about the same weakness
are grouped into a cluster: they share a CWE, or CWEs that are parent and child (one
tool says CWE-78, another CWE-77). Only the highest-severity member is sent to the
LLM. The rest inherit its verdict, so a defect costs one triage+judge pair no matter
how many tools reported it. Two credential findings on one line, and two advisories
with the same id against the same manifest, are clustered too so the report can say
the tools agree; neither is ever sent to a model. Findings with no CWE and no such
identity (most infrastructure-as-code findings) are not clustered.

Correlation **collapses nothing**: every finding keeps its own fingerprint,
severity, and behaviour under `--baseline`, `--file-issues`, and `--fail-on`. The
report shows the overlap instead of hiding it:

```
  [high] B602
    subprocess call with shell=True
    at run.py:5  (bandit)
    [CWE-78]
    also reported by: Opengrep OSS:achilles.python.subprocess-shell-true
    triage: true_positive  confidence=0.90  exploitability=reachable
```

and the duplicate records where its verdict came from:

```
    (verdict inherited from correlated finding 17cf544325f61c67)
```

The key is deliberately strict — a finding with no CWE or no line number never
clusters, and one tool reporting twice on a line is left alone — because a wrong
merge costs a wrong verdict while a missed merge costs one extra LLM call. Two
things still take precedence over an inherited verdict: **calibration** (with
`--calibrate`, feedback
about a finding's *own* rule outranks a sibling's verdict) and **remediation**,
which is never inherited, since a patch belongs to one specific finding. Disable
the whole thing with `--no-correlate`.

## Per-finding: triage → judge → remediation

Achilles sends the **enclosing function or block** as context, not a fixed number
of lines either side — a 3-line window usually hides the signature and the guard
clause that decide whether a finding is real. Brace-matching covers C-family
languages (Go, Java, JS/TS, C/C++, C#, PHP, Rust, Swift, Kotlin, Scala, HCL) and
indentation covers Python; other file types keep a fixed radius. It's a heuristic,
so it's bounded: the window must contain the flagged line, it's capped (oversized
scopes are clamped and labelled `// enclosing scope truncated to N lines`), and
anything unresolved falls back to the radius — which is a floor, so context never
shrinks. Wider prompts cost more; `--dry-run` shows exactly how much before you
pay it.

- **`--triage`** — for each finding, Achilles adds code context and asks the model
  for a structured verdict: `true_positive` / `false_positive` / `uncertain`, a
  confidence, exploitability, and reasoning. A second **adversarial judge** pass
  then tries to *refute* that verdict — only unrefuted true-positives with
  confidence ≥ 0.7 are treated as high-confidence. The judge has to back a
  refutation: it states its own confidence and quotes the line(s) of the context that
  prove it, and Achilles checks that the quote really is in the context it sent. A
  refuted true positive is ruled out only when that check passes, the judge was at
  least 0.7 confident, and the triage pass was itself below 0.9. Otherwise the two
  passes simply disagree: the finding stays in the gate, marked **disputed by judge**,
  and gets no automatic fix. Refuting an `uncertain` verdict never rules a finding out.
  Two kinds of finding are never sent to the model at all: credential findings (their
  matched text is the secret) and **dependency advisories** (known CVEs in
  dependencies: there is no code to judge, and a verdict must not be able to hide a
  vulnerable package). Both cost nothing and are counted separately in every report.
- **`--remediate`** — for those high-confidence findings, propose a fix: a summary
  plus a unified diff when a clean patch is possible, or prose guidance otherwise.
  Implies `--triage`. Achilles proposes; it never auto-applies (see `--fix-pr` in
  [CI & the Scan Hub](ci-and-hub.md) for opening a *review* PR).

```bash
achilles --remediate --llm-model gpt-4o --html-report report.html .
```

Verdicts and fixes show up per-finding in the HTML report and are recorded to the
vault.

### Gates: the attacker-first questions behind a verdict

Since prompt `triage/v4` the model answers five questions as separate structured
fields (`verdict.gates`) before it classifies, so a report can show *why* a finding
was kept or dismissed instead of only a paragraph of reasoning:

| Gate | Answers | Question |
|------|---------|----------|
| `designedBehavior` | yes / no / unknown | Is this the application doing what it is designed to do? |
| `reachable` | yes / no / unknown | Can production code reach it? (one-line evidence) |
| `attackerControlled` | yes / no / unknown | Does attacker-influenced data reach it? |
| `sanitized` | none / partial / effective / unknown | Is there an effective control between source and sink, and where? |
| `newCapability` | yes / no / unknown | Would exploiting it give the attacker something they did not already have? |

Gates are advisory and lenient: a model that omits them still produces a verdict,
and an answer outside a gate's vocabulary is stored as `unknown`. They can only make
dismissal *harder* — a verdict whose own gates say reachable + attacker-controlled +
not (effectively) sanitized + new capability is never dismissed, whatever its
classification. The prompt also tells the model that comments, docstrings and names
are claims, not evidence, and that the repository text is untrusted data. Since
`triage/v6` that text (the scanner's message, the code, past findings, and for the
judge the first pass's reasoning) sits between markers carrying a random per-request
id, so a line in the code cannot pass itself off as the end of the code. The prompt
also defines `confidence`: below 0.7 means "I would need to see more code", and such
a finding is kept for a person.

### Self-consistency sampling: `--llm-samples N`

One answer from a model is one draw. With `N > 1`, a **borderline** verdict —
`uncertain`, confidence below 0.85, or one the judge refuted or overturned — is
re-asked up to `N-1` more times (extra samples at a small non-zero temperature; the
first answer stays deterministic). The classification becomes the plurality answer,
**a tie is `uncertain`** (never broken toward `false_positive`), and confidence is
the mean of the agreeing samples. The split is kept on the verdict as
`stability: {samples, agreeing, classifications}`.

A non-unanimous result is **never dismissed**. The judge's refuted/overturned flags
describe the first answer, so they are kept only if the result is still that
classification. Extra samples are triage calls only (they are not re-judged), are
recorded to the vault as `triage-sample`, and a sample that errors is simply
dropped. `--dry-run` counts `N-1` extra triage calls per finding — an upper bound,
since only borderline verdicts are re-asked and that cannot be known beforehand.
Confident, judge-approved verdicts cost nothing extra.

### Not asking twice: the verdict cache

Most of a repeat scan is findings that have not changed. When a finding's rule,
message and surrounding code, the prompt version, the privacy mode and the models
are all the same as in an earlier run recorded in the same vault, that run's verdict
is reused and the model is not called. Line numbers are ignored, so code that only
moved within its file still matches. The report says how many verdicts were reused,
and each one records which run it came from.

```
achilles: 41 verdict(s) reused from earlier runs: the same code was reviewed with the same prompt and models
```

- `--verdict-cache-days N` (default 30) is how long a verdict may be reused; `0`
  turns the cache off and reviews everything afresh. The limit exists because a
  provider can change the model behind a name.
- Reuse makes results steadier as well as cheaper: a model asked the same question
  twice does not always answer the same way, which is how a finding can flip between
  runs when nothing changed.
- Fix suggestions (`--remediate`) are cached the same way, with one difference: a
  suggestion usually carries a patch, and a patch is written against lines, so it is
  reused only when the code is also in the same place. If the code moved, the fix is
  asked for again. Whether a patch works is never cached: the re-scan that verifies it
  runs in every scan.
- Cache entries are signed with a key kept in the Achilles home directory
  (`~/.achilles/verdict-cache.key`, or under `$ACHILLES_HOME`), not in the vault. The
  vault's default location is inside the scanned directory, so a vault file can arrive
  with a repository; without the signature a pull request could carry a ready-made
  "false positive" for its own code. An entry that does not verify is ignored. A fresh
  CI runner has a fresh key, so in CI the cache only helps if you persist both the
  vault and the Achilles home between runs.

### Entry-point hints

The code context can begin with a short block naming how the finding's **own file**
takes input:

```
// This file exposes (pattern match on this file only; no hint is NOT evidence of unreachability):
//   HTTP route POST /run (line 9)
```

A fast, offline line-pattern detector (`internal/inventory`) recognises Go
(`net/http`, gin/echo/chi, gRPC), Python (Flask/FastAPI/Django, Celery), JS/TS
(Express/Koa/Fastify/Nest/Next), Java/Kotlin (Spring, JAX-RS, servlets, message
listeners), Rails, PHP superglobals/Laravel routes, CLI argument parsing, and
stdin/queue/file consumers. It reads only that file (the one already being read for
context), scans at most 1 MiB, and lists at most 8 hints nearest the finding; a
summary carries only the kind, HTTP method and a scrubbed route path, never code or
tokens. It makes no cross-file claims, and the prompt says so: a handler is often
registered in another file, so a missing hint is not evidence the code is
unreachable. `--llm-no-code` withholds the block with the rest of the code.

## Whole-repo agents

These reason over the codebase profile + findings rather than one finding at a time:

| Flag | Produces |
|------|----------|
| `--review` | **Systemic risks** — architectural weaknesses, themes across findings, missing controls |
| `--sca-advice` | **Dependency upgrade plan** — what to bump, merge-risk scored, security-driven first |
| `--threat-model f.otm.json` | an **OTM threat model** — trust zones, components, STRIDE threats + mitigations |

```bash
achilles --review --sca-advice --threat-model tm.otm.json \
  --html-report report.html --llm-model gpt-4o .
```

## The learning loop

Achilles gets quieter over time from analyst feedback:

```bash
achilles --feedback <fingerprint> --label fp --note "md5 used for a cache key"
```

- **Calibration** (`--calibrate`, off by default) — when a rule has been labeled
  false positive often enough, Achilles rules its findings out *without* an LLM call.
  This takes findings out of the gate on past labels alone, so the bar is high and
  the decision is bounded: at least 10 **distinct** labeled findings of the rule (one
  finding labeled ten times counts once, by its latest label), at least 90% of them
  false positive, labels no older than 180 days, and never a finding above medium
  severity or about a credential. Every run that uses it prints which rules it ruled
  out and how many findings, and reports say those verdicts came from feedback rather
  than a model review. Without `--calibrate`, feedback never dismisses anything.
- **RAG** (`--rag`, needs `--llm-embed-model`) — injects similar past findings and
  how analysts ruled them as few-shot context for triage.
- **`--rule-health`** prints per-rule TP/FP rates so you can see what's noisy, and
  which rules `--calibrate` would rule out.
- **`--mine-rules`** turns analyst-confirmed findings into new Opengrep rules
  (validated before they can run — see [DESIGN.md](../DESIGN.md) §9).

## Multi-model routing

Different tasks want different models — a fast/cheap one for high-volume triage, a
strong reasoner for the judge and threat model, a good coder for remediation. Map
tasks to models in a YAML file and pass it with `--model-config`:

```yaml
# models.yaml — any task you omit falls back to --llm-model
tasks:
  triage:       { model: gpt-4o-mini }
  judge:        { model: gpt-4o }
  remediation:  { model: gpt-4o }
  review:       { model: gpt-4o }
  sca:          { model: gpt-4o-mini }
  threat-model: { model: gpt-4o }
```

```bash
achilles --triage --review --sca-advice \
  --llm-model gpt-4o-mini --model-config models.yaml .
```

Routable task names: `triage`, `judge`, `remediation`, `review`, `sca`,
`threat-model`, `research`, `mine-rules`. A task entry may also set its own `baseURL`. The API key is shared
across all of them (one `ACHILLES_LLM_API_KEY`), as are the provider settings below.

### Any OpenAI-compatible provider

Achilles speaks the OpenAI Chat Completions wire format, so anything that exposes
`POST {base-url}/chat/completions` works: OpenAI, Azure OpenAI, Ollama, vLLM,
llama.cpp, LM Studio, LiteLLM, OpenRouter, and gateways in front of them.
`--llm-base-url` is the URL *before* `/chat/completions`.

Provider differences are settings, not code. `--llm-auth` picks how the key is
sent; environment variables cover the rest (they are env-only so CI, the fleet and
containers pass them through unchanged):

| Setting | Purpose |
|---------|---------|
| `--llm-auth key` | `Authorization: Bearer $ACHILLES_LLM_API_KEY` (or `OPENAI_API_KEY`). An **empty key sends no header**, so keyless local runtimes just work. |
| `--llm-auth api-key` | same key, sent as an `api-key:` header (Azure OpenAI). |
| `--llm-auth none` | never send a credential — local runtimes, or auth carried in `ACHILLES_LLM_HEADERS`. |
| `ACHILLES_LLM_HEADERS` | extra headers on every request, `Name=Value,Name2=Value2` (OpenRouter's `HTTP-Referer` / `X-Title`, gateway routing headers). Values may contain `=` but not `,`. |
| `ACHILLES_LLM_QUERY` | query string, `name=value,...` — Azure's `api-version=2024-10-21`. |
| `ACHILLES_LLM_TIMEOUT` | per-request timeout as a Go duration (default `120s`). Raise it, e.g. `10m`, for slow CPU-bound local models. |
| `ACHILLES_LLM_OMIT_TEMPERATURE` | `true` drops the `temperature` field. Needed for reasoning models (OpenAI o-series / GPT-5 class) that reject any explicit value. |
| `ACHILLES_LLM_MAX_TOKENS` | cap output tokens. `ACHILLES_LLM_MAX_TOKENS_PARAM` names the wire field: `max_tokens` (default, widest support) or `max_completion_tokens` (newer OpenAI models). |
| `ACHILLES_LLM_MAX_RETRIES` | retries on HTTP 429/502/503/504 with backoff, honoring `Retry-After` (default `2`; negative disables). |

Examples:

```bash
# Local Ollama — no key, longer timeout
ACHILLES_LLM_TIMEOUT=10m achilles --triage --llm-auth none \
  --llm-base-url http://localhost:11434/v1 --llm-model qwen3:32b .

# Azure OpenAI — the deployment is part of the base URL
export ACHILLES_LLM_API_KEY=<azure-key>
ACHILLES_LLM_QUERY=api-version=2024-10-21 achilles --triage --llm-auth api-key \
  --llm-base-url https://<resource>.openai.azure.com/openai/deployments/<deployment> \
  --llm-model <deployment> .

# OpenRouter
export ACHILLES_LLM_API_KEY=<openrouter-key>
ACHILLES_LLM_HEADERS="HTTP-Referer=https://example.com,X-Title=achilles" achilles --triage \
  --llm-base-url https://openrouter.ai/api/v1 --llm-model <vendor>/<model> .

# OpenAI reasoning model
ACHILLES_LLM_OMIT_TEMPERATURE=true ACHILLES_LLM_MAX_TOKENS_PARAM=max_completion_tokens \
  achilles --triage --llm-model <reasoning-model> .
```

**What Achilles tolerates from imperfect servers.** Structured output is requested
as `json_schema` and, if the server rejects the `response_format` (HTTP 400, 404,
405, 415, 422, 500, 501, or a 200 with an unusable body), retried once as plain
`json_object`; credential, rate-limit, timeout and network failures are *not*
retried that way, since they would only fail again. The schema is sent as OpenAI
`strict` only when it satisfies strict mode's rules. Replies are parsed after
stripping `<think>…</think>` blocks and code fences; if `content` is empty, the
server's `reasoning_content` / `reasoning` is used. Token usage is reported as 0
when a server omits `usage`.

**Quality is per-model, not per-protocol.** "Works" means wire-compatible; the
measured triage accuracy differs a lot between models (see the eval harness in
[`evals/`](../evals/README.md)). Run it against your own endpoint before trusting
gating decisions to it.

### Open models via Ollama Cloud

Ollama Cloud is OpenAI-compatible, so you can mix open models per task. Achilles
ships an example routing at [`configs/models.ollama.yaml`](../configs/models.ollama.yaml):

```bash
export ACHILLES_LLM_API_KEY=<ollama-key>
achilles --triage --review --sca-advice --threat-model tm.otm.json \
  --llm-base-url https://ollama.com/v1 \
  --llm-model glm-5.2 \
  --model-config configs/models.ollama.yaml \
  --html-report report.html .
```

That config routes `triage`/`review`/`sca` → `minimax-m2.7`, `judge` → `minimax-m3`
and `remediation`/`threat-model` → `kimi-k2.6`, with `glm-5.2` as the fallback. Only
the triage and judge pair was measured ([evals](../evals/README.md)); the judge was
chosen because the alternative refuted most correct true positives. Tune it freely,
and re-run the eval when you change either of those two.

> **Note on open models.** They're looser than frontier models about JSON shape.
> Achilles hardens for this (fence-stripping + a schema-validated repair retry), but
> output quality still varies run-to-run — the agents are best-effort by design and
> never block the scan.
