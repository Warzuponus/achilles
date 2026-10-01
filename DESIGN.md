# Achilles — Design & Implementation Plan

> **Status:** v0.10 — **roadmap complete (Phases 0–6, backlog Tiers A–G)** (Apache-2.0). **Local-first**: runs on your own machine, in Docker, or in your own GitHub Actions, with no cloud dependency and no authentication layer (PostgreSQL or file Evidence Vault, any OpenAI-compatible LLM endpoint) — see DEPLOY.md and docs/containers.md. P6: `achillesd` War Room (HTMX/Alpine) over the Evidence Vault, single-user and unauthenticated, with per-project vault isolation, secret redaction, audit export, SSE. P5: CI & delivery. P4: research agents + §9.3 validation gate. P3: learning loop. P2/2.1: OpenAI-compatible triage + judge + remediation. P1: config registry, license gate, Evidence Vault. Earlier: phased-pipeline, containment, permissive-license/AGPL decisions.
> **What this is:** An LLM-assisted harness that orchestrates open-source SAST tools, normalizes and de-duplicates their findings, then uses LLMs to interpret, verify, and prioritize them — improving over time from analyst feedback.
> **Provenance:** Independently implemented from publicly-documented SAST concepts and the goals below; see the README acknowledgements for public writing that informed some design choices.

---

## 1. Goals & Non-Goals

### Goals
1. **Aggregate** multiple open-source SAST engines behind one interface and one normalized result model.
2. **Interpret & verify** raw findings with LLMs — cut false positives, explain real ones, propose fixes.
3. **Learn**: get measurably better at triage as analysts confirm/reject findings.
4. **Be commercially deployable**: every default-enabled tool must be license-clean for scanning *third-party/customer* code in a paid product.
5. **Reproducible & auditable**: pinned tool versions, deterministic runs, traceable "why" for every verdict.

### Non-Goals (for now)
- **DAST / runtime testing** — that's Reverb's lane. Achilles is static analysis only.
- **Autofix-and-commit** — we *propose* fixes; we don't auto-merge.
- **Being our own SAST engine** — we orchestrate existing engines; we don't write a new taint analyzer.

---

## 2. Design Principles
- **SARIF is the lingua franca.** Prefer tools that emit [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html); adapt the ones that don't. Everything internal maps to a SARIF-compatible model.
- **Tools are plugins.** Adding an engine = implementing one interface + a pinned container image. No core changes.
- **The LLM never sees a finding without code context.** Triage quality depends on surrounding code, data flow, and dependency facts — not just the tool's one-line message.
- **Learning is a data system, not a magic model.** LLMs don't learn online (see §8). We get smarter via a feedback store + retrieval-augmented few-shot + per-rule calibration, with optional fine-tuning much later.
- **Commercial-safe by construction.** A license registry gates which tools can run in which mode. Non-commercial tools can't be silently enabled in a paid scan.
- **Code stays in the customer's trust boundary.** The only thing that leaves is what goes to the LLM — and that's configurable (redaction, self-hosted/BYO-model).

---

## 3. Tool Inventory & License Matrix (the load-bearing table)

Licenses verified 2026-07-05. **Commercial-safe** = usable in a paid product that scans third-party code.

| Tool | Coverage | License | Commercial-safe? | Role in Achilles |
|------|----------|---------|------------------|------------------|
| **Opengrep** | Multi-lang SAST (Semgrep CE fork) | LGPL-2.1 | ✅ Yes | **Primary multi-language engine** |
| **Bandit** | Python SAST | Apache-2.0 | ✅ Yes | Python |
| **gosec** | Go SAST | Apache-2.0 | ✅ Yes | Go |
| **ESLint** + security plugins | JS/TS SAST | MIT | ✅ Yes | JS/TS |
| **njsscan** | Node.js SAST | LGPL-3.0 | ✅ Yes | Node.js |
| **Gitleaks** | Secrets | MIT | ✅ Yes | Secrets scanning |
| **TruffleHog** | Secrets (+ verification) | **AGPL-3.0** | ✅ **Only via process boundary** | Secrets w/ live credential verification — see AGPL rule below |
| **Trivy** | SCA + IaC + secrets + misconfig | Apache-2.0 | ✅ Yes | Deps, IaC, containers |
| **Grype** / **Syft** | SCA / SBOM | Apache-2.0 | ✅ Yes | Dependency vulns + SBOM |
| **OSV-Scanner** | SCA (OSV.dev) | Apache-2.0 | ✅ Yes | Dependency vulns |
| **Checkov** | IaC (TF/CFN/K8s) | Apache-2.0 | ✅ Yes | Infra-as-code |
| **KICS** | IaC | Apache-2.0 | ✅ Yes | Infra-as-code |
| **Semgrep (upstream)** | Multi-lang SAST | LGPL engine, **restricted registry rules** | ⚠️ Engine yes, **registry rules no** | Not used — replaced by Opengrep |
| **Brakeman** | Ruby/Rails | **CC BY-NC-SA (non-commercial)** | ❌ **No** | Excluded; use Railroader |
| **Railroader** | Ruby/Rails (Brakeman fork) | MIT | ✅ Yes | Ruby/Rails |
| **CodeQL** | Multi-lang SAST | Free only for OSS codebases | ❌ Not for customer code | BYO-license opt-in only |

**Design consequence:** the harness ships two policy profiles — `oss-mode` (everything, for scanning our own/OSS code) and `commercial-mode` (only ✅ rows). The license registry (§10) enforces this at runtime; enabling a ❌/⚠️ tool in commercial mode is a hard error unless the operator supplies a license attestation.

**Achilles's own license & the AGPL rule.** Achilles ships under the **Apache-2.0** license (permissive). That choice imposes one hard architectural rule:

> **AGPL/GPL tools (e.g., TruffleHog) are invoked ONLY as separate processes in their own container — never imported as Go libraries.** Arm's-length process invocation is "mere aggregation" and does not impose AGPL copyleft on Achilles; linking would. A CI check forbids importing AGPL-licensed modules. AGPL §13 (network source-disclosure) is not triggered because we do not modify or host the tool itself — we only run its CLI.

This is the standard pattern for orchestrating copyleft CLIs in a non-copyleft product, but **get legal advice before redistributing Achilles inside a commercial product** (this doc is not legal advice). Every bundled tool and its license is recorded in `THIRD-PARTY.md`.

---

## 4. Architecture

### 4.1 Component overview

```
                         ┌─────────────────────────────────────────┐
   CLI / API  ──────────▶│              Orchestrator                 │
                         │  (scan plan, scheduling, worker pool)     │
                         └───────────────┬───────────────────────────┘
                                         │ fan-out (goroutines)
             ┌───────────────┬───────────┼───────────────┬───────────────┐
             ▼               ▼           ▼               ▼               ▼
        ┌─────────┐    ┌─────────┐  ┌─────────┐    ┌─────────┐    ┌─────────┐
        │Opengrep │    │ Bandit  │  │ gosec   │    │ Trivy   │ …  │ Gitleaks│   Scanner adapters
        │ adapter │    │ adapter │  │ adapter │    │ adapter │    │ adapter │   (each = 1 pinned container)
        └────┬────┘    └────┬────┘  └────┬────┘    └────┬────┘    └────┬────┘
             └──────────────┴───────────┴──────┬────────┴──────────────┘
                                                ▼
                                     ┌────────────────────┐
                                     │    Normalizer       │  native output → SARIF-compatible Finding
                                     └──────────┬──────────┘
                                                ▼
                                     ┌────────────────────┐
                                     │ Correlator / Dedup  │  cluster findings across tools by (file, span, CWE)
                                     └──────────┬──────────┘
                                                ▼
                                     ┌────────────────────┐
                                     │    Enricher         │  + code context, git blame, call/data-flow, dep facts
                                     └──────────┬──────────┘
                                                ▼
                                     ┌────────────────────┐        ┌──────────────────┐
                                     │  LLM Triage +       │◀──────▶│ Knowledge / RAG  │  past verdicts, curated examples
                                     │  Verification layer │        │  (vector + KV)   │
                                     └──────────┬──────────┘        └──────────────────┘
                                                ▼
                                     ┌────────────────────┐        ┌──────────────────┐
                                     │  Reporter           │───────▶│ Feedback capture │  analyst TP/FP → learning store
                                     │ (SARIF/HTML/PR/gate)│        └──────────────────┘
                                     └────────────────────┘
```

### 4.2 Go project layout

```
achilles/
├── cmd/
│   ├── achilles/            # CLI entrypoint (cobra)
│   └── achillesd/           # optional server (the War Room)
├── internal/
│   ├── orchestrator/        # scan planning, worker pool, lifecycle
│   ├── scanner/             # Scanner interface + registry
│   │   ├── opengrep/
│   │   ├── bandit/
│   │   ├── gosec/
│   │   ├── trivy/
│   │   └── ...              # one package per adapter
│   ├── exec/                # container runner (Docker/OCI), sandboxing, resource limits
│   ├── model/               # Finding, Scan, Verdict, SARIF mapping
│   ├── normalize/           # native → Finding
│   ├── correlate/           # dedup + cross-tool clustering
│   ├── enrich/              # code context, git, dep facts, flow
│   ├── triage/              # LLM prompts, structured output, verifier
│   │   ├── llm/             # OpenAI-compatible client (base_url + key + model)
│   │   └── prompts/
│   ├── research/            # research agents: intel lookup → rule synthesis
│   ├── rules/               # generated-rule repository: store, versioning, validation gate
│   ├── vault/               # Evidence Vault: append-only provenance store (§5.1)
│   ├── knowledge/           # feedback store, embeddings (chromem-go), retrieval, calibration
│   ├── policy/              # license registry + scan/gating policy + containment profiles
│   ├── report/              # SARIF/HTML/markdown/JSON, PR annotations, CI gate
│   └── store/               # persistence (file default → PostgreSQL when scans and the War Room are separate processes)
├── pkg/                     # anything intended as a stable public API
├── configs/                 # default policies, tool image pins, rulepacks
├── deployments/             # Docker image + compose today; Helm is not provided
└── DESIGN.md
```

### 4.3 The core interface

```go
// A Scanner wraps one underlying SAST engine.
type Scanner interface {
    ID() string                 // "opengrep", "gosec", ...
    Meta() ScannerMeta          // license, languages, image pin, capabilities
    Applicable(t Target) bool   // does this repo contain langs this tool handles?
    Run(ctx context.Context, t Target) (RawResult, error) // runs the pinned container
}

// Normalizer turns a tool's native output into our model.
type Normalizer interface {
    Normalize(RawResult) ([]Finding, error)
}
```

Adapters are dumb: run the container, capture output (SARIF where possible), hand bytes to the normalizer. All intelligence lives above the adapter line, which keeps engines swappable.

### 4.4 Adding or swapping tools (modularity)

Tools are declared in `configs/tools.yaml` — image digest, output format, `enabledInMode`, languages, and normalizer mapping. Adding a scanner is ideally **config + a thin normalizer**, not core surgery:

- If a tool emits **SARIF**, the generic SARIF normalizer handles it and **no Go code is needed** — just a config entry and an image pin.
- Only non-SARIF tools need a small custom normalizer *(implemented 2026-07-09)*: a tool declares `format: <name>` in its config; that name rides on `RawResult.Format`, and `normalize.Normalize` dispatches to the registered `Normalizer` for it (`normalize.Register` for out-of-package/test ones). `sarif` is the default; `bandit` (Python `bandit -f json`) is the first per-tool JSON normalizer and the worked example. An unknown `format:` is a loud error, not a silent SARIF-parse failure. This removes the need to wrap non-SARIF tools (Bandit, ShellCheck, Railroader, verified-secrets tools) in a SARIF-converter container.
- **Swapping** an engine (e.g., Opengrep → some future better engine) is a registry edit, not a rewrite.

This is deliberate: the OSS scanner landscape moves fast (Semgrep→Opengrep happened in weeks), so onboarding or replacing a tool has to be cheap. The license/mode metadata travels with the tool declaration, so a swapped-in tool is automatically subject to the same `commercial-mode` gating.

### 4.5 Phased pipeline (the "mission" model)

A scan runs as an ordered set of **configurable, skippable phases**. This is an organizing overlay on the components above — each phase is a named, independently-observable step whose inputs/outputs land in the Evidence Vault (§5.1), which is what makes a run auditable and resumable.

| Phase | Does | Built from |
|-------|------|-----------|
| **1. Recon** | Detect languages, frameworks, entrypoints, exact dep versions → scan plan | enrich + inventory (feeds §9) |
| **2. Scan** | Run applicable engines in parallel containers → raw output | §6 execution + scanner adapters |
| **3. Triage / Judge** | Normalize → correlate/dedup → LLM triage → adversarial judge verification | §5 + §7 |
| **4. Remediation** | For confirmed findings, produce fixes/diffs or guidance (opt-in) | §7 + a dedicated remediation prompt |
| **5. Report** | SARIF + HTML/MD/JSON, PR annotations, CI gate | §11 |
| **6. Reflect** | Post-run: compare verdicts vs. human labels, update calibration + RAG, propose rule/prompt improvements | §8 + §9 |

Profiles pick the phase set: a **quick scan** runs Recon→Scan→Report; a **full mission** runs all six with human-in-the-loop on high-severity findings. Phases are the auditable, resumable unit — a failed phase records a gap and the run can resume from it rather than restarting.

> **Shared harness:** this phase engine, the exec/runner, normalize, Evidence Vault, and triage layers are engine-agnostic. The **Reverb** DAST sibling reuses this same harness, swapping SAST adapters for DAST engines (ZAP/Nuclei) and adding a Recon-driven attack-surface phase. Achilles itself stays static-analysis only (§1 Non-Goals).

---

## 5. Core Data Model

`Finding` is SARIF-shaped so we can both import and export SARIF losslessly:

```go
type Finding struct {
    ID          string        // stable hash: tool + rule + file + normalized span
    Tool        string
    RuleID      string
    CWE         []string      // normalized taxonomy (CWE primary)
    Message     string
    Location    Location      // file, region (line/col span), optional data-flow path
    CodeContext string        // surrounding source (populated by enricher)
    Severity    Severity      // tool-reported, pre-triage
    Fingerprint string        // for dedup + tracking across scans (stable across line drift)
    Raw         json.RawMessage

    // Populated by the triage layer:
    Verdict     *Verdict      // TP / FP / uncertain, confidence, exploitability
    Explanation string
    SuggestedFix string
    Provenance  Provenance    // model, prompt version, evidence used, retrieved examples
}
```

`Fingerprint` uses SARIF's partial-fingerprint idea (context hash rather than raw line number) so a finding survives reformatting and line drift — essential for baseline diffing and for the learning store to link "same finding, later scan."

### 5.1 Evidence Vault (provenance store)

Every phase writes to an **append-only, immutable Evidence Vault**: raw tool output, the normalized findings, each LLM prompt (+ prompt version) and its structured response, RAG hits used, the judge's verdict, and any human feedback — all keyed to a run + finding fingerprint. This one component does triple duty:

- **Compliance / trust**: a customer (or auditor) can reconstruct *exactly* why Achilles said what it said — which tool, which model, which evidence, which examples. This is the difference between a security tool teams trust and one they don't.
- **Reproducibility**: a run is replayable from its recorded inputs; we can diff two models or two prompt versions over the identical evidence.
- **The learning corpus**: the vault *is* the training data for §8 (retrieval + calibration) and §9 (rule performance stats). It's not a separate datastore bolted on later — the learning loop reads from the vault.

Storage: SQLite for records + `internal/vault` API; content-addressed blobs for large raw outputs. Records are write-once (corrections are new rows referencing the original), so the audit trail can't be rewritten. Each project's vault is isolated from the others (§10).

---

## 6. Execution Model
- **Every tool runs in a pinned container** (`configs/images.yaml` maps tool→digest). Reproducibility, isolation, and no "works on my laptop" tool-install hell.
- **Concurrency** *(implemented 2026-07-09)*: the CLI fans applicable scanners out over a bounded worker pool (`min(numCPU, N)`) — `runScanners` in `cmd/achilles`. Workers do only the parallel-safe work (Run + SARIF normalize); the collector serializes all Evidence-Vault writes and result aggregation, and results are sorted by tool id so output stays deterministic regardless of finish order. Verified race-clean.
- **Applicability** *(implemented 2026-07-09)*: `inventory.Scan` detects the tree's languages, and language-specific tools are skipped when their language is absent. Language-agnostic tools (SCA/secrets/IaC) declare `generic`, which is a wildcard and always applies.
- **Target prep once**: shallow-clone/checkout, language detection, then share the read-only workspace across adapters.
- **Failure isolation**: one tool crashing/timing out degrades to a partial scan with a recorded gap — never fails the whole run silently (we `log` the gap in the report).
- **Named containment profiles**: `default` (read-only source mount, resource caps) and `strict-containment` for customer code (also `--network none` — already the `DockerRunner` default — dropped capabilities, no egress, ephemeral filesystem). The profile is part of the scan config and recorded in the Evidence Vault, so "how isolated was this scan" is auditable after the fact.

---

## 7. LLM Triage & Verification Layer

This is the product's differentiator.

**Step 0 — Correlate** *(implemented 2026-07-30 — `internal/correlate`, `--no-correlate` to disable)*: before any model call, findings that different tools reported for the same defect (same file + line + CWE set) are grouped, and only the cluster's highest-severity member goes through steps 1–3. The others inherit its verdict, recorded to the vault under source `correlation` with `Provenance.CorrelatedFrom` naming the representative's fingerprint. The key is deliberately strict (no CWE or no line number → never clustered; same-tool repeats → never clustered) because a wrong merge yields a wrong verdict while a missed merge only costs one extra LLM call. Nothing is collapsed: identity, severity, and gating are untouched, which is what makes it safe on by default.

Then for each finding (or correlated cluster representative):

**Step 1 — Contextualize.** Enricher supplies: the code span + surrounding function, the data-flow path if the tool provided one, git blame (who/when), and for dependency findings the transitive path + fixed-version info.

*Enclosing-scope context (implemented 2026-07-30 — `internal/enrich/scope.go`).* The window was a fixed 3-line radius, which routinely cut off the function signature and the guard clause that decides whether a finding is real. It now widens to the **enclosing function/block**: brace-matching for C-family syntax (Go, Java, JS/TS, C/C++, C#, PHP, Rust, Swift, Kotlin, Scala, HCL) and indentation for Python; everything else keeps the fixed radius. It is a heuristic, not a parser — 15+ normalized languages don't justify carrying a parser each — so three things bound the damage: the resolved range must contain the flagged line, it is capped at `MaxScopeLines` (120 by default, clamped-and-labelled rather than dropped), and any failure falls back to the radius. The radius is also a **floor**: the window is unioned with it, so context can only grow. `MaxScopeLines = 0` restores pure fixed-radius behaviour. Measured on a 48-finding self-scan: triage prompt tokens +43.5%, projected spend +8.0% (`--dry-run` shows this before you pay it). **Triage-quality impact is unmeasured** — see the eval-harness gap in §14.

**Step 2 — Triage prompt (structured output).** The LLM returns a typed verdict, not prose:
```json
{
  "classification": "true_positive | false_positive | uncertain",
  "confidence": 0.0-1.0,
  "exploitability": "reachable | not-reachable | unknown",
  "reasoning": "...",
  "suggested_fix": "...",
  "cwe": ["CWE-89"]
}
```

**Step 3 — Adversarial verification (the anti-hallucination pass).** A *second, independent* LLM call is prompted to **refute** the first verdict ("assume this is a false positive; what evidence in the provided context supports that?"). We only surface as high-confidence when the verifier fails to refute. This is cheap insurance against confident-but-wrong triage — the single most important quality mechanism in the system. **Bidirectional as of 2026-07-30 (`triage/v2`).** The judge was one-directional: `HighConfidence()` requires `Classification == true_positive`, so refuting a *false_positive* set `Refuted=true` and the finding still stayed suppressed. It guarded over-reporting only and could not rescue a **missed** true positive — the costlier direction, since a false alarm wastes analyst time while a miss ships the bug. The eval corpus measured exactly that: a cheap triage model marked `go-trap-md5-auth-compare` false_positive at 0.95 confidence and the stronger judge model, already running on every finding, was structurally forbidden from overturning it.

Now the consequence of a refutation depends on the direction of the verdict it attacks:

| triage said | judge refutes | result |
|---|---|---|
| `true_positive` | yes | `Refuted` — suppressed (unchanged) |
| `false_positive` | yes | `Overturned` — **surfaced for review** |
| `uncertain` | yes | nothing: "the verdict is wrong" does not say which way, so we do not guess |

Three deliberate choices. The judge prompt states a **direction-specific burden of proof** (for a false_positive: show the value *is* attacker-influenced, the sink *is* reachable, or the claimed mitigation does not apply — and look past naming, which is a measured failure mode). The original `Classification`/`Confidence` are **preserved verbatim** rather than rewritten, because a 0.95 "false_positive" confidence is not evidence for the opposite claim; an overturn is its own state, and the report says so. And an overturned finding is `Surfaced()` but **not** `HighConfidence()`, so it reaches a human but never triggers remediation or an auto-fix PR — when two passes disagree we do not write a patch.

The win is that it costs **no extra calls**: the judge already runs once per finding, so the strong model's opinion was being computed and discarded.

**Step 4 — Ground truth where cheap.** For classes where static evidence is decisive (e.g., is the tainted source actually attacker-controllable? is the sink reachable from an entrypoint?), prefer evidence from the tool's own data-flow output over the model's guess. LLM fills gaps; it doesn't override hard evidence.

**LLM access — OpenAI-compatible by default.** `triage/llm` targets the OpenAI Chat Completions schema, so **any endpoint that speaks it works**: OpenAI, Azure OpenAI, local runtimes (vLLM, Ollama, LM Studio), and gateways (OpenRouter, Together, Groq — and Anthropic/Claude via its OpenAI-compat endpoint or a gateway). Config is just `{base_url, api_key, model}` per profile:

- **Swap the API key** or point `base_url` at a different provider with no code change.
- **Support any model** — the model name is config; structured output uses JSON-schema/JSON-mode where the endpoint supports it, with a parse-and-retry fallback for endpoints that don't.
- **Data-residency escape hatch**: point `base_url` at a self-hosted vLLM/Ollama and code never leaves your boundary. This is the single change that unblocks security-conscious users, and it costs nothing because it's the same interface.

The interface stays narrow (one `Complete(ctx, req) → resp` method) so a genuinely non-compatible provider can be added as a second adapter later without touching triage logic.

**Model routing (cost control).** The client resolves a model *per task*, not globally: a cheap/fast model for high-volume triage, a stronger model for the judge pass, remediation, and reflection. Each task maps to a named profile (`{base_url, api_key, model}`), so routing is pure config. This is where most of the LLM cost savings live at scale.

**Step 5 — Remediation (opt-in, its own phase).** For confirmed findings, a remediation prompt produces a concrete fix — a diff/patch where the fix is local and mechanical, or guidance where it needs judgment. Remediation is a separate phase (§4.5) and a separate model profile because it's higher-value, lower-volume than triage. We *propose*; we never auto-merge (§1 Non-Goals).

> **Note on agent loops.** We deliberately keep triage as a structured two-pass (triage → judge) rather than open-ended ReAct loops. Free-form loops add latency, cost, and nondeterminism that hurt more than they help for finding-level triage. Reserve genuinely agentic (multi-step, tool-using) loops for the research agents (§9), where the task actually requires iterative investigation.

- **Threat-model agent** *(implemented 2026-07-11, Tier D — `internal/threatmodel`, `--threat-model <path>`)*: infers a starting-point threat model from the codebase profile + findings and writes it as an **OTM (Open Threat Model) 0.2.0** document — `trustZones`, `components` (assigned to zones), and STRIDE `threats` with risk + mitigation, each tied to a component where possible. Schema-validated LLM output for the body; Achilles sets `otmVersion` + `project` (from the target) for grounding. Vault `KindThreatModel`, routed through the `threat-model` task. Honest scope: it's an inferred scaffold to review/refine, not a substitute for a human threat-modeling session; the prompt tells the model not to invent components it has no evidence for.
- **SCA upgrade advisor** *(implemented 2026-07-09, Tier D — `internal/advisor`, `--sca-advice`)*: turns the dependency inventory + the SCA scanners' vulnerability findings (osv-scanner/trivy/govulncheck — which carry the vulnerable/fixed versions) into a prioritized, **merge-safety-scored** upgrade plan: security-driven upgrades first, each scored `low|medium|high` merge risk (patch/leaf = low; major/core = high). Structured output (`Advice{summary, upgrades[]}`), vault `KindAdvisory`, routed through the `sca` task. Honest scope: it reasons about *prioritization + merge risk*, not exact target versions (it leaves `recommendedVersion` empty when unsure).
- **Full-repo review agent** *(implemented 2026-07-09, Tier D — `internal/review`, `--review`)*: a holistic pass that is deliberately NOT finding-level. It reasons over a compact codebase profile (languages, dependency count, scanners run, per-severity finding counts, most-common rules/files) plus the surfaced findings, and returns **systemic** risks — architectural weaknesses, themes across multiple findings, missing controls, risky tech/dep choices — that no single rule reports. Structured output (schema-validated `Review{summary, risks[]}`), recorded to the vault (`KindReview`), routed through the `review` task so `--model-config` can give it a stronger model than triage.

---

## 8. The Learning Loop (honest mechanics)

**Important framing:** a hosted LLM does not learn from your usage. So "gets smarter over time" is delivered by a **data system around** the model, not by the model itself. Four concrete mechanisms, cheapest→most involved:

1. **Feedback store (foundation).** Every analyst decision (confirm/reject/reclassify) is persisted against the finding fingerprint: `{fingerprint, code_context, tool_verdict, llm_verdict, human_verdict, timestamp}`. This is the labeled dataset everything else is built on. Ship this from day one even before it's used — the data compounds.

2. **Retrieval-augmented triage (the real "gets smarter").** Embed each finding's code context + rule. At triage time, retrieve the *k* most similar past findings **with known human verdicts** and inject them as few-shot examples ("last 4 times we saw this shape, analysts ruled 3 FP because X"). The model's behavior improves as the corpus grows — no retraining. This is where most of the compounding value lives.

3. **Per-rule / per-pattern calibration.** Track TP/FP rate per `(tool, rule)` and per finding-cluster signature. Auto-downrank or auto-suppress chronically-noisy rules (with an audit trail), and boost rules with high confirmed-TP rates. Surfaces as a "rule health" report — `--rule-health` *(implemented 2026-07-09)* prints every rule's TP/FP/samples/FP-rate from accumulated feedback, noisiest first, flagging which are auto-suppressed (same `>=3 samples & >=80% FP` thresholds the triage calibrator uses) vs. `watch` vs. `healthy`. It reads only the vault's feedback history (no scan, no LLM).

4. **Optional fine-tuning (much later, gated on data volume).** Once the feedback store has enough high-quality labels, fine-tune a smaller/open triage model or distill a classifier for the high-volume, low-ambiguity cases — reserving the big model for the hard ones. Only worth it after 1–3 prove insufficient.

**Metrics we track to prove it's working:** precision/recall of LLM triage vs. human ground truth over time, FP-suppression rate, analyst time-per-finding, and rule-health drift. If these curves don't improve, the learning loop isn't earning its keep — and we'll know.

**Eval harness** *(implemented 2026-07-30 — `internal/eval`, `cmd/achilles-eval`, corpus in `evals/triage/`)*. The promise above needed a measuring instrument: until this existed every prompt/context/model change was argued rather than measured, and the one-off bake-off's corpus was never committed, so no result was reproducible and no regression could be caught. Two modes, split by what they need:

- **Context mode** is hermetic — no model, no key, no cost. Each case declares the `evidenceLines` a triager must see to decide correctly; the harness builds the prompt Achilles *would* send and checks whether they are in it. It gates in CI (`make eval-gate`) against a committed baseline, so a change that quietly takes context away fails the build.
- **Verdict mode** runs the real triage→judge path against a live model and scores against the labels. It scores on `Verdict.HighConfidence()` — the shipped surfacing decision — so the metric covers the prompt, the judge, and the 0.7 threshold together rather than the first prompt alone. Headline is **balanced accuracy** (a confirm-everything triager scores 0.5, not something respectable); it also reports TP recall, FP suppression, a calibration gap, and per-case instability across `--repeat`.

The corpus is 14 cases, 7 tp / 7 fp — the FP half is the point, since suppressing safe-but-flagged code is the job. Loading validates every line number against the fixture, so a drifted corpus fails loudly instead of silently scoring the wrong span. Honest limits: 14 cases catches gross regressions and obvious wins, not two-point differences between models; and context mode measures whether evidence is *available*, never whether the model *used* it.

---

## 9. Research Agents & Self-Growing Rule Repository

**Your instinct is good — with one non-negotiable guardrail.** This turns Achilles from a static wrapper into a *continuous detection-engineering* loop, which is a real and defensible pattern (it's essentially automated variant analysis + threat-intel-to-detection). The guardrail: **every generated rule must pass an automated validation gate before it is ever allowed to run against customer code.** Skip that and the corpus becomes a false-positive factory that poisons every future scan. Keep it, and the rule repository becomes a genuine moat that compounds.

### 9.1 What's actually novel here (and what's already covered)

Be honest about overlap: **known CVEs in your dependencies are already handled *deterministically*** by the SCA tools (Trivy / Grype / OSV-Scanner). Do **not** have an LLM re-derive those — it'll hallucinate versions and advisory IDs, and you'd be paying tokens to reproduce a lookup you already do for free. The research agents earn their keep on the **long tail SCA misses**:

- newly-disclosed issues with no clean package-version match yet;
- framework/library **misuse** patterns (insecure-by-default configs, dangerous-API usage) that aren't a CVE at all;
- threat intel "in the news" for a technology that's in the stack;
- codebase-specific patterns worth a bespoke rule.

### 9.2 Flow

1. **Inventory** (already produced in Phase 1): languages, frameworks, and exact dependency versions from the SBOM/SCA pass.
2. **Dedup & gate targets**: only research stack items not researched recently — cache keyed on `tech@version` with a TTL. Controls cost and noise.
3. **Research agent** (per novel target): performs **grounded** lookups against authoritative sources — OSV.dev, NVD/CVE, GitHub Security Advisories, vendor advisories, news — and must cite a real, resolvable source. **A claim with no citation is discarded** (anti-hallucination rule #1). This is a tool-using agent, not a free-associating one.
4. **Rule synthesis**: for confirmed issues a scanner *could* catch structurally, generate an **Opengrep/Semgrep YAML rule** (our primary engine; rules are pattern YAML, and rules we author are our own clean IP).
5. **Validation gate (mandatory)** — see §9.3.
6. **Admit / quarantine**: rules that pass are versioned into the repository and used in future scans; rules that fail are quarantined for human review and **never auto-run**.

### 9.3 The validation gate (the whole idea lives or dies here)

A synthesized rule is admitted only if it:

- **parses/compiles** in the engine,
- **matches** at least one *vulnerable* test snippet (true-positive proof), and
- **does NOT match** a *patched/benign* counterpart (false-positive proof).

The agent generates both snippets, ideally seeded from the advisory's real PoC and patch diff. This is the same "prove it works" discipline as the adversarial verifier in §7: a rule that can't demonstrate it catches the bug *without* flagging the fix does not ship. Rule validation runs in the same sandboxed container path as the scanners — only ever against synthetic snippets.

### 9.4 Rule repository & lifecycle

- **Versioned store** (`internal/rules`): each rule carries provenance — source advisory/CVE, generating model + prompt version, test fixtures, creation date.
- **Performance tracking**: once live, each rule accrues TP/FP stats from real scans + analyst feedback — reusing the **exact same calibration machinery as §8**. Noisy rules get auto-demoted/retired; high-yield rules get promoted. The corpus curates itself.
- **It's a learned artifact**, so it plugs into the learning loop rather than being a separate system. The rule repository *is* part of "gets smarter over time."
- **Licensing stays clean**: we author original rules and never import Semgrep's restricted registry. If an agent references a public PoC, that's threat intel (facts), not copied rule IP — but we record sources regardless.
- **Rule miner from confirmed findings** *(implemented 2026-07-09, Tier D — `research.Miner`, `--mine-rules`)*: a SECOND source for the rule repo, sourced from our own data rather than external intel. It takes analyst-**confirmed** (true-positive) findings from the vault, turns each into a synthesis seed (the finding's message + code context + an internal citation), and runs it through the *same* synthesize → §9.3 validation gate → RuleRepo pipeline as the research agents. So confirmed patterns become durable, precise Opengrep rules — which then flow into future scans via the flywheel + shadow window below (and can turn an expensive LLM-triaged pattern into a cheap deterministic rule). Skips already-generated (`gen.*`) rules and findings whose language can't be inferred; the validation gate quarantines bad mines.
- **Loaded into scans + shadow window** *(implemented 2026-07-09)*: admitted rules feed subsequent scans automatically. `RuleRepo.Provision` materializes the always-active baseline rules plus generated rules that have aged past a **shadow window** (`--rule-shadow-days`, default 7) into Opengrep's active rule set; rules still inside the window run in a *separate* report-only pass and their findings are tagged `Shadow` — surfaced in the report but excluded from the `--fail-on` gate, issue filing, and written baselines. So a freshly-admitted rule is observed before it can affect an outcome, and (once it ages in) its findings become genuinely "new" and gate. The two-pass split makes shadow status unambiguous without brittle rule-id matching; the adapter runs with `--no-rewrite-rule-ids` so ruleIds/fingerprints stay stable across machines and runs.

### 9.5 Safety & cost controls

- Research agents **read**; they never execute untrusted code. Only synthetic validation snippets ever run, and only in the sandbox.
- Rate-limit + cache research per `tech@version`; full re-research only on TTL expiry or a new disclosure.
- Per-scan budget cap; research is **async/best-effort and never blocks** the core scan from returning results.

**Verdict on the idea:** worth building — it's the feature that makes Achilles compound rather than stay a thin wrapper. Sequence it *after* the learning loop (it reuses that loop's feedback/calibration plumbing), and ship it with the §9.3 gate from day one or not at all.

---

## 10. Commercial-Readiness Design

The policy features that make Achilles safe to use on code you do not own, or inside a paid service:

- **License registry** (`internal/policy`): every scanner declares `{license, commercialSafe, requiresAttestation}`. A scan runs under a **mode**; `commercial-mode` refuses to enable any non-safe tool. This is enforced in code, tested, and logged — not tribal knowledge.
- **Data boundary**: code never leaves the deployment except in LLM calls. Options: (a) redact secrets/PII before sending, (b) send only minimal context windows, (c) BYO/self-hosted model for customers with hard data-residency rules.
- **Projects (tenants)**: a project is a namespace for grouping the repos you scan, with its own isolated workspaces, findings, and feedback store. One project's learning data never appears in another's retrieval set. (The code, config keys and vault layout still say `tenant`; the user-facing name is *project*.) This is isolation of *data*, not of *people*: the War Room has no authentication (§10).
- **War Room security model — no authentication, by design.** Achilles is for someone scanning their own repositories, so `achillesd` is a single-user tool that ships no login, roles or per-user access. Anyone who can reach its port can read every finding and submit feedback, create projects, purge data and view the fleet rollup; so it is made reachable only from the local machine: it listens on loopback by default and refuses another address without `--allow-remote`; the compose stack publishes it on `127.0.0.1` only; the `Host` header must be `localhost`/`127.0.0.1`/`::1` or listed in `--allowed-hosts` (defeats DNS rebinding); and state-changing requests are protected against cross-site requests (`http.CrossOriginProtection`). Sharing it means putting your own authenticating reverse proxy in front (and adding its hostname to `--allowed-hosts`) or not sharing it.
- **Auditability**: every verdict carries `Provenance` (model, prompt version, evidence, retrieved examples) so a customer can see *why* Achilles said what it said. Critical for security-tool trust.
- **Secrets hygiene**: findings frequently *contain* secrets (Gitleaks). Redact in storage and reports by default; never log raw secret material.

---

## 11. Reporting & CI Integration
- **Outputs**: SARIF (for GitHub code scanning / other consumers), plus HTML and Markdown summaries, and machine JSON.
- **PR annotations**: inline comments on the diff for new findings only (baseline-aware, using fingerprints).
- **Inline review comments** *(implemented 2026-07-11, Tier C — `--pr-review <n> --pr-head-sha <sha>`)*: posts findings as inline comments on the PR diff via the review-comments API. Deduped by a per-finding fingerprint marker (re-runs don't repost), best-effort per comment (a line not in the diff → 422 → skipped, not fatal), and capped (the rest stay in the sticky summary). Pairs with `--diff` (only changed-line findings land inline).
- **Issue lifecycle** *(implemented 2026-07-13, Tier C — `--file-issues`)*: reconciles GitHub issues against the current finding set, keyed by a per-finding fingerprint marker in the issue body. A finding with no issue → open one (labeled `achilles`); a fingerprint matching an **open** issue → already tracked (skip); a fingerprint matching a **closed** issue → suppressed, i.e. a human triaged/won't-fixed it (never refiled); an open Achilles issue whose fingerprint is **no longer detected** → auto-closed (`state_reason: completed`). New issues are capped per run. Auto-close reconciles against the full finding set, so it is **skipped under `--diff`** (a diff-limited scan doesn't see findings outside changed files). Intended for full-repo / scheduled scans on the default branch.
- **Auto-fix PRs** *(implemented 2026-07-13, Tier C — `--fix-pr`, needs `--remediate`)*: opens a **review** PR carrying high-confidence auto-fixes. For each remediation that produced a concrete unified diff, Achilles applies it to a fresh branch (`internal/gitops`: `git checkout -B` → `git apply` → `git add`/`commit` → `push` to `--fix-remote`, default `origin`), then opens a PR into `--fix-base` (default: the current branch). **It never merges** — this is the load-bearing guardrail (DESIGN §1 Non-Goals). The branch name is derived from the SHA of the fingerprints being fixed, so a re-run reuses the same branch/PR (checked via `ListPullsForHead`) instead of spawning duplicates; patches that don't apply cleanly are skipped, not fatal; fixes per PR are capped. Prose-only remediation (guidance, no diff) is left for the sticky summary/issues, not force-patched.
- **Sticky PR summary comment** *(implemented 2026-07-11, Tier C — `internal/github`, `--pr-comment <n>`)*: posts the Markdown scan summary as a single comment on the PR, updating its own comment on re-runs (found via a hidden `<!-- achilles:pr-summary -->` marker) instead of spamming a new one. Uses `GITHUB_TOKEN` + `--repo`/`$GITHUB_REPOSITORY`, so it drops into a GitHub Action. Outward-facing + opt-in: it posts only when the flag is set. (Inline Review-API comments, issue lifecycle, and auto-fix PRs are the remaining Tier-C GitHub items.)
- **CI gate**: policy-driven exit codes — e.g., "fail on confirmed-TP high/critical introduced in this diff," configurable per repo. Baseline suppression so legacy debt doesn't block every PR.
- **Baseline classification** *(implemented 2026-07-09)*: `baseline.Classify` splits a scan against the baseline into **introduced** (new — these gate), **pre-existing** (already known), and **fixed** (baseline fingerprints no longer present — resolved by this change). The CLI prints the breakdown and records it to the Evidence Vault for the audit trail / War Room. Follow-up: emit SARIF `baselineState` (new/unchanged/absent) so GitHub code scanning shows the same tri-state natively.
- **Diff-aware scanning**: scan changed files/functions for PR speed; full scan on schedule.
- **Fleet metrics rollup** *(implemented 2026-07-11, Tier E read-side — `internal/metrics`, `--metrics`)*: a pure read over the Evidence Vault that aggregates findings by severity/tool/rule/**target**, the analyst feedback FP rate, and LLM token spend. Because it's a vault query, it works identically on a single file-backed vault or a shared PostgreSQL vault holding many targets/projects — so it IS the read-side of fleet aggregation regardless of how scans are dispatched. "Runs" counts scan-meta-bearing run IDs only (standalone actions like `--feedback` don't inflate it). The multi-repo *dispatch* builds on this same aggregation (see the fleet control plane, `achilles-fleet`).
- **Cross-project rollup + War Room fleet view** *(implemented 2026-07-11, Tier E)*: `metrics.ComputeFleet` aggregates per-project vaults into fleet-wide totals + a per-project breakdown; the War Room serves it at `GET /admin/fleet`, discovering projects via the registry and reading each one's isolated vault. So you see the whole set of repos you scan — total findings, severity mix, FP rate, LLM spend, and a per-project table — from the vault we already have.
- **PR-mini (auto seed-vs-delta)** *(implemented 2026-07-09)*: `--pr-mini <file>` seeds the baseline on first run (full scan, writes the baseline, doesn't gate) and delta-scans against it thereafter (gates only on newly-introduced findings). One flag replaces the "first run vs. subsequent runs" branching a consumer workflow would otherwise hand-code.
- **PR vs. full severity floors**: PR and scheduled/full scans use different `--fail-on` floors — e.g. `--fail-on high` on PRs (block only serious *new* issues), a stricter floor on the scheduled full scan. This is workflow config (two invocations), not a code path; the example workflow shows the PR side.
- **Per-repo config merge** *(implemented 2026-07-09)*: a target's own tool ignore/config files are honored so Achilles doesn't re-report what the repo already suppressed. Declarative in `configs/tools.yaml` (`localConfig: [{file, arg}]`): when the target contains `file`, `arg` is appended to that tool's argv. Wired for Trivy (`.trivyignore` → `--ignorefile`) and Gitleaks (`.gitleaks.toml` → `--config`); Opengrep already reads a target's `.semgrepignore` from the scan root.
- **Noise filter** *(implemented 2026-07-09)*: findings in vendored dependencies, generated code, and minified assets are dropped before diff/baseline/gating, so third-party and machine-written code doesn't drown the signal (`internal/noise`). On by default (vendor/node_modules/third_party/…, `*.min.js`, `*.pb.go`, …); `--no-default-excludes` disables it and `--exclude` adds patterns (a path segment or a basename glob). Test code is NOT excluded by default — security issues in tests can be real; opt in with `--exclude` if desired. Excluded counts are logged and recorded to the vault (never a silent drop).
- **Project discovery + switcher** *(implemented 2026-07-28)*: the War Room resolved the project from the `X-Tenant` header only, so a browser always landed on `tenant-default` — effectively single-project once CI started writing per-repo vaults. The switcher needed a *list*, and the registry was the wrong source: scans write straight to their project vault and never register, so `registry.List()` under-reports (`/admin/fleet` had the same blind spot). Added backend-aware discovery — PostgreSQL keys by `tenant-` prefix, `<root>/<id>/vault.jsonl` dirs for the file backend — unioned with the registry, so a project that exists only as *data* is still selectable. Selection is `?tenant=` persisted to a cookie so navigating into a run detail page stays in the same project. Precedence: `X-Tenant` > `?tenant=` > cookie > `default`. Every value is validated so a bad id reaches neither a store nor a cookie. Selection is a convenience for one user, not an access control.
- **Vault write integrity** *(implemented 2026-07-28)*: Evidence Vault writes were `_, _ = Append(r)` — a scan could authenticate, print its vault banner, exit 0, and persist **nothing**. For the component that IS the audit trail, silent loss is worse than failure. Writes are now checked and counted; the first cause prints immediately; and the run exits non-zero via a check that runs **before** the `--fail-on` gate, so a vault outage can't hide behind a passing gate. Deliberately not fatal mid-scan — the report and gate are still worth producing. Found by a live CI run that reported success with an empty vault.
- **Credentials stay out of argv and the vault** *(implemented 2026-07-27/28)*: the LLM key is read from `ACHILLES_LLM_API_KEY` (or `OPENAI_API_KEY`), the PostgreSQL connection string from `ACHILLES_VAULT_DSN`, and git tokens for fleet sources from environment variables *named* in the fleet config. None of them appears on a command line, in a log line, or in the Evidence Vault.
- **Diagnostics sidecar** *(implemented 2026-07-09)*: `--diagnostics <path>` writes a JSON sidecar recording (a) tool/parse failures — a tool that failed to run or whose output couldn't be normalized, so a degraded scan never reads as silently "clean" (§6 failure isolation made visible), and (b) LLM token usage (prompt/completion/total, accumulated across triage/judge/remediation). Both are also written to the Evidence Vault. Token→dollar costing needs a per-model price table and is deferred.

---

## 12. Tech Stack
- **Language**: Go (see rationale below).
- **CLI**: cobra + viper (Phase 1+; Phase 0 is stdlib `flag` to stay dependency-free).
- **Container exec**: Docker/OCI via API; abstracted so we can swap to a rootless/remote runner.
- **Storage**: the Evidence Vault (§5.1) is the only persistence layer, behind the `vault.Store` interface: a JSONL file (default, single-binary, safe to share between processes on one host), or PostgreSQL (shared between processes, one key per project).
- **Vectors/RAG**: **chromem-go** — pure-Go, embeddable, persistent vector DB. Keeps the single-binary story (no separate vector service), Ollama-native for local embeddings. Move to pgvector only if corpus scale demands it.
- **LLM**: **OpenAI-compatible client** — configurable `base_url` + `api_key` + `model` per task profile (model routing, §7); works with OpenAI, Azure, vLLM/Ollama, and gateways. Self-hostable for data-residency. Swap key or base URL to change providers with no code change.
- **Web/API (UI phase)**: stdlib `net/http` + chi router (or Gin) — **not Fiber**; its fasthttp base complicates the SSE we need for live phase progress. Server-rendered **HTMX + Alpine.js + Tailwind** for the "War Room" UI (lightweight, Go-native, no SPA build step).
- **SARIF**: a Go SARIF library (or a small internal package) for import/export.
- **Composability (optional)**: expose phases as **MCP** tools (`run_recon`, `analyze_finding`, …) so Achilles is usable from other local agent setups. Nice-to-have, gated behind a flag; not on the critical path.

**Why Go (your question):** right call for this tool. Single static binary makes CI distribution trivial; goroutines fit the fan-out-many-scanners pattern perfectly; and the entire modern security-tooling ecosystem you're wrapping (Trivy, Grype/Syft, Gitleaks, gosec, KICS, OSV-Scanner, Nuclei) is Go — so shelling out, sharing formats, and even importing some as libraries is natural. Rust is the only serious alternative and buys you little here while costing iteration speed. **Caveat:** the LLM/data-science tooling (embeddings, eval harnesses, any future fine-tuning) is Python-first. Keep those as separate Python sidecar services behind a clean API rather than fighting to do ML in Go — a Go orchestrator with a Python "brain" service is a fine, common split.

---

## 13. Roadmap (thin vertical slices)

**Phase 0 — Walking skeleton (1 tool, end to end). ✅ scaffolded (2026-07-05).**
CLI → run Opengrep (local or container) → normalize SARIF → `Finding` → SARIF + human report. No LLM yet. Proves the spine. Stdlib-only (no external deps); `--from-sarif` ingest mode + normalizer unit tests make the normalize→report path verifiable without Docker/Opengrep installed. `--fail-on` gate implemented.

> Note: this roadmap is the **build order**. It's distinct from the runtime **mission phases** in §4.5 (Recon→…→Reflect), which are assembled incrementally across these build phases.

**Phase 1 — Multi-tool + Evidence Vault. ✅ built & tested (2026-07-06).**
Config-driven tool registry (`configs/tools.yaml`) + generic SARIF adapter (gosec, Trivy as config entries; opengrep bespoke) + license-mode policy gate (`oss`/`commercial` + attestation) + append-only **Evidence Vault** (§5.1). Apache-2.0 LICENSE + `THIRD-PARTY.md` in. Verified: hermetic unit tests (policy/config/vault/generic/normalize) + real-Opengrep integration test (`-tags integration`). **Deferred to Phase 1.1:** cross-tool correlator/dedup; AGPL-import CI check.

**Phase 2 — LLM triage + judge. ✅ built & tested (2026-07-06).**
OpenAI-compatible client (`internal/triage/llm`) + model Router + enricher (code context) + structured triage verdict + adversarial judge, all recorded to the vault. Reports carry verdicts/confidence/exploitability/fix. Verified with a fake LLM client (hermetic) + httptest for the HTTP client + a live mock-endpoint end-to-end run.

**Phase 2.1 — Remediation + git-blame + JSON-schema. ✅ built & tested (2026-07-06).**
Remediation as its own step (high-confidence findings only; produces diff/guidance; never auto-applied). git-blame enrichment appends attribution to prompt context (best-effort). LLM client gains strict `json_schema` output with an automatic retry-to-`json_object` fallback for endpoints that don't support it. CLI `--remediate`. Verified: hermetic tests over a real temp git repo + httptest.

**Phase 3 — Learning loop. ✅ built & tested (2026-07-06).**
Feedback capture (`internal/knowledge`, vault-backed, keyed by fingerprint), per-rule **calibration** that auto-resolves chronically-FP rules without an LLM call, and **chromem-go** RAG (injectable embedder; OpenAI-compat in prod) that injects similar past findings as few-shot. Wired into the triage engine + CLI (`--feedback`, `--rag`). Verified end-to-end: scan→triage says TP → 3 FP feedback → re-scan auto-resolves as FP with **no LLM call**. Rule-health metrics surface via `Calibrator.Health`; a dedicated Reflect-phase agent is a later refinement.

**Phase 4 — Research agents & rule synthesis. ✅ built & tested (2026-07-06).**
`internal/inventory` (languages + deps from go.mod/requirements.txt/package.json) feeds `internal/research`: an LLM **Agent** that discards any issue without a resolvable citation, an LLM **Synthesizer** that emits an Opengrep rule + vulnerable/patched fixtures, and the **§9.3 validation gate** (`OpengrepValidator` + `Admit`) that admits a rule only if it parses, matches the vulnerable fixture, and does NOT match the patched one. Admitted/quarantined rules land in a versioned `RuleRepo` with provenance, logged to the vault. CLI `--research`. Verified: hermetic gate/agent/engine tests (fakes) + real-Opengrep integration test (good rule admitted, overbroad rule rejected) + live E2E (flask dep → cited issue → synth → real gate → admitted rule with provenance). **Follow-ups:** ~~feed admitted rules into future scans~~ (done 2026-07-09 — §9.4, with a shadow window); OSV.dev grounding; rule performance tracking via §8 calibration.

**Phase 5 — CI & delivery. ✅ built & tested (2026-07-06).**
`internal/baseline` (suppress known findings; write baseline), `internal/vcs` (diff-aware — changed files vs a git ref), and `internal/report` exports: unified SARIF, JUnit XML, Markdown, GitHub-annotation workflow commands. `--fail-on` is now baseline/diff-aware (gates on the surfaced set). GitHub Action (`action.yml`) + repo CI + example scan workflow + `make release` cross-compile. Verified: hermetic export/baseline tests + real-git diff test + live E2E (baseline suppresses → gate flips exit 1→0; all exports valid). **Known UX:** stdlib flag requires flags before the target path (cobra migration backlogged).

**Phase 6 — War Room UI + per-project isolation. ✅ built & tested (2026-07-06).**
`cmd/achillesd` + `internal/server`: server-rendered **HTMX/Alpine War Room** (dashboard, run/findings explorer with inline verdicts, one-click TP/FP feedback, Evidence Vault audit export as JSON, SSE event stream). Hardening: **per-project vault isolation** (structural — each project's data under its own dir or key), **secret redaction** before anything reaches the UI/API. Dep-free (Go 1.22 `net/http` routing, `html/template`, `embed`). Verified: httptest suite (project isolation, redaction, feedback→vault, audit JSON, SSE) + live curl demo. UI feedback feeds Phase-3 calibration, closing the loop. Deliberately **no authentication** — see §10; live per-scan SSE progress remains open.

Each phase is shippable and independently useful; we validate before expanding. **All six phases are complete.**

---

## 14. Risks & Open Questions
- **LLM triage cost at scale.** A large repo can produce thousands of findings; two LLM calls each is real money/latency. Mitigation: correlate/cluster first, triage clusters not raw findings, cache verdicts by fingerprint, and use the calibration layer to auto-resolve high-confidence noise without a model call. **Correlation shipped 2026-07-30** (`internal/correlate`, on by default, `--no-correlate` to disable): findings from *different* tools sharing a file+line+CWE are clustered, the highest-severity member is triaged, and the rest inherit its verdict (vault source `correlation`, `Provenance.CorrelatedFrom`). It collapses nothing — every fingerprint, severity, and gating decision is unchanged — so baselines, `--file-issues`, and feedback are unaffected. Calibration still wins over an inherited verdict (per-rule feedback beats a sibling's verdict) and remediation is never inherited. **Pre-flight cost gate shipped 2026-07-30** (`internal/cost` + `Engine.Plan`, `--dry-run` / `--max-cost` / `--price-config`): the planned call set is projected from the real prompts before the first model call, reflecting the surfaced set, correlation savings, and calibration short-circuits. Dollars require an operator-supplied price table — we ship none deliberately, since prices change per provider and a cap built on guessed numbers is worse than no cap — so `--max-cost` refuses to run rather than enforce an uncomputable cap. Still open from this bullet: verdict caching by fingerprint across runs, and **mid-run** enforcement (the cap is pre-flight only, so actual spend can still exceed the estimate).
- **LLM false confidence.** Adversarial verifier (§7 step 3) + prefer-hard-evidence (§7 step 4) are the guardrails; the §8 metrics tell us if they're working.
- **Research agents hallucinating vulnerabilities.** The #1 failure mode of the §9 feature. Guardrails: mandatory resolvable citations (no citation → discarded), don't re-derive what SCA already knows deterministically, and the §9.3 validation gate means a hallucinated issue can't produce a shipping rule (it won't have a real vulnerable snippet to match).
- **Generated-rule quality / corpus poisoning.** A bad rule pollutes every future scan. The §9.3 gate (must match vulnerable, must NOT match patched) plus §9.4 performance-based auto-demotion are the containment; quarantine-not-auto-run is the backstop.
- **Model portability across OpenAI-compatible endpoints.** Structured-output support varies (JSON mode vs. tool-calls vs. nothing). Mitigation: JSON-schema where supported, parse-and-retry fallback otherwise; validate each new model in an eval harness before trusting its verdicts.
- **AGPL contamination via TruffleHog (or future AGPL tools).** If we ever `import` an AGPL module instead of shelling out, Achilles itself becomes AGPL, which conflicts with its Apache-2.0 license. Mitigation: the process-boundary rule (§3) and a CI check that fails on any AGPL-licensed dependency in `go.mod`. Not legal advice.
- **Evidence Vault growth.** Storing every raw tool output + prompt/response per run grows fast. Mitigation: content-addressed blob storage with dedup, retention policies per project, and keeping large raw outputs out of the hot SQLite path.
- **License drift.** Tool licenses change (Semgrep, Brakeman both did). The registry must be reviewed per tool-version bump; make it a release checklist item.
- **Data residency.** Sending code to a third-party LLM is a dealbreaker for some users → the self-hosted-model path (now easy via OpenAI-compatible `base_url`) isn't optional long-term.
- **Ruby coverage gap.** Railroader (MIT) replaces Brakeman but is a community fork — verify its maintenance health before promising Rails coverage in commercial-mode.
- **Open question:** global vs. per-project learning — this now includes the *generated rule corpus*, not just triage feedback. Cross-project rule sharing is more powerful but a privacy/contractual minefield (a rule's test fixtures can leak a project's code shape). Default project-private; revisit opt-in anonymized sharing later.

---

## Appendix A — Sources (license verification, 2026-07-05)
- Opengrep / Semgrep relicensing: InfoQ, The New Stack, semgrep.dev/docs/licensing
- Brakeman CC BY-NC-SA: github.com/presidentbeef/brakeman/blob/main/LICENSE.md; rails/rails#51195
- CodeQL terms: github.com/github/codeql-cli-binaries/blob/main/LICENSE.md
