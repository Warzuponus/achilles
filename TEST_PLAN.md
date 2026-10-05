# Achilles — Test Plan

Every phase ships with verifiable tests. "Done" means the acceptance checks
below pass, not "looks right."

## Testing philosophy

1. **Hermetic by default.** `go test ./...` must pass with **no** external tools,
   network, Docker, or API keys. Scanner execution is tested against a **fake
   `exec.Runner`** that writes canned SARIF, and normalization is tested against
   **committed SARIF fixtures**. This keeps CI fast and deterministic.
2. **Real-tool integration tests are opt-in**, behind the `integration` build
   tag, and `t.Skip()` when the tool is absent:
   `go test -tags integration ./...`.
3. **LLM-dependent tests (Phase 2+)** use a fake LLM client returning fixed
   structured responses. Live-model runs go behind an `llm` tag + env-gated key.
4. **Every bug gets a regression test** before the fix is called done
   (e.g. the SARIF `defaultConfiguration.level` inheritance bug → dedicated test).

Commands:
```bash
make test              # hermetic unit tests (go test ./...)
make test-integration  # + real tools where installed (-tags integration)
make vet               # go vet
gofmt -l .             # formatting (must be empty)
```

---

## Phase 0 — Walking skeleton  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| SARIF → Finding normalization | `internal/normalize` unit tests over `testdata/sample.sarif` (count, tool name, field mapping, severity, CWE, fingerprint precedence, stable fallback, empty, malformed) | ✅ |
| Human report + severity gate | exercised via `--from-sarif` + `--fail-on` (manual + used in demos) | ✅ |
| End-to-end spine w/o tools installed | `achilles --from-sarif testdata/sample.sarif` | ✅ |

Acceptance: `go test ./...`, `go vet`, `gofmt -l` all clean. ✅

---

## Phase 1 — Multi-tool + Evidence Vault  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| **License-mode gate** | `internal/policy` table test: safe/non-safe/attestation × oss/commercial; unknown-mode error | ✅ |
| **Config loader** | `internal/config` tests: parse fixture, field mapping, `ToLicense` projection, missing-file error, duplicate-id + enabled-without-argv validation, bespoke exemption | ✅ |
| **Evidence Vault** | `internal/vault` tests: append+get, ByRun filter, distinct IDs for identical payloads, **persistence across reopen**, correction-references-prev (immutability model) | ✅ |
| **Generic config-driven scanner** | `internal/scanner/generic` tests via fake runner: reads tool SARIF, read-only src mount, missing-output→error, Applicable language matrix, argv placeholders reach runner | ✅ |
| **Multi-image runner** | `exec.Command.Image` per-tool; docker runner falls back to default | ✅ (unit path) |
| **CLI wiring** (gate → register → run → vault) | manual demo: commercial-mode gates brakeman; oss-mode allows; partial-scan on tool failure; vault records `scan_meta`/`raw_output`/`finding` | ✅ |
| **Real Opengrep scan** | `-tags integration` test: real binary finds `eval()`, asserts high severity + CWE-95 + line | ✅ |

Acceptance: hermetic suite green; integration suite green where opengrep present. ✅
Deferred to Phase 1.1 (not blocking): cross-tool **correlator/dedup** (+ its tests).

---

## Phase 2 — LLM triage + judge  ✅ done (remediation → 2.1)

| What | How it's verified | Status |
|------|-------------------|--------|
| Enricher (code context) | `internal/enrich` tests: reads N lines around span, marks flagged line, falls back to tool snippet when file unreadable | ✅ |
| OpenAI-compatible client | `internal/triage/llm` httptest: sends model+messages+Bearer auth + `json_object` response_format; per-request model overrides default; HTTP-error path | ✅ |
| Model routing | `Router` test: triage vs judge resolve to different clients; both called exactly once | ✅ |
| Triage structured output | fake LLM returns fixed JSON → Verdict fields parsed + attached; prose-wrapped JSON tolerated (parse-and-retry fallback) | ✅ |
| Adversarial judge | fake scripted to "refute" → verdict marked refuted and **not** high-confidence; unrefuted TP@0.9 is high-confidence | ✅ |
| Provenance | `llm_call` (triage+judge) + `verdict` records written to vault (asserted) | ✅ |
| Live end-to-end | manual: real Opengrep scan + triage/judge against a mock OpenAI endpoint → verdict in report + 6 vault records | ✅ |

Acceptance: hermetic (fake LLM + httptest) suite green — no API key or network needed. ✅

## Phase 2.1 — Remediation + git-blame + JSON-schema  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| Remediation phase | `internal/triage` test: high-confidence finding gets remediation attached; low-confidence/refuted finding gets none and makes no LLM call; never auto-applied | ✅ |
| git-blame enrichment | `internal/enrich` tests over a real temp git repo: author/commit/date parsed; ok=false outside a repo; Context appends attribution when enabled | ✅ |
| JSON-schema output | `internal/triage/llm` httptest: `response_format: json_schema` (name + strict) is sent when a Schema is set | ✅ |
| Schema→JSON fallback | `internal/triage` test: schema call errors → retries once with plain JSON mode, drops schema, still parses verdict | ✅ |

Acceptance: hermetic suite green (fake LLM + httptest + real local git). ✅
Remaining for later: optional `-tags llm` smoke test against a live endpoint.

---

## Phase 3 — Learning loop  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| Feedback capture | `internal/knowledge` test: TP/FP written to the vault, retrievable by fingerprint; `All()` corpus | ✅ |
| Per-rule calibration | tests: chronically-FP rule auto-resolves; too-few-samples does not; mostly-TP rule does not; FP-rate math | ✅ |
| RAG retrieval (chromem-go) | test with a deterministic fake embedder: seeded corpus returns the most-similar labeled finding; empty corpus returns nil | ✅ |
| Engine integration | tests: calibration short-circuits the LLM entirely; RAG examples are injected into the triage prompt | ✅ |
| Live learning loop | manual E2E: scan→triage=TP → 3 FP feedback → re-scan auto-resolves as FP with **no LLM call** | ✅ |

Acceptance: hermetic suite green (fake embedder, no embeddings endpoint needed). ✅
Later: precision/recall dashboards over a labeled fixture set; dedicated Reflect-phase agent.

---

## Phase 4 — Research agents & rule synthesis  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| Inventory (Recon) | `internal/inventory` tests: languages by extension; deps from go.mod/requirements.txt/package.json with ecosystem; vendor dirs skipped | ✅ |
| Grounding / anti-hallucination | `internal/research` test: agent discards any issue with an empty citation | ✅ |
| Synthesis + provenance | test: synthesizer builds a rule with fixtures + provenance (citation, prompt version, date) | ✅ |
| **Validation gate** (the load-bearing one) | hermetic `Admit` table (parse × vuln-match × patched-match) **+ integration test with real Opengrep**: good rule admitted; overbroad rule (matches the fix) rejected | ✅ |
| Repo admit/quarantine | test: admitted → admitted/ dir + provenance sidecar + vault record; failures → quarantine/, never run | ✅ |
| Engine orchestration | tests: passing rule admitted, failing rule quarantined, targets deduped by key, budget cap honored | ✅ |
| Live E2E | manual: flask dep → cited issue → synth → **real Opengrep gate** → admitted rule with provenance in the repo | ✅ |

Acceptance: no rule enters the corpus without passing the gate; a deliberately-overbroad rule is quarantined. ✅
Follow-ups: OSV.dev grounding; rule perf tracking via §8. (Feeding admitted rules into scans is done — DESIGN.md §9.4.)

---

## Phase 5 — CI & delivery  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| Baseline suppression | `internal/baseline` tests: filter partitions new vs known; write→load round-trip (dedup, drop empty); missing file = empty | ✅ |
| Diff-aware scan | `internal/vcs` tests: FilterFindings (relative + abs-suffix); ChangedFiles over a real temp git repo (modified + untracked reported, unchanged not) | ✅ |
| SARIF export | `internal/report` test: output re-parses as SARIF 2.1.0; level mapping; location preserved | ✅ |
| JUnit export | test: output re-parses as JUnit XML; failing cases counted | ✅ |
| Markdown / GitHub annotations | tests: table + pipe-escaping; `::error`/`::warning` lines by severity | ✅ |
| Baseline-aware gate | live E2E: no baseline → `--fail-on high` exit 1; with baseline → "1 suppressed" exit 0 | ✅ |
| Delivery | GitHub Action (action.yml), repo CI workflow, example scan workflow, `make release` | ✅ |

Acceptance: hermetic suite green; CI fails only on newly-introduced findings. ✅
Copyleft-import guard: `license-check.yml` fails the build on any AGPL/GPL/LGPL Go dependency.

---

## Phase 6 — War Room UI + per-project isolation  ✅ done

| What | How it's verified | Status |
|------|-------------------|--------|
| Local-only exposure (no authentication by design) | loopback-only default and `--allow-remote` opt-in for other addresses; Host header must be localhost/127.0.0.1/::1 or in `--allowed-hosts`; cross-origin POST rejected. Covered by `deploy/compose/smoke.sh` (run in CI by `quickstart.yml`) — see [docs/containers.md](docs/containers.md#security-model-no-authentication) | ✅ |
| Project isolation | httptest: acme sees only acme's run, globex only globex's; never each other's | ✅ |
| Redaction | `Redact` unit tests (AWS key, secret assignment, long token) + httptest: secret never appears in the rendered run page | ✅ |
| Dashboard / run handlers | httptest: dashboard lists runs; run page renders findings + severity + verdict | ✅ |
| Feedback → vault | httptest: analyst POST records a feedback entry to the project vault (History len 1) | ✅ |
| Audit export | httptest: the run's audit endpoint returns the JSON records | ✅ |
| SSE | httptest: `text/event-stream` content-type; `event: run` + `event: done` in the body | ✅ |
| Live end-to-end | curl demo: seed acme via scan → dashboard, run detail, isolation, feedback (UI → vault), audit JSON, SSE | ✅ |

Acceptance: hermetic httptest suite green — no network, no browser. ✅
Still open: live per-scan SSE progress. (Authentication is intentionally not built; the War Room is a local, single-user tool.)

---

## Triage eval harness (2026-07-30)

Unit tests verify the harness; the harness verifies the triage layer. Both matter,
and they are different things.

| Area | What the tests prove | Status |
|------|----------------------|--------|
| Corpus validation | rejects bad label, missing `why`, finding/evidence line past EOF, duplicate id, missing fixture, missing tool, empty corpus; lists every problem at once; refuses a fixture path escaping the corpus dir | ✅ |
| Case → Finding | tool/rule/CWE/location mapped, severity normalized, unknown severity → `unknown`, stable `eval:<id>` fingerprint | ✅ |
| Context scoring | evidence visibility counted from the RENDERED prompt (not re-derived from the same arithmetic), missing lines reported, deterministic across runs, line-number parsing ignores the truncation notice | ✅ |
| Verdict scoring | perfect triage → 1.0; confirm-everything → balanced accuracy 0.5 with recall 1.0 / suppression 0.0; judge refusal and sub-0.7 confidence both score as suppression; errors count as wrong and never as correct; disagreeing repeats flagged unstable; calibration gap ≈ 0.45 for a confident-and-wrong model | ✅ |
| Reports & diffs | wrong answers print their ground truth; `CompareContext`/`CompareVerdict` flag REGRESSED cases; the repeat<2 noise caveat is printed | ✅ |
| CLI end-to-end | context mode over the real corpus; verdict mode against a request-counting mock endpoint (28 calls = 14 cases × triage+judge) | ✅ |
| CI gate | `make eval-gate` passes against the committed baseline and **fails (exit 2)** when context is taken away — proven by re-running with `--max-scope-lines -1` | ✅ |

Acceptance: `make eval-context` is hermetic (no model, key, or network) and gates
in CI. Verdict mode needs `ACHILLES_LLM_API_KEY` and real spend, so it is run
deliberately, not on every push. ✅

**Not yet done:** no verdict-mode run against a real model has been recorded, so
there is no committed accuracy number for any model — only the harness that
produces one.

---

## Roadmap complete

Phases 0–6 are built and tested. The hermetic suite (`go test ./...`) runs with
no network, tools, or API keys; integration tests (`-tags integration`) add
real-Opengrep and real-git coverage and self-skip when those are absent.
