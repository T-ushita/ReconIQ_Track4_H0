# Architecture

## Overview

ReconIQ is a single-process, multi-agent pipeline. One scan = one
`ScanContext` (in-memory, per-run shared state) + one `ScanSession`
(persisted, per-run record). Agents are pure functions: `(inputs, context)
-> (validated_output, router_result)`. The pipeline orchestrator
(`pipeline.run_pipeline`) sequences agents, persists intermediate state
after every stage, and emits progress events the UI subscribes to.

```
URL
 │
 ▼
[domain validation] ──reject──▶ private/internal targets blocked
 │
 ▼
[rate limit + concurrency guard] ──reject──▶ cooldown / quota / "scan in progress"
 │
 ▼
┌────────────────────────────────────────────────────────────────────┐
│ ScanSession created (status=QUEUED → RUNNING)                      │
│ ScanContext created (shared memory for this run)                   │
│                                                                    │
│  1. Crawler            → links, forms, scripts, cookies            │
│  2. Form Fuzzer         → XSS/SQLi probes (consent-gated)          │
│  3. Auth Crawler (opt)  → protected pages, admin panels, IDOR      │
│  4. Recon Agent          → attack-surface profile  ──┐             │
│  5. Vuln Detection Agent → raw findings ◀───────────┘ (sanitized   
│         │                                              via prompt  │
│         ▼                                              guard)      │
│  6. Verifier Agent       → independent re-review per finding       │
│         │                                                          │
│         ▼                                                          │
│  [confidence.py]  detector_confidence ⊕ verifier_score            │
│                    → consensus confidence (single source of truth) │
│         │                                                          │
│         ▼                                                          │
│  7. Triage Agent         → semantic dedup, ranking, exploit chains │
│         │                                                          │
│         ▼                                                          │
│  8. Report Agent          → prioritized remediation action plan    │
│                                                                    │
│ ScanSession updated after every stage (status=COMPLETED/FAILED)    │
└────────────────────────────────────────────────────────────────────┘
```

## Components

### `pipeline.py` - Orchestrator
- `is_private_target()` - blocks RFC1918 ranges, loopback, link-local, and
  internal TLDs before any agent runs.
- `_check_rate_limit()` - enforces a cooldown (`_MIN_SCAN_INTERVAL`) and a
  per-session hourly quota (`_MAX_SCANS_PER_SESSION`), protected by
  `_rate_lock`.
- `_scan_semaphore` - a `threading.Semaphore(1)` enforces a single
  in-flight scan across the whole process (acquired/released around the
  entire pipeline run in `run_pipeline`).
- `_compute_agreement_score()` - a cross-agent sanity check independent of
  per-finding confidence: penalizes contradictions between what recon,
  detection, and triage report (e.g. triage escalating more "critical"
  findings than detection produced raw).
- `run_pipeline()` - sequences all 8 stages, persists `ScanSession` after
  each stage, and calls `progress_callback(stage, message, data)` for live
  UI updates.

### `scan_context.py` - `ScanContext`
In-memory dataclass passed by reference to every agent during one run.
Holds per-stage summaries (`crawl_summary`, `fuzz_summary`,
`auth_summary`, `recon_profile`, ...), free-form `annotations` agents can
leave for each other, `injection_detections`, and `confidence_scores`.
`get_cross_reference_hints()` synthesizes these into a text block fed to
the detection and triage prompts - this is what lets, e.g., the triage
agent reason about "login form found in recon + SQLi found by fuzzer ⇒
auth bypass chain" rather than just seeing isolated JSON blobs.

### `scan_session.py` - `ScanSession` (persistence)
SQLite-backed (`scan_sessions.db`). One row per scan, written
incrementally as each stage completes (so a UI refresh or API poll mid-scan
sees partial results). `SessionStatus` is `QUEUED | RUNNING | COMPLETED |
FAILED`. `get_history_summaries()` is the single read path used by the
dashboard, reports page, and diff/trend view - there is intentionally no
separate `scan_history.json`.

### `model_router.py` - Intelligence design
`TaskType` enum (`CLASSIFICATION`, `EXTRACTION`, `DETECTION`, `SYNTHESIS`)
maps to a `ROUTING` table of `{primary model, fallback model, temperature,
max_tokens}`. `route_llm_call()`:
1. Calls the primary model.
2. Estimates confidence heuristically (`_estimate_confidence`: output
   length, hallucination-marker presence, JSON validity for
   structured-output task types).
3. If confidence is below `min_confidence`, escalates to the fallback
   model and returns that result with `escalated=True` and a recorded
   `escalation_reason`.

This heuristic confidence is the *router's* escalation signal (cheap,
synchronous, used to decide "should I re-run on a bigger model right now").
It is distinct from - and feeds into - the consensus confidence below.

### `agents/verifier_agent.py` + `confidence.py` - Verification layer
After detection, `verify_vulnerabilities()` sends each finding to a second,
independent prompt (`TaskType.DETECTION`, which escalates to `qwen-qwq-32b`
on low confidence - a different reasoning model than the primary detector
typically lands on). The verifier returns `verified: bool` and a
`verification_score` per finding id, with reasoning.

`calculate_consensus_confidence(detector_confidence, verifier_score,
verified)`:
- If **not verified**: `min(detector_confidence, verifier_score) * 0.25` -
  heavily penalized.
- If **verified**: `detector_confidence * 0.4 + verifier_score * 0.6` - the
  verifier (independent second pass) is weighted higher.

This consensus value overwrites `vuln["confidence"]` and becomes the only
confidence figure triage and the report agent see - the original detector
self-confidence and verifier score are preserved alongside it
(`detector_confidence`, `verifier_score`) for transparency/audit, along
with a `verification_disagreement` flag when the two scores differ by
>0.4.

### `prompt_guard.py` - Injection defense
`sanitize()` / `sanitize_dict()` run a battery of regex patterns over every
piece of web-sourced content (HTML snippets, recon output, crawl data)
*before* it is interpolated into any LLM prompt. Categories covered:
instruction overrides ("ignore previous instructions"), role-play triggers
("you are now a...", `<|im_start|>`), security-specific evasion ("no
vulnerabilities found", "this site is fully patched"), and delimiter
injection (fake `system:` blocks). Matches are replaced with
`[PROMPT_INJECTION_BLOCKED]` and recorded as detections.

Detections are **not** written to a standalone log file. They are
accumulated on `ScanContext.injection_detections`, persisted onto
`ScanSession.injection_attempts` at the end of the run, and aggregated
across sessions by `prompt_guard.get_injection_log()` for the Agent
Security Audit page - `ScanSession` remains the single source of truth.

### `output_validator.py` - Trust layer for agent JSON
`safe_json_parse()` handles three failure modes of LLM JSON output:
direct parse, markdown-code-block-wrapped JSON, and "JSON object embedded
in prose." `validate_recon/validate_vuln_detection/validate_triage()` then
check required top-level fields against a schema and fill in safe defaults
for everything optional - so a partially-malformed or hallucinated agent
response degrades gracefully instead of raising deep into the pipeline.

### `agents/triage_agent.py` - Dedup, ranking, exploit chains
Two-stage deduplication: `_semantic_dedup()` first removes
near-duplicate findings using cosine similarity over
`sentence-transformers` embeddings of `title + location + type` (keeping
the higher-CVSS member of any near-duplicate pair), *then* the LLM triage
pass removes exact duplicates/false-positives, re-ranks by
`(verified, confidence, verifier_score)`, and identifies multi-finding
exploit chains using the cross-reference hints from `ScanContext`.

### `monitored_sites.py` - Continuous monitoring
Background daemon thread (`start_scheduler`) wakes every 5 minutes, checks
`monitored_sites.json` for sites whose `next_scan` time has passed, runs
`run_pipeline()` for each, computes a diff against the previous scan
(`get_diff()`: new / resolved / unchanged vulnerabilities + trend
direction), and posts a webhook notification
(`_send_notification`). `monitored_sites.json` intentionally remains
file-based - it is configuration (which sites, what schedule, what
webhook), not scan result data.

### `crawler_state.py` - Auto Crawler queue
File-based (`crawler_state.json`) by design - holds the *in-progress*
BFS queue/visited-set for a multi-site crawl session, which is
ephemeral working state, not historical results. Completed scan results
from the auto-crawler flow through the same `ScanSession` path as single
scans.

### `api/routes/` - Optional HTTP interface
A thin FastAPI layer over the same `pipeline.py` / `scan_session.py` used
by the Streamlit UI. `POST /api/v1/scans` creates a `ScanSession`
(status=QUEUED) synchronously and returns its `session_id` immediately,
then runs the pipeline as a background task against that session id.
Clients poll `GET /api/v1/scans/{session_id}` for status and
`GET /api/v1/scans/{session_id}/results` once completed. See
`api/routes/scans.py` docstring for the full contract.

## Concurrency & threading model

- **Pipeline execution**: synchronous, single-threaded per scan; only one
  scan runs at a time process-wide (`_scan_semaphore`).
- **Rate-limit state** (`_last_scan_time`, `_session_scan_times`): mutated
  under `_rate_lock`, separate from the execution semaphore - this avoids
  the earlier deadlock where the rate-limit check tried to inspect a lock
  it was currently holding.
- **Monitoring scheduler**: a single daemon thread polling every 5 minutes,
  calling the same `run_pipeline()` (so it is also subject to the
  semaphore/rate limit).
- **Streamlit**: each user session runs in its own script-rerun thread;
  shared mutable state (`_session_scan_times`, the semaphore) is
  module-level and shared across all Streamlit sessions in the same
  process by design (single-tenant prototype).

## Data flow summary (what persists where)

| Data                                   | Storage                          | Notes |
|----------------------------------------|-----------------------------------|-------|
| Scan results, status, confidence scores, injection log, report | `scan_sessions.db` (SQLite, via `scan_session.py`) | single source of truth |
| Monitored site config (URL, schedule, webhook, last/next scan) | `monitored_sites.json` | intentional config-layer file |
| Auto-crawler in-progress queue/visited set | `crawler_state.json` | intentional ephemeral working state |

## Where this goes next

See [`future-implementation-scope/README.md`](future-implementation-scope/README.md)
for the planned Postgres/pgvector/S3 persistence layer, async/distributed
worker model, RBAC/audit logging, and pricing-tier API platform - and for
why the current architecture (clean separation of agents, pipeline,
session model, and UI) was chosen to make that migration additive rather
than a rewrite.
