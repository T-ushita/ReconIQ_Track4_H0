# ReconIQ - Autonomous Web Agent Security Framework

ReconIQ is a multi-agent autonomous security scanner built for the
**Security in the Agentic Future** theme: it scans a target web application
using a pipeline of cooperating LLM agents, while itself implementing the
defenses an agentic security tool needs against prompt injection,
unauthorized/uncontrolled action, and untrustworthy AI output.

This README describes what is **implemented and runnable today**. For
planned/roadmap components (Postgres, S3, pgvector, distributed workers,
RBAC, etc.), see [`future-implementation-scope/README.md`](future-implementation-scope/README.md).
For a deeper architectural walkthrough, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## What it does

Given a target URL, ReconIQ runs a 7-agent pipeline:

1. **Crawler** - discovers links, forms, scripts, cookies, tech stack.
2. **Form Fuzzer** - tests discovered forms for XSS/SQLi, gated behind an
   explicit user-granted authorization flag.
3. **Authenticated Crawler** *(optional)* - crawls with supplied
   credentials/cookies to discover protected pages, admin panels, and IDOR
   hints.
4. **Recon Agent** - extracts a structured attack-surface profile (tech
   stack, input vectors, auth mechanisms, exposed data).
5. **Vulnerability Detection Agent** - identifies concrete vulnerabilities
   with evidence, severity, and CVSS scoring.
6. **Verifier Agent** - independently re-reviews each finding from
   detection, using a different prompt (and, on escalation, a different
   model) to produce a verification score.
7. **Triage Agent** - deduplicates (including semantic deduplication via
   sentence embeddings), filters false positives, ranks by
   exploitability/impact/confidence, and identifies multi-step exploit
   chains.
8. **Report Agent** - generates a prioritized "Fix this week / this month /
   this quarter" remediation action plan (not just a bug list).

Results are stored as a `ScanSession` (SQLite-backed), viewable in the
Streamlit dashboard, comparable across scans (diff view + risk trend
sparklines), and optionally re-run on a schedule via **Monitored Sites**
with webhook notifications.

## Security-by-design features (Theme alignment)

- **Prompt injection guard** (`prompt_guard.py`): every piece of
  web-sourced content is sanitized before reaching any LLM. Detected
  injection attempts (e.g. "ignore previous instructions", role-play
  triggers, fake system delimiters) are stripped, logged per-session, and
  surfaced in the live agent log and the Agent Security Audit page.
- **Consent-gated active testing**: the form fuzzer only sends
  XSS/SQLi payloads if the user explicitly checks "Authorize active form
  fuzzing" in the UI. Every submission attempt is logged regardless.
- **Domain/target validation**: private IP ranges (RFC1918), loopback,
  link-local, and internal TLDs (`.local`, `.internal`, `.test`, `.corp`)
  are rejected before any agent runs (`pipeline.is_private_target`).
- **Rate limiting & single-flight queue**: a semaphore enforces one
  concurrent scan; a cooldown and per-session hourly quota prevent abuse
  (`pipeline._check_rate_limit`).
- **Output validation** (`output_validator.py`): every agent's JSON output
  is schema-checked and coerced to safe defaults before being passed
  downstream - a malformed or hallucinated field can no longer crash the
  pipeline.
- **Verifier + Consensus Confidence** (`confidence.py`,
  `agents/verifier_agent.py`): instead of trusting the detection agent's
  self-reported confidence, an independent verifier agent re-reviews each
  finding. The two scores are combined into a single consensus confidence
  that downstream triage and the report use as the source of truth.

## Intelligence design: model routing

`model_router.py` routes each pipeline stage to the model best suited for
its task, with confidence-based escalation to a stronger fallback model:

| Task type      | Used by                  | Primary model              | Fallback (on low confidence) |
|-----------------|--------------------------|------------------------------|--------------------------------|
| Classification  | Triage                    | `llama-3.1-8b-instant`       | `llama-3.3-70b-versatile`      |
| Extraction       | Recon                     | `llama-3.3-70b-versatile`    | `llama-3.1-8b-instant`         |
| Detection        | Vuln Detection, Verifier  | `llama-3.3-70b-versatile`    | `qwen-qwq-32b` (reasoning)     |
| Synthesis        | Report generation         | `llama-3.3-70b-versatile`    | `qwen-qwq-32b`                  |

Triage additionally uses a `sentence-transformers` embedding model
(`all-MiniLM-L6-v2`) for semantic deduplication - a non-LLM specialist
model used for a non-generative task.

## Running the app

```bash
cd python-app
pip install -r requirements.txt
# create a .env with GROQ_API_KEY and TINYFISH_API_KEY
streamlit run app.py
```

The Streamlit UI provides six pages: Dashboard, Single Scan, Auto Crawler,
Reports, Monitor (scheduled scans), and Agent Audit (prompt-injection /
confidence / verification log).

### Optional: HTTP API

`app.py` also defines a FastAPI `app` object with `/api/v1/scans`,
`/api/v1/sessions`, `/api/v1/reports`, and `/health` routes. To serve it:

```bash
uvicorn app:app --port 8000
```

This shares the same `pipeline.py` and `scan_session.py` as the Streamlit
UI - scans created via either interface appear in the same session store.
See `api/routes/scans.py` for the async create-then-poll contract.

## Directory structure

```
python-app/
├── app.py              # Streamlit entry point + FastAPI app object
├── pipeline.py         # 7+1 agent orchestrator, rate limiting, domain guard
├── model_router.py     # per-task model selection + confidence escalation
├── confidence.py       # consensus confidence (detector + verifier)
├── prompt_guard.py      # injection detection/sanitization
├── output_validator.py # JSON schema validation for agent outputs
├── scan_context.py     # shared cross-agent memory for one scan
├── scan_session.py     # SQLite-backed ScanSession model (source of truth)
├── crawler_state.py    # Auto Crawler queue/visited-set (file-based, intentional)
├── monitored_sites.py  # scheduled recurring scans + webhook notifications
├── agents/             # one module per pipeline agent
├── ui/                  # Streamlit pages
└── api/routes/          # optional FastAPI HTTP interface
```

## Known intentional design choices

- `monitored_sites.json` and `crawler_state.json` remain file-based by
  design - they hold *configuration* and *in-progress crawl queue state*
  respectively, not historical scan results. All scan results/history live
  in `scan_session.py`'s SQLite store, which is the single source of truth
  for the dashboard, reports, and diff/trend views.
- Email notifications are deferred to v2; `monitored_sites.py` ships
  webhook-only notifications (the repo link is used as the webhook target
  for this submission).
- The pipeline is intentionally single-threaded/synchronous per scan
  (enforced via a semaphore) for deterministic agent coordination during
  the prototype phase. See `future-implementation-scope/README.md` for the
  async/distributed roadmap.