# Future Implementation Scope

This folder contains code, schemas, and deployment configuration for
ReconIQ's **planned production architecture**. Nothing here is imported by
the live application in `python-app/` - it exists to demonstrate the
upgrade path from the current lightweight prototype to a production-scale
deployment, without requiring that path to be built (or its infrastructure
running) for this submission.

## Rationale

The current implementation (`python-app/`) deliberately uses a lightweight,
zero-external-dependency persistence layer (SQLite via `scan_session.py`,
JSON config files for monitoring/crawler state) to prioritize portability,
rapid setup, and ease of evaluation - anyone can clone the repo, `pip
install`, and run a full multi-agent scan with no database, object storage,
or container orchestration to provision.

The architecture already separates **scan execution** (`pipeline.py`,
`agents/`), **session management** (`scan_session.py`), **reporting**
(`agents/report_agent.py`, `ui/reports.py`), and **agent orchestration**
(`scan_context.py`, `model_router.py`) into independent concerns. Each item
below upgrades one of these layers without requiring changes to the others
- i.e., this is additive infrastructure work, not a rewrite.

## Contents

### `storage/` - Persistence layer upgrade
- **`postgres.py`** - SQLAlchemy engine pointed at `DATABASE_URL`. Would
  replace `scan_session.py`'s SQLite connection; the `ScanSession`
  dataclass and its `to_db_row()`/`from_db_row()` methods are designed to
  map directly onto a Postgres table (see `db/schema.sql`).
- **`vector_store.py`** - `sentence-transformers` embedding helper for
  **pgvector**. Triage already computes embeddings for semantic
  deduplication within a single scan (`agents/triage_agent.py`); persisting
  those embeddings would enable cross-scan vulnerability correlation
  ("have we seen this finding on a different target before?") and
  intelligent historical deduplication.
- **`s3_store.py`** - uploads generated reports (and, eventually, crawl
  artifacts/screenshots) to S3-compatible storage. Would replace storing
  `report_md` inline on `ScanSession` with a reference/key.

### `db/`
- **`schema.sql`** - target Postgres schema for `scan_sessions`.
- **`db.py`** - a SQLite mirror of that schema, written while prototyping
  the Postgres migration. **Not used by the live app** - `scan_session.py`
  is the live, feature-complete session store. This file exists purely to
  validate the planned column layout (including the `injection_attempts`,
  `confidence_scores`, and `cross_references` columns already present in
  `scan_session.py`) before porting it to Postgres.

### `deployment/`
- **`DockerFile`**, **`docker-compose.yml`** - containerizes the app
  alongside Postgres (`pgvector/pgvector:pg16` image) and `localstack` (S3
  emulation), wired via `DATABASE_URL` / `S3_BUCKET` / `AWS_ENDPOINT_URL`
  environment variables that `storage/postgres.py` and `storage/s3_store.py`
  already expect.

### `requirements-future.txt`
Additional Python dependencies (`sqlalchemy`, `psycopg2-binary`,
`pgvector`, `boto3`, `alembic`) needed only once the above is wired up.
Kept separate from `python-app/requirements.txt` so the live prototype has
no AWS/Postgres SDK dependencies to install.

## Roadmap beyond persistence

**Scalability**
- Replace the single `_scan_semaphore` with a Celery/RQ/Dramatiq
  queue-backed worker model - the agent interfaces in `pipeline.py` would
  not need to change, only how `run_pipeline()` is invoked (worker process
  vs. in-process call).
- Multiple scan workers / horizontal scan processing, with `ScanSession`
  (Postgres-backed) as the shared coordination point.
- Async agent execution (`asyncio`) for the I/O-bound crawl/fuzz/auth
  stages.
- Job scheduling, retries, failure recovery, and scan
  cancellation/pause/resume.

**Security & governance**
- Role-based access control (RBAC) and team workspaces.
- Audit logging for all scan activity (who scanned what, when, with what
  authorization).
- Scan approval/authorization workflows (extending the current per-scan
  "authorize active fuzzing" checkbox to org-level policy).
- Secrets management and credential rotation for stored auth
  cookies/headers used in authenticated crawls.

**Product / API platform**
- Webhooks (already partially implemented for Monitored Sites -
  generalize to all scan-lifecycle events).
- Public API platform with the tiers below.

### Planned pricing tiers

| Tier       | Price   | Limits            |
|------------|---------|-------------------|
| Community  | Free    | 10 scans/day      |
| Pro        | $49/mo  | 500 scans/month   |
| Team       | $199/mo | Shared workspaces |
| Enterprise | Custom  | SSO, RBAC, API    |

## Migration order (suggested)

1. Stand up Postgres via `deployment/docker-compose.yml`; point
   `storage/postgres.py` at it via `DATABASE_URL`.
2. Port `scan_session.py`'s SQLite queries to SQLAlchemy against
   `db/schema.sql` (column layout already matches).
3. Swap `crawler_state.json` / `monitored_sites.json` file I/O for
   Postgres tables once the above is stable (these were intentionally kept
   simple in the prototype - see `python-app/README.md`).
4. Add `pgvector` columns + `storage/vector_store.py` for cross-scan
   correlation once single-scan semantic dedup (already live in
   `agents/triage_agent.py`) is validated.
5. Introduce the Celery/RQ worker model, replacing the in-process
   semaphore with a queue.
6. Layer RBAC/audit logging/API tiers on top once multi-tenant storage
   exists.
