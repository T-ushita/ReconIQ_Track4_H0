"""
Scan endpoints.

ASYNC / POLLING PATTERN (by design, not a bug):
POST /api/v1/scans does not run the scan inline or return results directly.
It creates a ScanSession (status=QUEUED), schedules the pipeline as a
FastAPI BackgroundTask, and immediately returns that session_id. The
pipeline (run_pipeline) updates the same session's status/results as it
progresses (QUEUED -> RUNNING -> COMPLETED/FAILED).

Clients are expected to poll:
  1. POST /api/v1/scans                  -> { session_id, status: "queued" }
  2. GET  /api/v1/scans/{session_id}     -> { status: "running" | "completed" | ... }
  3. GET  /api/v1/scans/{session_id}/results  -> once status == "completed"

This mirrors the long-running-job pattern used by the Streamlit UI, which
polls the same ScanSession table via progress callbacks.
"""

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from pipeline import run_pipeline
from services.scan_session import get_session, create_session

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class ScanRequest(BaseModel):
    url: str
    enable_form_fuzzing: bool = True
    enable_auth_crawl: bool = False
    fuzzing_authorized: bool = False


@router.post("")
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    # Create the session synchronously so the caller has a session_id to
    # poll immediately. run_pipeline will pick this session up via
    # session_id and update its status as the scan progresses.
    session = create_session(
        target_url=request.url,
        fuzzing_authorized=request.fuzzing_authorized,
    )

    def run():
        run_pipeline(
            url=request.url,
            enable_form_fuzzing=request.enable_form_fuzzing,
            enable_auth_crawl=request.enable_auth_crawl,
            fuzzing_authorized=request.fuzzing_authorized,
            session_id=session.session_id,
        )

    background_tasks.add_task(run)

    return {
        "status": "queued",
        "session_id": session.session_id,
        "target": request.url,
        "poll": f"/api/v1/scans/{session.session_id}",
    }


@router.get("/{session_id}")
async def get_scan_status(session_id: str):

    session = get_session(session_id)

    if not session:
        return {
            "error": "session not found"
        }

    return {
        "session_id": session.session_id,
        "status": session.status,
        "started_at": session.started_at,
        "error_message": session.error_messages
    }


@router.get("/{session_id}/results")
async def get_scan_results(session_id: str):

    session = get_session(session_id)

    if not session:
        return {
            "error": "session not found"
        }

    return {
        "crawl": session.crawl_result,
        "fuzz": session.fuzz_result,
        "auth": session.auth_result,
        "recon": session.recon_result,
        "vulnerabilities": session.vuln_result,
        "triage": session.triage_result,
        "report": session.report_md
    }

@router.get("/{session_id}/agents")
async def get_agent_info(session_id: str):

    session = get_session(session_id)

    if not session:
        return {
            "error": "session not found"
        }

    return {
        "confidence_scores": session.confidence_scores,
        "cross_references": session.cross_references,
        "injection_attempts": session.injection_attempts
    }