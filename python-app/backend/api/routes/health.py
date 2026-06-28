from fastapi import APIRouter
from scan_session import list_sessions

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health():

    return {
        "status": "healthy"
    }

@router.get("/metrics")
async def metrics():

    sessions = list_sessions()

    completed = sum(
        1 for s in sessions
        if str(s.status) == "completed"
    )

    failed = sum(
        1 for s in sessions
        if str(s.status) == "failed"
    )

    running = sum(
        1 for s in sessions
        if str(s.status) == "running"
    )

    return {
        "total_scans": len(sessions),
        "completed_scans": completed,
        "failed_scans": failed,
        "running_scans": running
    }