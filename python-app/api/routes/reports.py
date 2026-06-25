from fastapi import APIRouter

from scan_session import get_session

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"]
)


@router.get("/{session_id}")
async def get_report(session_id: str):

    session = get_session(session_id)

    if not session:
        return {
            "error": "session not found"
        }

    return {
        "session_id": session_id,
        "report": session.report_md
    }