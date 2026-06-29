from fastapi import APIRouter
from services.scan_session import list_sessions, clear_all_sessions, get_history_summaries

router = APIRouter(
    prefix="/api/v1/sessions",
    tags=["Sessions"]
)

@router.get("")
async def sessions():

    data = []

    for session in list_sessions():

        data.append(
            {
                "session_id": session.session_id,
                "target_url": session.target_url,
                "status": session.status
            }
        )

    return data

@router.get("/history")
async def history():
    """Dashboard-ready summaries for completed scans."""
    return get_history_summaries()

@router.delete("")
async def delete_all_sessions():
    clear_all_sessions()
    return {"deleted": True}