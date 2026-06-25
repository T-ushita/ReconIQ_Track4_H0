from fastapi import APIRouter

from scan_session import list_sessions

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