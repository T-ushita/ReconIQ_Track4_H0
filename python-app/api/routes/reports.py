from fastapi import APIRouter
from scan_session import get_session

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"]
)


@router.get("{session_id}")
async def get_report(session_id: str):

    session = get_session(session_id)

     if not session:
        raise HTTPException(status_code=404, detail="Session not found")
 
    try:
        text_content = get_report_text(session_id)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=text_content, media_type="text/markdown")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch report: {e}")
