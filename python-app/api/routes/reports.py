from fastapi import APIRouter
from scan_session import get_session
from storage.s3_store import upload_report, get_report_text

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
        text_content = get_report_t fext(session_id)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=text_content, media_type="text/markdown")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch report: {e}")



@router.get("{session_id}/download")
async def download_report(session_id: str):
    """
    Returns a redirect to a presigned S3 URL for the report markdown.
    The Next.js frontend hits this endpoint when the user clicks Download.
    """
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
 
    s3_key = session.report_md
    if not s3_key or not s3_key.startswith("reports/"):
        # Fallback: report was stored inline (e.g. S3 upload failed at scan time)
        raise HTTPException(
            status_code=404,
            detail="Report not found in S3. Re-run the scan to generate a fresh report."
        )
 
    try:
        presigned_url = get_report_presigned_url(session_id)
        return RedirectResponse(url=presigned_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate download URL: {e}")
 