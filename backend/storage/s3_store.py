import os
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION"),
    endpoint_url=os.getenv("AWS_ENDPOINT_URL")
)

BUCKET = os.getenv("S3_BUCKET")
preset_expiry_seconds = 3600

def report_key(session_id: str) -> str:
    return f"reports/{session_id}.md"
 

def upload_report(session_id: str, report_text: str) -> str:
    """
    Uploads the markdown to S3 and returns the S3 key.

    Called in pipeline.py immediately after generate_report() succeeds:
        from storage.s3_store import upload_report
        s3_key = upload_report(session.session_id, report_md)
        session.report_md = s3_key   # store key, not content
        save_session(session)
    """
    key = report_key(session_id)
    try:
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=report_text.encode("utf-8"),
            ContentType="text/markdown; charset=utf-8",
        )        
        logger.info(f"Report uploaded to S3 with key: {key}")
        return key
    except ClientError as e:
        logger.error(f"Failed to upload report to S3: {e}")
        raise

def get_report_preassigned_url(session_id: str) -> str:
    """ 
    generate a time-limited pre-signed GET URL for the report markdown in S3.
    Used by the FastAPI endpoint:
    GET /api/reports/{session_id}/download
    The Next.js frontend redirects the user to this URL for download.
 
    URL expires after PRESIGNED_EXPIRY_SECONDS (default 1 hour).
    """

    key = report_key(session_id)
    try:
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": BUCKET, "Key": key},
            ExpiresIn=preset_expiry_seconds,
        )
        logger.info(f"Generated pre-signed URL for report: {url}")
        return url
    except ClientError as e:
        logger.error(f"Failed to generate pre-signed URL: {e}")
        raise

def get_report_text(session_id: str)-> str:
    """
    Download and return the report markdown as a string.
    Used server-side (e.g. PDF generation Lambda, admin export).
    """
    key = report_key(session_id)
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        return obj["Body"].read().decode("utf-8")
    except ClientError as e:
        logger.error(f"Failed to download report from S3: {e}")
        raise


def delete_report(session_id: str) -> bool:
    """
    Delete the report markdown from S3.
    Called in pipeline.py after the session is deleted from the database.
    Returns True if deletion was successful, False otherwise.
    """
    key = report_key(session_id)
    try:
        s3.delete_object(Bucket=BUCKET, Key=key)
        logger.info(f"Report deleted from S3 with key: {key}")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return False
        logger.error(f"[S3] delete_report failed for {session_id}: {e}")
        raise