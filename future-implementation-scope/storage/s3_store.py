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
    Uploads the report text to S3 and returns the S3 key.

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