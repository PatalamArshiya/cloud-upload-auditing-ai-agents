import os
import uuid
import hmac
import hashlib
import time
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, HTTPException, Header, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from testbed_app.config import (
    S3_ENDPOINT_URL,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_BUCKET_NAME,
    S3_REGION,
    SCENARIO_PROFILES,
    VulnerabilitySettings,
    get_active_scenario,
    set_active_scenario
)

app = FastAPI(
    title="Direct Cloud Upload Testbed (Controlled Research Environment)",
    description="Simulates direct-to-cloud upload architectures with configurable security profiles (V1-V6).",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="testbed_app/static"), name="static")
templates = Jinja2Templates(directory="testbed_app/templates")

UPLOADED_RECORDS: List[Dict[str, Any]] = []
SECRET_CALLBACK_KEY = "testbed-callback-hmac-secret-key"

def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT_URL,
        aws_access_key_id=S3_ACCESS_KEY_ID,
        aws_secret_access_key=S3_SECRET_ACCESS_KEY,
        region_name=S3_REGION,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"})
    )

class PresignedUrlRequest(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    file_size: Optional[int] = None
    upload_method: str = "PUT"

class CallbackNotificationRequest(BaseModel):
    key: str
    filename: str
    file_size: int
    content_type: str
    signature: Optional[str] = None
    upload_token: Optional[str] = None

class ScenarioSwitchRequest(BaseModel):
    scenario_key: str

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    key, settings = get_active_scenario()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "active_scenario_key": key,
            "active_scenario": settings,
            "all_scenarios": SCENARIO_PROFILES
        }
    )

@app.get("/api/scenarios")
async def list_scenarios():
    active_key, active_cfg = get_active_scenario()
    return {
        "active_key": active_key,
        "active_config": active_cfg.model_dump(),
        "available_scenarios": {k: v.model_dump() for k, v in SCENARIO_PROFILES.items()}
    }

@app.post("/api/scenarios/set")
async def switch_scenario(req: ScenarioSwitchRequest):
    if req.scenario_key not in SCENARIO_PROFILES:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{req.scenario_key}'")
    updated = set_active_scenario(req.scenario_key)
    return {
        "message": f"Active scenario switched to '{req.scenario_key}'",
        "active_key": req.scenario_key,
        "config": updated.model_dump()
    }

@app.post("/api/get-upload-url")
async def generate_upload_url(
    req: PresignedUrlRequest,
    authorization: Optional[str] = Header(None)
):
    _, config = get_active_scenario()

    # --- V1 Check: Unrestricted Credential Acquisition ---
    if config.require_auth_for_credentials:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="[V1 Prevention] Authentication required: Missing or invalid Bearer token."
            )

    # --- V3 Check: Enforce Allowed File Types & Size Caps ---
    if config.enforce_type_and_size_limits:
        allowed_types = ["image/png", "image/jpeg", "application/pdf", "text/plain"]
        if req.content_type not in allowed_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"[V3 Prevention] Disallowed Content-Type '{req.content_type}'. Only {allowed_types} are permitted."
            )
        if req.file_size and req.file_size > 5 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"[V3 Prevention] File size ({req.file_size} bytes) exceeds maximum limit (5MB)."
            )

    # --- V4 Check: File Overwriting & Path Namespacing ---
    sanitized_filename = os.path.basename(req.filename)
    if config.allow_file_overwrite:
        object_key = f"uploads/{sanitized_filename}"
    else:
        unique_prefix = uuid.uuid4().hex[:12]
        object_key = f"uploads/{unique_prefix}_{sanitized_filename}"

    s3 = get_s3_client()
    expiry = config.expiry_seconds

    try:
        raw_sig = f"{object_key}:{req.content_type}:{int(time.time())}"
        callback_token = hmac.new(
            SECRET_CALLBACK_KEY.encode(), raw_sig.encode(), hashlib.sha256
        ).hexdigest()

        if req.upload_method.upper() == "POST":
            # Presigned POST Policy
            conditions = []
            fields = {}

            if config.public_read_acl:
                fields["acl"] = "public-read"
                conditions.append({"acl": "public-read"})

            # V3 POST Policy Rules
            if config.enforce_type_and_size_limits:
                conditions.append(["content-length-range", 1, 5 * 1024 * 1024])
                conditions.append({"Content-Type": req.content_type})
                fields["Content-Type"] = req.content_type
            else:
                conditions.append(["starts-with", "$Content-Type", ""])
                fields["Content-Type"] = req.content_type

            post_data = s3.generate_presigned_post(
                Bucket=S3_BUCKET_NAME,
                Key=object_key,
                Fields=fields,
                Conditions=conditions if conditions else None,
                ExpiresIn=expiry
            )

            return {
                "upload_type": "POST",
                "url": post_data["url"],
                "fields": post_data["fields"],
                "key": object_key,
                "expires_in_seconds": expiry,
                "acl": "public-read" if config.public_read_acl else "private",
                "callback_token": callback_token if config.verify_callback_signature else "none"
            }

        else:
            # Presigned PUT URL
            params = {
                "Bucket": S3_BUCKET_NAME,
                "Key": object_key,
                "ContentType": req.content_type,
            }
            required_headers = {
                "Content-Type": req.content_type
            }

            if config.public_read_acl:
                params["ACL"] = "public-read"
                required_headers["x-amz-acl"] = "public-read"

            presigned_url = s3.generate_presigned_url(
                ClientMethod="put_object",
                Params=params,
                ExpiresIn=expiry,
                HttpMethod="PUT"
            )

            return {
                "upload_type": "PUT",
                "url": presigned_url,
                "headers": required_headers,
                "key": object_key,
                "expires_in_seconds": expiry,
                "acl": "public-read" if config.public_read_acl else "private",
                "callback_token": callback_token if config.verify_callback_signature else "none"
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate presigned upload: {str(e)}")


@app.post("/api/upload-complete")
async def upload_complete_callback(req: CallbackNotificationRequest):
    _, config = get_active_scenario()

    # --- V6 Check: Callback Spoofing Prevention ---
    if config.verify_callback_signature:
        if not req.signature or req.signature == "none":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="[V6 Prevention] Callback Rejected: Missing or invalid callback signature token."
            )
        
        s3 = get_s3_client()
        try:
            head = s3.head_object(Bucket=S3_BUCKET_NAME, Key=req.key)
            actual_size = head.get("ContentLength", 0)
            if req.file_size > 0 and actual_size != req.file_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="[V6 Prevention] Callback Rejected: Reported size does not match storage object."
                )
        except ClientError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"[V6 Prevention] Callback Rejected: Object '{req.key}' was not found in storage bucket."
            )

    record = {
        "id": str(uuid.uuid4()),
        "key": req.key,
        "filename": req.filename,
        "file_size": req.file_size,
        "content_type": req.content_type,
        "timestamp": time.time(),
        "verified": config.verify_callback_signature
    }
    UPLOADED_RECORDS.append(record)

    return {
        "status": "success",
        "message": "Upload recorded and registered in application database.",
        "record": record
    }


@app.get("/api/files")
async def list_files():
    return {"files": UPLOADED_RECORDS}


@app.get("/health")
async def health_check():
    key, cfg = get_active_scenario()
    return {
        "status": "healthy",
        "active_scenario": key,
        "storage_endpoint": S3_ENDPOINT_URL,
        "bucket_name": S3_BUCKET_NAME
    }
