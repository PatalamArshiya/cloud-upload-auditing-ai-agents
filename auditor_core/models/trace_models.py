from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import time
import uuid

class Stage1CredentialTrace(BaseModel):
    """Evidence captured during Stage 1: Credential Requesting & Dispatching"""
    endpoint_url: str
    method: str = "POST"
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[Dict[str, Any]] = None
    status_code: int
    upload_type: str = "PUT"  # "PUT" or "POST"
    presigned_url: str = ""
    storage_key: str = ""
    expires_in_seconds: Optional[int] = None
    acl: Optional[str] = None
    callback_token: Optional[str] = None
    signed_headers: Optional[Dict[str, str]] = None
    form_fields: Optional[Dict[str, str]] = None

class Stage2StorageTrace(BaseModel):
    """Evidence captured during Stage 2: Direct Upload to Cloud Storage"""
    storage_url: str
    method: str = "PUT"
    status_code: int
    request_headers: Dict[str, str] = Field(default_factory=dict)
    payload_size_bytes: int = 0
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None

class Stage3CallbackTrace(BaseModel):
    """Evidence captured during Stage 3: Post-Upload Callback Notification"""
    callback_url: str
    method: str = "POST"
    request_headers: Dict[str, str] = Field(default_factory=dict)
    payload: Optional[Dict[str, Any]] = None
    status_code: int
    response_body: Optional[Dict[str, Any]] = None
    is_verified: bool = False

class WorkflowTrace(BaseModel):
    """Consolidated 3-Stage Direct Cloud Upload Workflow Evidence Trace"""
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    target_page_url: str
    scenario_name: Optional[str] = None
    test_file_name: str
    test_file_size: int
    stage1: Optional[Stage1CredentialTrace] = None
    stage2: Optional[Stage2StorageTrace] = None
    stage3: Optional[Stage3CallbackTrace] = None
    raw_network_events: List[Dict[str, Any]] = Field(default_factory=list)
    completed: bool = False
    error_message: Optional[str] = None
