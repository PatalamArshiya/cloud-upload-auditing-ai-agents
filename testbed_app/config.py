import os
from typing import Dict, Any
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# S3 / MinIO Configuration
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "http://127.0.0.1:9000")
S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "minioadmin")
S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "minioadmin")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "auditor-test-bucket")
S3_REGION = os.getenv("S3_REGION", "us-east-1")

class VulnerabilitySettings(BaseModel):
    name: str
    description: str
    require_auth_for_credentials: bool = False  # V1
    expiry_seconds: int = 604800               # V2 (7 days = 604800s, Safe = 300s)
    enforce_type_and_size_limits: bool = False  # V3
    allow_file_overwrite: bool = True           # V4 (uses un-namespaced filename)
    public_read_acl: bool = True               # V5 (exposes file directly)
    verify_callback_signature: bool = False     # V6 (accepts spoofed callbacks)

SCENARIO_PROFILES: Dict[str, VulnerabilitySettings] = {
    "VULNERABLE": VulnerabilitySettings(
        name="All Vulnerabilities Active (V1-V6)",
        description="Emulates a high-risk legacy web application with all 6 direct-cloud-upload flaws enabled.",
        require_auth_for_credentials=False,
        expiry_seconds=604800,
        enforce_type_and_size_limits=False,
        allow_file_overwrite=True,
        public_read_acl=True,
        verify_callback_signature=False
    ),
    "SAFE": VulnerabilitySettings(
        name="Fully Hardened & Secure Baseline",
        description="Implements all security mitigations: strict auth, 5m TTL, size/MIME caps, UUID keys, private ACL, verified callbacks.",
        require_auth_for_credentials=True,
        expiry_seconds=300,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=False,
        public_read_acl=False,
        verify_callback_signature=True
    ),
    "V1_ONLY": VulnerabilitySettings(
        name="V1: Unrestricted Credential Acquisition",
        description="Publicly accessible endpoint issues presigned upload credentials without authentication.",
        require_auth_for_credentials=False,
        expiry_seconds=300,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=False,
        public_read_acl=False,
        verify_callback_signature=True
    ),
    "V2_ONLY": VulnerabilitySettings(
        name="V2: Credential Validity Flaw",
        description="Presigned URL validity window is excessively long (7 days) without single-use restrictions.",
        require_auth_for_credentials=True,
        expiry_seconds=604800,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=False,
        public_read_acl=False,
        verify_callback_signature=True
    ),
    "V3_ONLY": VulnerabilitySettings(
        name="V3: Unrestricted File Types and File Size",
        description="No restrictions on file size or MIME types in the presigned policy parameters.",
        require_auth_for_credentials=True,
        expiry_seconds=300,
        enforce_type_and_size_limits=False,
        allow_file_overwrite=False,
        public_read_acl=False,
        verify_callback_signature=True
    ),
    "V4_ONLY": VulnerabilitySettings(
        name="V4: File Overwriting",
        description="Uses raw, un-sanitized client filenames allowing malicious users to overwrite existing user files.",
        require_auth_for_credentials=True,
        expiry_seconds=300,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=True,
        public_read_acl=False,
        verify_callback_signature=True
    ),
    "V5_ONLY": VulnerabilitySettings(
        name="V5: File Stealing & Public Object Access",
        description="Objects are uploaded with public-read ACL, allowing unauthenticated third parties to read files.",
        require_auth_for_credentials=True,
        expiry_seconds=300,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=False,
        public_read_acl=True,
        verify_callback_signature=True
    ),
    "V6_ONLY": VulnerabilitySettings(
        name="V6: Callback Notification Spoofing",
        description="Backend accepts post-upload notifications without validating signatures or checking S3 presence.",
        require_auth_for_credentials=True,
        expiry_seconds=300,
        enforce_type_and_size_limits=True,
        allow_file_overwrite=False,
        public_read_acl=False,
        verify_callback_signature=False
    ),
}

CURRENT_SCENARIO_KEY = os.getenv("ACTIVE_SCENARIO", "VULNERABLE")
if CURRENT_SCENARIO_KEY not in SCENARIO_PROFILES:
    CURRENT_SCENARIO_KEY = "VULNERABLE"

current_settings: VulnerabilitySettings = SCENARIO_PROFILES[CURRENT_SCENARIO_KEY]

def set_active_scenario(key: str) -> VulnerabilitySettings:
    global CURRENT_SCENARIO_KEY, current_settings
    if key in SCENARIO_PROFILES:
        CURRENT_SCENARIO_KEY = key
        current_settings = SCENARIO_PROFILES[key]
    return current_settings

def get_active_scenario() -> tuple[str, VulnerabilitySettings]:
    return CURRENT_SCENARIO_KEY, current_settings
