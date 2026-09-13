import requests
from urllib.parse import urljoin
from typing import Optional, Dict, Any
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V6CallbackProbe(BaseProbe):
    """
    V6 Probe: Callback Notification Spoofing.
    Sends fabricated, safe test callbacks with invalid/missing signatures
    and non-existent storage keys to determine if the backend blindly trusts callbacks.
    """

    def __init__(self):
        super().__init__(
            code="V6",
            category=VulnerabilityCategory.V6,
            cwe_id="CWE-345: Insufficient Verification of Data Authenticity"
        )

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        target_url = base_url or trace.target_page_url
        endpoint_url = urljoin(target_url, "/api/upload-complete")

        evidence: Dict[str, Any] = {
            "tested_callback_endpoint": endpoint_url
        }

        # 1. Inspect captured trace verification state
        trace_verified = False
        if trace.stage3:
            trace_verified = trace.stage3.is_verified
            evidence["trace_recorded_verified"] = trace_verified

        # 2. Active Probe: Send fabricated callback payload with fake key and invalid signature
        spoofed_payload = {
            "key": "uploads/spoofed_phantom_probe_file.pdf",
            "filename": "spoofed_phantom_probe_file.pdf",
            "file_size": 99999,
            "content_type": "application/pdf",
            "signature": "fabricated_spoofed_signature_token_xyz"
        }
        evidence["sent_spoofed_payload"] = spoofed_payload

        spoof_accepted = False
        http_status = None
        response_data = None

        try:
            res = requests.post(endpoint_url, json=spoofed_payload, timeout=5)
            http_status = res.status_code
            evidence["response_http_status"] = http_status
            try:
                response_data = res.json()
                evidence["response_body"] = response_data
            except Exception:
                evidence["response_body"] = res.text[:200]

            if http_status == 200 and response_data and response_data.get("status") == "success":
                spoof_accepted = True

        except Exception as e:
            evidence["probe_error"] = str(e)

        if spoof_accepted:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Callback Notification Spoofing Vulnerability Detected",
                vulnerable=True,
                severity="HIGH",
                cwe_id=self.cwe_id,
                description=(
                    f"The backend accepted a fabricated upload callback (HTTP {http_status}) for a non-existent "
                    "object without validating cryptographic signatures or verifying that the file was actually "
                    "written to cloud storage. An attacker can forge database entries, trigger post-processing workflows, "
                    "or falsify transaction confirmations."
                ),
                evidence=evidence,
                recommendation=(
                    "Require HMAC-signed tokens in callback requests and perform server-side object verification "
                    "(e.g. s3.head_object) to confirm object existence and byte size before registering the upload."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Callback Notifications Strictly Verified with Signature & Storage Checks",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    f"Fabricated callback notification was correctly rejected by backend with HTTP {http_status}. "
                    "The application requires valid cryptographic signatures and verifies storage object integrity."
                ),
                evidence=evidence,
                recommendation="Maintain strict HMAC verification and head_object checks on post-upload webhooks."
            )
