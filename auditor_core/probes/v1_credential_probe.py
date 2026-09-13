import requests
from typing import Optional
from urllib.parse import urljoin
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V1CredentialProbe(BaseProbe):
    """
    V1 Probe: Unrestricted Upload Credential Acquisition.
    Tests whether unauthenticated anonymous clients can request presigned upload credentials.
    """

    def __init__(self):
        super().__init__(
            code="V1",
            category=VulnerabilityCategory.V1,
            cwe_id="CWE-306: Missing Authentication for Critical Function"
        )

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        target_url = base_url or trace.target_page_url
        endpoint = "/api/get-upload-url"
        full_endpoint_url = urljoin(target_url, endpoint)

        # 1. Inspect captured trace
        observed_unauthenticated_success = False
        if trace.stage1 and trace.stage1.status_code == 200:
            auth_header = trace.stage1.request_headers.get("authorization", "")
            if not auth_header:
                observed_unauthenticated_success = True

        # 2. Execute active verification probe (Send unauthenticated request)
        probe_response_status = None
        probe_response_body = None
        unauth_request_succeeded = False

        try:
            res = requests.post(
                full_endpoint_url,
                json={
                    "filename": "probe_v1_auth_check.txt",
                    "content_type": "text/plain",
                    "file_size": 100,
                    "upload_method": "PUT"
                },
                headers={"Content-Type": "application/json"},  # Explicitly omit Authorization header
                timeout=5
            )
            probe_response_status = res.status_code
            try:
                probe_response_body = res.json()
            except Exception:
                probe_response_body = res.text[:200]

            if res.status_code == 200 and "url" in str(res.text):
                unauth_request_succeeded = True

        except Exception as e:
            probe_response_body = f"Connection error: {str(e)}"

        is_vulnerable = unauth_request_succeeded or observed_unauthenticated_success

        if is_vulnerable:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Unauthenticated Presigned Upload Credential Acquisition",
                vulnerable=True,
                severity="HIGH",
                cwe_id=self.cwe_id,
                description=(
                    "The application allows anonymous, unauthenticated clients to request valid "
                    "presigned upload URLs/policies. An attacker can abuse this endpoint to obtain "
                    "unauthorized cloud storage write credentials."
                ),
                evidence={
                    "endpoint_tested": full_endpoint_url,
                    "http_status": probe_response_status,
                    "unauth_request_succeeded": unauth_request_succeeded,
                    "observed_in_trace": observed_unauthenticated_success,
                    "response_sample": probe_response_body
                },
                recommendation=(
                    "Implement mandatory authentication and authorization checks (e.g. Bearer token "
                    "or session cookie validation) before generating presigned upload credentials."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Credential Acquisition Correctly Enforces Authentication",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    "Unauthenticated requests to obtain presigned upload credentials were "
                    f"correctly rejected by the server with HTTP {probe_response_status}."
                ),
                evidence={
                    "endpoint_tested": full_endpoint_url,
                    "http_status": probe_response_status,
                    "rejection_response": probe_response_body
                },
                recommendation="Maintain current authentication requirements on presigned URL issuance endpoints."
            )
