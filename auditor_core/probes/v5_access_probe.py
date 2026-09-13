import requests
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Any
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V5AccessProbe(BaseProbe):
    """
    V5 Probe: File Stealing & Public Object Access.
    Tests whether uploaded files are stored with public-read permissions
    and can be retrieved anonymously by unauthorized third parties.
    """

    def __init__(self):
        super().__init__(
            code="V5",
            category=VulnerabilityCategory.V5,
            cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        )

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        evidence: Dict[str, Any] = {}
        is_publicly_readable = False

        # 1. Inspect ACL settings from Stage 1
        observed_acl = trace.stage1.acl if trace.stage1 else None
        evidence["observed_acl_in_trace"] = observed_acl

        # 2. Extract Clean Storage Object URL (Strip all authentication query parameters)
        raw_storage_url = None
        candidate_url = None
        if trace.stage2 and trace.stage2.storage_url:
            candidate_url = trace.stage2.storage_url
        elif trace.stage1 and trace.stage1.presigned_url:
            candidate_url = trace.stage1.presigned_url

        if candidate_url:
            parsed = urlparse(candidate_url)
            raw_storage_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        evidence["tested_object_url"] = raw_storage_url

        # 3. Active Probe: Perform unauthenticated GET request on the raw object
        http_status = None
        if raw_storage_url:
            try:
                res = requests.get(raw_storage_url, timeout=5)
                http_status = res.status_code
                evidence["unauthenticated_get_status"] = http_status
                if http_status == 200:
                    is_publicly_readable = True
                    evidence["read_payload_preview"] = res.text[:100]
            except Exception as e:
                evidence["probe_error"] = str(e)

        if observed_acl == "public-read" or is_publicly_readable:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Uploaded Files Publicly Accessible via Unauthenticated Read",
                vulnerable=True,
                severity="HIGH",
                cwe_id=self.cwe_id,
                description=(
                    f"Uploaded files are stored with 'public-read' access permissions (HTTP {http_status}). "
                    "Any unauthenticated third party with knowledge or guessing of the object key can "
                    "download sensitive user data without authorization (File Stealing risk)."
                ),
                evidence=evidence,
                recommendation=(
                    "Enforce 'private' ACL on all uploaded objects and serve files exclusively through "
                    "authenticated application endpoints or short-lived presigned download URLs."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Object Storage Enforces Private Access Controls",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    f"Direct unauthenticated GET requests to the object URL were rejected with HTTP {http_status}. "
                    "Objects are properly protected against unauthorized public reading."
                ),
                evidence=evidence,
                recommendation="Maintain private object ACL policies."
            )
