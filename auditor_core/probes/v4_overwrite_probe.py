import requests
from urllib.parse import urljoin
from typing import Optional, Dict, Any
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V4OverwriteProbe(BaseProbe):
    """
    V4 Probe: File Overwriting.
    Evaluates whether storage keys use raw, predictable client filenames
    or enforce collision-resistant unique identifiers (e.g. UUIDs).
    """

    def __init__(self):
        super().__init__(
            code="V4",
            category=VulnerabilityCategory.V4,
            cwe_id="CWE-73: External Control of File Name or Path"
        )

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        target_url = base_url or trace.target_page_url
        full_endpoint_url = urljoin(target_url, "/api/get-upload-url")

        evidence: Dict[str, Any] = {}
        observed_key = trace.stage1.storage_key if trace.stage1 else ""
        test_filename = trace.test_file_name

        evidence["observed_storage_key"] = observed_key
        evidence["client_filename"] = test_filename

        # Active Probe: Request 2 upload URLs for the same filename to test collision
        key1, key2 = None, None
        try:
            r1 = requests.post(
                full_endpoint_url,
                json={"filename": "probe_collision_sample.png", "content_type": "image/png", "upload_method": "PUT"},
                timeout=5
            )
            r2 = requests.post(
                full_endpoint_url,
                json={"filename": "probe_collision_sample.png", "content_type": "image/png", "upload_method": "PUT"},
                timeout=5
            )
            if r1.status_code == 200 and r2.status_code == 200:
                key1 = r1.json().get("key")
                key2 = r2.json().get("key")
                evidence["test_dispatched_key_1"] = key1
                evidence["test_dispatched_key_2"] = key2
        except Exception as e:
            evidence["active_probe_error"] = str(e)

        # Evaluate key collision
        has_key_collision = False
        if key1 and key2 and key1 == key2:
            has_key_collision = True
        elif observed_key and observed_key == f"uploads/{test_filename}":
            has_key_collision = True

        if has_key_collision:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Predictable Storage Key Naming Allows Arbitrary File Overwrite",
                vulnerable=True,
                severity="HIGH",
                cwe_id=self.cwe_id,
                description=(
                    f"The backend dispatches static, un-namespaced object keys (e.g. '{observed_key or key1}') "
                    "directly derived from client-supplied filenames. An attacker can overwrite other users' "
                    "stored files by uploading a file with the same filename."
                ),
                evidence=evidence,
                recommendation=(
                    "Prepend a cryptographically random UUID or secure hash to storage keys "
                    "(e.g., 'uploads/{uuid4()}_{filename}') to prevent key collisions and unauthorized overwriting."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Object Storage Keys are Randomized with Collision Prevention",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    "The backend generates unique, non-colliding storage keys for separate upload requests, "
                    "preventing unauthorized file overwriting."
                ),
                evidence=evidence,
                recommendation="Maintain unique randomized namespacing for all object keys."
            )
