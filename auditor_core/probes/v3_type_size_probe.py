import json
import base64
import requests
from urllib.parse import urljoin
from typing import Optional, Dict, Any, List
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V3TypeSizeProbe(BaseProbe):
    """
    V3 Probe: Unrestricted File Types and File Size.
    Evaluates whether storage policies and issuance APIs constrain
    maximum upload byte size and MIME types.
    """

    def __init__(self):
        super().__init__(
            code="V3",
            category=VulnerabilityCategory.V3,
            cwe_id="CWE-434: Unrestricted Upload of File with Dangerous Type"
        )

    def _analyze_post_policy(self, fields: Dict[str, str]) -> Dict[str, Any]:
        result = {
            "has_content_length_range": False,
            "max_size_bytes": None,
            "has_strict_content_type": False,
            "allowed_content_types": [],
            "raw_conditions": []
        }
        if not fields or "policy" not in fields:
            return result

        try:
            raw_b64 = fields["policy"]
            decoded = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
            conditions = decoded.get("conditions", [])
            result["raw_conditions"] = conditions

            for cond in conditions:
                if isinstance(cond, list) and len(cond) == 3:
                    if cond[0] == "content-length-range":
                        result["has_content_length_range"] = True
                        result["max_size_bytes"] = cond[2]
                    elif cond[0] == "starts-with" and cond[1] == "$Content-Type" and cond[2] == "":
                        result["has_strict_content_type"] = False
                elif isinstance(cond, dict):
                    if "Content-Type" in cond:
                        result["has_strict_content_type"] = True
                        result["allowed_content_types"].append(cond["Content-Type"])

        except Exception as e:
            result["parse_error"] = str(e)

        return result

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        target_url = base_url or trace.target_page_url
        endpoint_url = urljoin(target_url, "/api/get-upload-url")

        evidence: Dict[str, Any] = {}
        has_size_constraint = False
        has_type_constraint = False

        # 1. Inspect captured trace POST policy if available
        if trace.stage1 and trace.stage1.form_fields:
            post_analysis = self._analyze_post_policy(trace.stage1.form_fields)
            evidence["post_policy_analysis"] = post_analysis
            if post_analysis["has_content_length_range"]:
                has_size_constraint = True
            if post_analysis["has_strict_content_type"]:
                has_type_constraint = True

        # 2. Active Probing: Test with Disallowed MIME Type (application/x-dosexec)
        auth_headers = {}
        if trace.stage1 and trace.stage1.request_headers:
            auth_val = trace.stage1.request_headers.get("authorization")
            if auth_val:
                auth_headers["Authorization"] = auth_val

        mime_rejected = False
        try:
            r_mime = requests.post(
                endpoint_url,
                json={"filename": "probe_dangerous_executable.exe", "content_type": "application/x-dosexec", "upload_method": "PUT"},
                headers=auth_headers,
                timeout=5
            )
            evidence["dangerous_mime_status"] = r_mime.status_code
            if r_mime.status_code in [400, 403, 422]:
                mime_rejected = True
                has_type_constraint = True
        except Exception as e:
            evidence["mime_probe_error"] = str(e)

        # 3. Active Probing: Test with Oversized File Size (50 MB)
        size_rejected = False
        try:
            r_size = requests.post(
                endpoint_url,
                json={"filename": "probe_oversized_payload.bin", "content_type": "image/png", "file_size": 50 * 1024 * 1024, "upload_method": "PUT"},
                headers=auth_headers,
                timeout=5
            )
            evidence["oversized_request_status"] = r_size.status_code
            if r_size.status_code in [400, 403, 413, 422]:
                size_rejected = True
                has_size_constraint = True
        except Exception as e:
            evidence["size_probe_error"] = str(e)

        # Evaluate Vulnerability
        is_vulnerable = not (has_size_constraint and has_type_constraint)

        if is_vulnerable:
            missing_items = []
            if not has_size_constraint:
                missing_items.append("maximum file size limits (permits arbitrary DoS payloads)")
            if not has_type_constraint:
                missing_items.append("Content-Type / MIME restrictions (permits dangerous executable payloads)")

            evidence["missing_constraints"] = missing_items

            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Unrestricted File Types and File Size Allowed",
                vulnerable=True,
                severity="HIGH",
                cwe_id=self.cwe_id,
                description=(
                    "The application and presigned storage policy lack critical upload boundaries: "
                    + ", ".join(missing_items) + "."
                ),
                evidence=evidence,
                recommendation=(
                    "Implement server-side MIME whitelisting, enforce size validation during presigned URL "
                    "generation, and embed ['content-length-range', 1, <max_bytes>] conditions in POST policies."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="File Size and MIME Type Constraints Properly Enforced",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    "The application correctly rejected dangerous MIME types (HTTP 400) and oversized "
                    "payloads, enforcing strict storage boundaries."
                ),
                evidence=evidence,
                recommendation="Maintain strict file type whitelisting and size boundaries."
            )
