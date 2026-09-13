import json
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Any
from auditor_core.probes.base_probe import BaseProbe
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, VulnerabilityCategory

class V2ValidityProbe(BaseProbe):
    """
    V2 Probe: Upload Credentials Validity Flaw.
    Calculates presigned URL/policy TTL and flags validity windows greater than 300 seconds.
    """

    def __init__(self, max_allowed_ttl_seconds: int = 300):
        super().__init__(
            code="V2",
            category=VulnerabilityCategory.V2,
            cwe_id="CWE-613: Insufficient Session Expiration"
        )
        self.max_allowed_ttl = max_allowed_ttl_seconds

    def _extract_ttl_from_trace(self, trace: WorkflowTrace) -> tuple[Optional[int], Dict[str, Any]]:
        details: Dict[str, Any] = {}
        if not trace.stage1:
            return None, {"error": "No Stage 1 credential trace captured"}

        # 1. Direct field if captured
        if trace.stage1.expires_in_seconds is not None:
            details["source"] = "api_response_expires_in"
            return trace.stage1.expires_in_seconds, details

        # 2. Check URL query parameters (X-Amz-Expires)
        if trace.stage1.presigned_url:
            parsed = urlparse(trace.stage1.presigned_url)
            qs = parse_qs(parsed.query)
            if "X-Amz-Expires" in qs:
                ttl = int(qs["X-Amz-Expires"][0])
                details["source"] = "X-Amz-Expires query parameter"
                details["raw_value"] = qs["X-Amz-Expires"][0]
                return ttl, details

        # 3. Check Presigned POST Policy Base64
        if trace.stage1.form_fields and "policy" in trace.stage1.form_fields:
            try:
                raw_b64 = trace.stage1.form_fields["policy"]
                decoded_str = base64.b64decode(raw_b64).decode("utf-8")
                policy_json = json.loads(decoded_str)
                details["decoded_policy"] = policy_json

                if "expiration" in policy_json:
                    exp_str = policy_json["expiration"]
                    # Example: "2026-09-06T13:51:49Z"
                    exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    now_dt = datetime.now(timezone.utc)
                    ttl = int((exp_dt - now_dt).total_seconds())
                    details["source"] = "POST policy expiration attribute"
                    details["expiration_iso"] = exp_str
                    return ttl, details
            except Exception as e:
                details["policy_decode_error"] = str(e)

        return None, details

    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        calculated_ttl, details = self._extract_ttl_from_trace(trace)

        if calculated_ttl is None:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Presigned Credential Validity Window Indeterminate",
                vulnerable=False,
                severity="LOW",
                cwe_id=self.cwe_id,
                description="Could not extract expiration parameters from the captured upload trace.",
                evidence=details,
                recommendation="Ensure presigned upload URLs explicitly define an expiration parameter (e.g. ExpiresIn)."
            )

        details["calculated_ttl_seconds"] = calculated_ttl
        details["max_recommended_ttl_seconds"] = self.max_allowed_ttl

        if calculated_ttl > self.max_allowed_ttl:
            ttl_hours = round(calculated_ttl / 3600, 1)
            ttl_days = round(calculated_ttl / 86400, 1)
            duration_desc = f"{calculated_ttl}s (~{ttl_days} days)" if calculated_ttl >= 86400 else f"{calculated_ttl}s (~{ttl_hours} hours)"

            return ProbeFinding(
                category=self.category,
                code=self.code,
                title=f"Excessive Presigned Upload TTL ({duration_desc})",
                vulnerable=True,
                severity="MEDIUM",
                cwe_id=self.cwe_id,
                description=(
                    f"The presigned upload credential has an excessively long validity period of "
                    f"{duration_desc}, exceeding the safe threshold of {self.max_allowed_ttl} seconds. "
                    "Long-lived presigned credentials increase the exposure window if leaked or intercepted."
                ),
                evidence=details,
                recommendation=(
                    f"Configure the presigned URL/policy TTL to a short window (e.g., 300 seconds / 5 minutes) "
                    "sufficient only for completing the immediate client upload."
                )
            )
        else:
            return ProbeFinding(
                category=self.category,
                code=self.code,
                title="Presigned Credential Validity Window is Short & Constrained",
                vulnerable=False,
                severity="SAFE",
                cwe_id=self.cwe_id,
                description=(
                    f"The presigned upload credential expires in {calculated_ttl} seconds, "
                    f"which satisfies the maximum recommended TTL limit of {self.max_allowed_ttl} seconds."
                ),
                evidence=details,
                recommendation="Maintain short validity windows (<= 300s) on presigned upload tokens."
            )
