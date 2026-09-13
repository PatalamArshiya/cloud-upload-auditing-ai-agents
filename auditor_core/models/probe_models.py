from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import time
import uuid

class VulnerabilityCategory:
    V1 = "V1: Unrestricted Upload Credential Acquisition"
    V2 = "V2: Upload Credentials Validity Flaw"
    V3 = "V3: Unrestricted File Types and File Size"
    V4 = "V4: File Overwriting"
    V5 = "V5: File Stealing & Unauthorized Public Read"
    V6 = "V6: Callback Notification Spoofing"

class ProbeFinding(BaseModel):
    """Result of an individual deterministic security probe"""
    category: str
    code: str  # "V1", "V2", etc.
    title: str
    vulnerable: bool
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"
    cwe_id: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    recommendation: str

class ProbeSuiteResult(BaseModel):
    """Consolidated report across all V1-V6 deterministic probes"""
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    trace_id: str
    target_page_url: str
    scenario_name: Optional[str] = None
    total_probes_run: int = 6
    vulnerabilities_detected: int = 0
    passed_checks: int = 0
    findings: List[ProbeFinding] = Field(default_factory=list)
    summary: Dict[str, bool] = Field(default_factory=dict)
