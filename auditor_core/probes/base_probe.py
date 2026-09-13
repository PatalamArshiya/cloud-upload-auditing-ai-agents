from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding

class BaseProbe(ABC):
    """
    Abstract Base Class for Deterministic Upload Security Probes.
    Each probe focuses on a specific vulnerability category (V1 - V6).
    """

    def __init__(self, code: str, category: str, cwe_id: str):
        self.code = code
        self.category = category
        self.cwe_id = cwe_id

    @abstractmethod
    def run(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeFinding:
        """
        Executes the deterministic probe using evidence from WorkflowTrace
        and targeted, safe HTTP verification probes.
        """
        pass
