import os
import json
import time
from typing import Optional, List, Dict
from auditor_core.models.trace_models import WorkflowTrace
from auditor_core.models.probe_models import ProbeFinding, ProbeSuiteResult
from auditor_core.probes.v1_credential_probe import V1CredentialProbe
from auditor_core.probes.v2_validity_probe import V2ValidityProbe
from auditor_core.probes.v3_type_size_probe import V3TypeSizeProbe
from auditor_core.probes.v4_overwrite_probe import V4OverwriteProbe
from auditor_core.probes.v5_access_probe import V5AccessProbe
from auditor_core.probes.v6_callback_probe import V6CallbackProbe

class ProbeRunner:
    """
    Orchestrates execution of the V1-V6 deterministic probe suite
    against captured WorkflowTrace evidence.
    """

    def __init__(self, reports_dir: str = "data/reports"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        self.probes = [
            V1CredentialProbe(),
            V2ValidityProbe(max_allowed_ttl_seconds=300),
            V3TypeSizeProbe(),
            V4OverwriteProbe(),
            V5AccessProbe(),
            V6CallbackProbe()
        ]

    def run_all_probes(self, trace: WorkflowTrace, base_url: Optional[str] = None) -> ProbeSuiteResult:
        """Executes all 6 deterministic probes and produces a consolidated result."""
        target_url = base_url or trace.target_page_url
        findings: List[ProbeFinding] = []
        summary: Dict[str, bool] = {}

        vulnerabilities_count = 0
        passed_count = 0

        print(f"[*] Launching Deterministic Probe Suite across 6 vulnerability categories...")
        for probe in self.probes:
            print(f"  -> Executing {probe.code} ({probe.category})...")
            try:
                finding = probe.run(trace, base_url=target_url)
                findings.append(finding)
                summary[probe.code] = finding.vulnerable

                if finding.vulnerable:
                    vulnerabilities_count += 1
                    status_str = f"[VULNERABLE - {finding.severity}]"
                else:
                    passed_count += 1
                    status_str = "[SAFE / PASSED]"

                print(f"     {status_str} {finding.title}")
            except Exception as e:
                print(f"     [ERROR] Probe {probe.code} failed: {e}")
                # Fallback finding on unexpected error
                finding = ProbeFinding(
                    category=probe.category,
                    code=probe.code,
                    title=f"Probe Execution Error: {str(e)}",
                    vulnerable=False,
                    severity="LOW",
                    cwe_id=probe.cwe_id,
                    description=f"Probe encountered an unexpected error: {str(e)}",
                    evidence={"error": str(e)},
                    recommendation="Review system logs."
                )
                findings.append(finding)
                summary[probe.code] = False
                passed_count += 1

        result = ProbeSuiteResult(
            trace_id=trace.trace_id,
            target_page_url=target_url,
            scenario_name=trace.scenario_name,
            total_probes_run=len(self.probes),
            vulnerabilities_detected=vulnerabilities_count,
            passed_checks=passed_count,
            findings=findings,
            summary=summary
        )

        # Save structured report
        report_filename = f"probe_report_{int(result.timestamp)}_{result.run_id[:8]}.json"
        report_path = os.path.join(self.reports_dir, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))

        print(f"[+] Consolidated Probe Report saved to: {report_path}")
        return result

    def run_from_trace_file(self, trace_file_path: str, base_url: Optional[str] = None) -> ProbeSuiteResult:
        """Loads a trace JSON file and runs the deterministic probe suite against it."""
        with open(trace_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        trace = WorkflowTrace(**data)
        return self.run_all_probes(trace, base_url=base_url)
