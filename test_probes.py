import os
import sys
import json
import time
import requests

from auditor_core.observer.workflow_observer import WorkflowObserver
from auditor_core.probes.probe_runner import ProbeRunner

BASE_URL = "http://127.0.0.1:8000"
MINIO_URL = "http://127.0.0.1:9000"

def run_probe_tests():
    print("=" * 70)
    print("  PHASE 2 - PART 2: DETERMINISTIC SAFE PROBES (V1-V6 TEST SUITE)")
    print("=" * 70)

    # 1. Health check
    print("\n[Step 1/4] Verifying Local Testbed & MinIO Storage Health...")
    try:
        minio_res = requests.get(f"{MINIO_URL}/minio/health/live", timeout=3)
        app_res = requests.get(f"{BASE_URL}/health", timeout=3)
        if minio_res.status_code == 200 and app_res.status_code == 200:
            print("[PASS] Services are healthy and online.")
        else:
            print("[FAIL] Unhealthy services.")
            return False
    except Exception as e:
        print(f"[FAIL] Cannot reach local testbed: {e}")
        return False

    observer = WorkflowObserver(base_url=BASE_URL, headless=True)
    runner = ProbeRunner()

    # =========================================================================
    # Test Case 1: All Vulnerabilities Active (VULNERABLE Scenario)
    # =========================================================================
    print("\n" + "-" * 70)
    print("[Step 2/4] Test Case 1: Evaluating 'VULNERABLE' Profile (Expecting V1-V6 All Vulnerable)")
    print("-" * 70)

    # Switch scenario to VULNERABLE
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "VULNERABLE"}, timeout=3)

    # Observe upload workflow
    print("[*] Observing upload workflow via Playwright...")
    trace_vuln = observer.observe_upload(upload_method="PUT")
    if not trace_vuln.completed:
        print(f"[FAIL] Workflow observation failed: {trace_vuln.error_message}")
        return False

    # Run Probes
    vuln_result = runner.run_all_probes(trace_vuln, base_url=BASE_URL)

    print(f"\n[Test Case 1 Findings Summary]:")
    for f in vuln_result.findings:
        status_tag = "[VULNERABLE]" if f.vulnerable else "[SAFE]"
        print(f"  {f.code}: {status_tag} - {f.title} ({f.severity})")

    # Assertions for Test Case 1
    expected_vuln_codes = ["V1", "V2", "V3", "V4", "V5", "V6"]
    for code in expected_vuln_codes:
        if not vuln_result.summary.get(code):
            print(f"[FAIL] Expected {code} to be flagged as VULNERABLE, but was reported SAFE!")
            return False
    print(f"\n[PASS] Test Case 1: Successfully detected all 6/6 vulnerabilities under VULNERABLE profile!")

    # =========================================================================
    # Test Case 2: Fully Hardened & Secure Baseline (SAFE Scenario)
    # =========================================================================
    print("\n" + "-" * 70)
    print("[Step 3/4] Test Case 2: Evaluating 'SAFE' Profile (Expecting 0 Vulnerabilities)")
    print("-" * 70)

    # Switch scenario to SAFE
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "SAFE"}, timeout=3)

    # In SAFE profile, auth is required, so pass bearer token to observer
    print("[*] Observing upload workflow with valid Bearer auth token...")
    trace_safe = observer.observe_upload(upload_method="PUT", auth_token="test-authorized-user-token")
    if not trace_safe.completed:
        print(f"[FAIL] Workflow observation failed in SAFE mode: {trace_safe.error_message}")
        return False

    # Run Probes
    safe_result = runner.run_all_probes(trace_safe, base_url=BASE_URL)

    print(f"\n[Test Case 2 Findings Summary]:")
    for f in safe_result.findings:
        status_tag = "[VULNERABLE]" if f.vulnerable else "[SAFE]"
        print(f"  {f.code}: {status_tag} - {f.title} ({f.severity})")

    # Assertions for Test Case 2 (Expect 0 vulnerabilities)
    if safe_result.vulnerabilities_detected != 0:
        print(f"[FAIL] Expected 0 vulnerabilities under SAFE profile, but found {safe_result.vulnerabilities_detected}!")
        return False
    print(f"\n[PASS] Test Case 2: Correctly validated 0 false positives (6/6 checks SAFE) under SAFE profile!")

    # =========================================================================
    # Test Case 3: Targeted Single-Flaw Scenario (V1_ONLY)
    # =========================================================================
    print("\n" + "-" * 70)
    print("[Step 4/4] Test Case 3: Evaluating 'V1_ONLY' Profile (Expecting Only V1 Vulnerable)")
    print("-" * 70)

    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "V1_ONLY"}, timeout=3)
    trace_v1 = observer.observe_upload(upload_method="PUT")
    v1_result = runner.run_all_probes(trace_v1, base_url=BASE_URL)

    print(f"\n[Test Case 3 Findings Summary]:")
    for f in v1_result.findings:
        status_tag = "[VULNERABLE]" if f.vulnerable else "[SAFE]"
        print(f"  {f.code}: {status_tag} - {f.title}")

    if not v1_result.summary.get("V1") or v1_result.vulnerabilities_detected != 1:
        print(f"[FAIL] Expected only V1 to be vulnerable, got: {v1_result.summary}")
        return False
    print(f"\n[PASS] Test Case 3: Precision check passed — correctly isolated V1 vulnerability only!")

    # Reset testbed back to default
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "VULNERABLE"}, timeout=3)

    print("\n" + "=" * 70)
    print("  [ALL DETERMINISTIC PROBE SUITE TESTS PASSED 100%]")
    print("  V1-V6 Probes accurately classify both vulnerable and hardened profiles.")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_probe_tests()
    sys.exit(0 if success else 1)
