import os
import sys
import time
import requests
from auditor_core.observer.workflow_observer import WorkflowObserver

BASE_URL = "http://127.0.0.1:8000"
MINIO_URL = "http://127.0.0.1:9000"

def verify_observer():
    print("=" * 65)
    print("  PHASE 2 - PART 1: PLAYWRIGHT WORKFLOW OBSERVER TEST")
    print("=" * 65)

    # 1. Health check local services
    print("\n[Step 1/3] Verifying Local Testbed & MinIO Storage Availability...")
    try:
        minio_health = requests.get(f"{MINIO_URL}/minio/health/live", timeout=3)
        app_health = requests.get(f"{BASE_URL}/health", timeout=3)
        if minio_health.status_code == 200 and app_health.status_code == 200:
            print(f"[PASS] Services active! Target App: {BASE_URL} | Storage: {MINIO_URL}")
        else:
            print("[FAIL] Services returned unhealthy status.")
            return False
    except Exception as e:
        print(f"[FAIL] Could not connect to local testbed services: {e}")
        print("  -> Please run: start_all.bat or ensure MinIO & FastAPI are running.")
        return False

    # 2. Run Observer for Presigned PUT Workflow
    print("\n[Step 2/3] Executing Workflow Observer on Presigned PUT Upload...")
    observer = WorkflowObserver(base_url=BASE_URL, headless=True)
    trace_put = observer.observe_upload(upload_method="PUT")

    print("\n--- Presigned PUT Workflow Evidence Summary ---")
    print(f"Trace ID:         {trace_put.trace_id}")
    print(f"Completed:        {trace_put.completed}")
    print(f"Active Scenario:  {trace_put.scenario_name}")
    print(f"Test File:        {trace_put.test_file_name} ({trace_put.test_file_size} bytes)")

    if trace_put.stage1:
        print(f"[Stage 1 OK] Dispatched Key: {trace_put.stage1.storage_key}")
        print(f"             TTL:            {trace_put.stage1.expires_in_seconds}s")
        print(f"             ACL:            {trace_put.stage1.acl}")
        print(f"             URL:            {trace_put.stage1.presigned_url[:60]}...")
    else:
        print("[Stage 1 FAIL] No Stage 1 credential dispatch captured!")
        return False

    if trace_put.stage2:
        print(f"[Stage 2 OK] Upload HTTP Status: {trace_put.stage2.status_code}")
        print(f"             Storage Target:     {trace_put.stage2.storage_url[:60]}...")
    else:
        print("[Stage 2 FAIL] No Stage 2 cloud storage upload captured!")
        return False

    if trace_put.stage3:
        print(f"[Stage 3 OK] Callback Status:    {trace_put.stage3.status_code}")
        print(f"             Server Response:    {trace_put.stage3.response_body.get('message') if trace_put.stage3.response_body else 'N/A'}")
    else:
        print("[Stage 3 FAIL] No Stage 3 callback notification captured!")
        return False

    # 3. Run Observer for Presigned POST Workflow
    print("\n[Step 3/3] Executing Workflow Observer on Presigned POST Upload...")
    trace_post = observer.observe_upload(upload_method="POST")

    if not (trace_post.stage1 and trace_post.stage2 and trace_post.stage3):
        print("[FAIL] POST upload workflow failed to capture all 3 stages.")
        return False

    print(f"[Stage 1 OK] Form Fields Count: {len(trace_post.stage1.form_fields or {})}")
    print(f"[Stage 2 OK] POST HTTP Status:  {trace_post.stage2.status_code}")
    print(f"[Stage 3 OK] Callback Status:   {trace_post.stage3.status_code}")

    print("\n" + "=" * 65)
    print("  [SUCCESS] Playwright Workflow Observer is 100% Operational!")
    print("  All 3 stages of direct upload evidence were successfully collected.")
    print("=" * 65)
    return True

if __name__ == "__main__":
    success = verify_observer()
    sys.exit(0 if success else 1)
