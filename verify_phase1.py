import os
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://127.0.0.1:8000"
MINIO_URL = "http://127.0.0.1:9000"

def run_tests():
    print("=" * 65)
    print("  PHASE 1 VERIFICATION: DIRECT CLOUD UPLOAD TESTBED & STORAGE")
    print("=" * 65)

    # 1. Test MinIO Health
    print("\n[Step 1/6] Checking MinIO Object Storage Health...")
    try:
        minio_res = requests.get(f"{MINIO_URL}/minio/health/live", timeout=3)
        if minio_res.status_code == 200:
            print("[PASS] MinIO is running and healthy at http://127.0.0.1:9000")
        else:
            print(f"[WARN] MinIO returned status code: {minio_res.status_code}")
    except Exception as e:
        print(f"[FAIL] Cannot reach MinIO: {e}")
        print("  -> Please run: storage_mock\\run_minio.bat first.")
        return False

    # 2. Initialize S3 Bucket
    print("\n[Step 2/6] Verifying S3 Bucket & CORS Configuration...")
    from storage_mock.init_storage import initialize_bucket
    if not initialize_bucket():
        print("[FAIL] S3 Bucket initialization failed.")
        return False

    # 3. Test FastAPI Testbed Health
    print("\n[Step 3/6] Checking FastAPI Testbed App Health...")
    try:
        health_res = requests.get(f"{BASE_URL}/health", timeout=3)
        if health_res.status_code == 200:
            print(f"[PASS] Testbed App is active: {health_res.json()}")
        else:
            print(f"[FAIL] Testbed App returned status: {health_res.status_code}")
            return False
    except Exception as e:
        print(f"[FAIL] Cannot reach Testbed App: {e}")
        print("  -> Please run: run_testbed.bat first.")
        return False

    # 4. Test Scenario Switching (VULNERABLE mode)
    print("\n[Step 4/6] Switching to 'VULNERABLE' profile...")
    switch_res = requests.post(
        f"{BASE_URL}/api/scenarios/set",
        json={"scenario_key": "VULNERABLE"},
        timeout=3
    )
    if switch_res.status_code != 200:
        print(f"[FAIL] Failed to switch scenario: {switch_res.text}")
        return False
    print(f"[PASS] Scenario switched: {switch_res.json()['message']}")

    # 5. Test 3-Stage Direct Upload Workflow
    print("\n[Step 5/6] Testing End-to-End Direct Upload Workflow...")
    
    # Stage 1: Request Presigned URL
    test_content = b"Verification test payload for Phase 1 direct upload."
    presign_res = requests.post(
        f"{BASE_URL}/api/get-upload-url",
        json={
            "filename": "phase1_test_file.txt",
            "content_type": "text/plain",
            "file_size": len(test_content),
            "upload_method": "PUT"
        },
        timeout=3
    )
    if presign_res.status_code != 200:
        print(f"[FAIL] Stage 1 Presigned URL request failed: {presign_res.text}")
        return False
    
    presign_data = presign_res.json()
    upload_url = presign_data["url"]
    dispatched_key = presign_data["key"]
    token = presign_data["callback_token"]
    req_headers = presign_data.get("headers", {})
    print(f"  -> [Stage 1 OK] Dispatched Key: {dispatched_key}")

    # Stage 2: Direct Upload to MinIO
    upload_res = requests.put(
        upload_url,
        data=test_content,
        headers=req_headers,
        timeout=5
    )
    if upload_res.status_code not in (200, 204):
        print(f"[FAIL] Stage 2 Direct S3 Upload failed with status {upload_res.status_code}: {upload_res.text}")
        return False
    print(f"  -> [Stage 2 OK] Direct upload to MinIO succeeded (HTTP {upload_res.status_code})")

    # Stage 3: Callback Notification
    callback_res = requests.post(
        f"{BASE_URL}/api/upload-complete",
        json={
            "key": dispatched_key,
            "filename": "phase1_test_file.txt",
            "file_size": len(test_content),
            "content_type": "text/plain",
            "signature": token
        },
        timeout=3
    )
    if callback_res.status_code != 200:
        print(f"[FAIL] Stage 3 Callback failed: {callback_res.text}")
        return False
    print(f"  -> [Stage 3 OK] Callback accepted: {callback_res.json()['message']}")

    # 6. Test Security Profiles: SAFE vs V1_ONLY
    print("\n[Step 6/6] Testing Security Policy Toggles (SAFE vs V1_ONLY)...")
    
    # Switch to SAFE profile (enforces auth)
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "SAFE"}, timeout=3)
    
    # 6a. Unauthenticated request in SAFE mode should be 401
    unauth_res = requests.post(
        f"{BASE_URL}/api/get-upload-url",
        json={"filename": "unauth.txt", "content_type": "text/plain", "upload_method": "PUT"},
        timeout=3
    )
    if unauth_res.status_code == 401:
        print(f"[PASS] SAFE Mode: Unauthenticated request rejected with HTTP 401: {unauth_res.json()['detail']}")
    else:
        print(f"[FAIL] SAFE Mode: Expected HTTP 401, but received {unauth_res.status_code}")
        return False

    # 6b. Authenticated request in SAFE mode should succeed (200)
    auth_res = requests.post(
        f"{BASE_URL}/api/get-upload-url",
        headers={"Authorization": "Bearer test-user-token-123"},
        json={"filename": "auth.txt", "content_type": "text/plain", "upload_method": "PUT"},
        timeout=3
    )
    if auth_res.status_code == 200:
        print(f"[PASS] SAFE Mode: Authenticated request accepted (HTTP 200)")
    else:
        print(f"[FAIL] SAFE Mode: Authenticated request failed: {auth_res.text}")
        return False

    # 6c. Switch to V1_ONLY (Vulnerability active -> unauthenticated allowed)
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "V1_ONLY"}, timeout=3)
    v1_res = requests.post(
        f"{BASE_URL}/api/get-upload-url",
        json={"filename": "v1_test.txt", "content_type": "text/plain", "upload_method": "PUT"},
        timeout=3
    )
    if v1_res.status_code == 200:
        print(f"[PASS] V1_ONLY Mode: Unauthenticated credential acquisition permitted (Vulnerability V1 reproduced)")
    else:
        print(f"[FAIL] V1_ONLY Mode: Expected HTTP 200, got {v1_res.status_code}")
        return False

    # Reset back to default
    requests.post(f"{BASE_URL}/api/scenarios/set", json={"scenario_key": "VULNERABLE"}, timeout=3)

    print("\n" + "=" * 65)
    print("  [ALL 6 VERIFICATION CHECKS PASSED SUCCESSFULLY]")
    print("  Phase 1 Testbed & Local Storage Environment are 100% Ready!")
    print("=" * 65)
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
