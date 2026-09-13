import os
import sys
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://127.0.0.1:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY_ID", "minioadmin")
S3_SECRET_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "minioadmin")
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "auditor-test-bucket")
S3_REGION = os.getenv("S3_REGION", "us-east-1")


def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def initialize_bucket():
    print(f"[*] Connecting to local storage at {S3_ENDPOINT}...")
    s3 = get_s3_client()

    try:
        # Check if bucket exists
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        if S3_BUCKET not in buckets:
            print(f"[*] Creating test bucket: {S3_BUCKET}...")
            s3.create_bucket(Bucket=S3_BUCKET)
            print(f"[+] Bucket '{S3_BUCKET}' created successfully.")
        else:
            print(f"[+] Bucket '{S3_BUCKET}' already exists.")

        # Attempt to set CORS if supported, otherwise skip
        try:
            cors_configuration = {
                "CORSRules": [
                    {
                        "AllowedHeaders": ["*"],
                        "AllowedMethods": ["GET", "PUT", "POST", "HEAD", "DELETE"],
                        "AllowedOrigins": ["*"],
                        "ExposeHeaders": ["ETag", "x-amz-server-side-encryption"],
                        "MaxAgeSeconds": 3000,
                    }
                ]
            }
            s3.put_bucket_cors(Bucket=S3_BUCKET, CORSConfiguration=cors_configuration)
            print(f"[+] CORS configuration applied to bucket.")
        except Exception:
            # Modern MinIO handles CORS natively
            print(f"[+] CORS is handled natively by MinIO server.")

        # Put a sample placeholder file to confirm write access
        test_key = "init_marker.txt"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=test_key,
            Body=b"Direct Upload Auditor Initialized Successfully.",
            ContentType="text/plain",
        )
        print(f"[+] Verified write permission with marker file: '{test_key}'.")
        print("\n[SUCCESS] Local Object Storage is fully initialized and ready!")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to initialize storage: {e}", file=sys.stderr)
        print(
            "[!] Ensure MinIO is running on http://127.0.0.1:9000 before running this script."
        )
        return False


if __name__ == "__main__":
    success = initialize_bucket()
    sys.exit(0 if success else 1)
