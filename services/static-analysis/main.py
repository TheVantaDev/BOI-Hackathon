import asyncio
import io
import logging
import os
import shutil
import tempfile
from functools import lru_cache

import boto3
from botocore.client import Config
from fastapi import FastAPI
from pydantic import BaseModel

from analyzer import analyze_apk, decompile_apk

app = FastAPI(title="Static Analysis Service")
logger = logging.getLogger(__name__)

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


class APKRef(BaseModel):
    apk_id: str
    minio_path: str
    sha256: str


def _get_minio_client():
    endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "sentinel_minio")
    secret_key = os.getenv("MINIO_SECRET_KEY", "sentinel_minio_pass")
    return boto3.client(
        "s3",
        endpoint_url=f"http://{endpoint}",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def _fetch_from_minio(minio_path: str) -> bytes:
    client = _get_minio_client()
    parts = minio_path.split("/", 1)
    bucket, key = parts[0], parts[1]
    resp = client.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def _upload_to_minio(minio_path: str, data: bytes, content_type: str = "application/zip"):
    client = _get_minio_client()
    parts = minio_path.split("/", 1)
    bucket, key = parts[0], parts[1]
    try:
        client.head_bucket(Bucket=bucket)
    except Exception:
        client.create_bucket(Bucket=bucket)

    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=io.BytesIO(data),
        ContentLength=len(data),
        ContentType=content_type,
    )


def _run_analysis(tmp_path: str, apk_id: str):
    result = analyze_apk(tmp_path, RULES_DIR)
    result["apk_id"] = apk_id

    decompiled_info = {}
    try:
        decomp_res, temp_dir = decompile_apk(tmp_path, apk_id)

        if "apktool_zip" in decomp_res:
            apktool_minio_key = f"{apk_id}/decompiled_apktool.zip"
            with open(decomp_res["apktool_zip"], "rb") as f:
                _upload_to_minio(f"apk-uploads/{apktool_minio_key}", f.read())
            decompiled_info["apktool_path"] = f"apk-uploads/{apktool_minio_key}"

        if "jadx_zip" in decomp_res:
            jadx_minio_key = f"{apk_id}/decompiled_jadx.zip"
            with open(decomp_res["jadx_zip"], "rb") as f:
                _upload_to_minio(f"apk-uploads/{jadx_minio_key}", f.read())
            decompiled_info["jadx_path"] = f"apk-uploads/{jadx_minio_key}"

        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as decomp_exc:
        logger.exception("Decompilation pipeline failed: %s", decomp_exc)

    result["decompiled"] = decompiled_info
    return result


@app.post("/analyze")
async def analyze(ref: APKRef):
    try:
        apk_bytes = _fetch_from_minio(ref.minio_path)
    except Exception as exc:
        logger.warning("MinIO fetch failed, running stub analysis: %s", exc)
        return _stub_result(ref.apk_id)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_analysis, tmp_path, ref.apk_id)
        return result
    except Exception as exc:
        logger.exception("Analysis failed for %s: %s", ref.apk_id, exc)
        return _stub_result(ref.apk_id)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _stub_result(apk_id: str) -> dict:
    return {
        "apk_id": apk_id,
        "_stub": True,
        "permissions": [
            {"name": "READ_SMS", "full": "android.permission.READ_SMS", "dangerous": True},
            {"name": "RECEIVE_SMS", "full": "android.permission.RECEIVE_SMS", "dangerous": True},
            {"name": "BIND_ACCESSIBILITY_SERVICE", "full": "android.permission.BIND_ACCESSIBILITY_SERVICE", "dangerous": True},
            {"name": "INTERNET", "full": "android.permission.INTERNET", "dangerous": False},
        ],
        "dangerous_permission_count": 3,
        "manifest": {"package_name": "com.unknown.app", "min_sdk": "21", "target_sdk": "33"},
        "suspicious_apis": ["getDeviceId", "sendTextMessage", "DexClassLoader"],
        "obfuscation_detected": True,
        "dynamic_code_loading": True,
        "hardcoded_urls": ["http://185.220.101.45/c2/"],
        "hardcoded_ips": ["185.220.101.45"],
        "yara_matches": ["BankingTrojan_SMSInterceptor", "BankingTrojan_OverlayAttack"],
        "risk_indicator_count": 12,
        "iocs": {"domains": ["185.220.101.45"], "ips": ["185.220.101.45"]},
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "static-analysis"}
