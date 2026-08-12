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
    """Run Androguard static analysis only — fast, returns immediately."""
    result = analyze_apk(tmp_path, RULES_DIR)
    result["apk_id"] = apk_id
    result["decompiled"] = {}  # will be filled by background decompilation
    return result


def _run_decompilation_background(tmp_path: str, apk_id: str):
    """
    Run APKTool + JADX decompilation in a background thread.
    This is intentionally separated from _run_analysis so that:
    - OOM crashes from JADX don't kill the analysis response
    - Large APKs don't block the pipeline for minutes
    - Score calculation always gets static features even if decompilation fails
    """
    import threading
    logger.info("[bg-decompile] Starting background decompilation for apk_id=%s", apk_id)

    def _worker():
        try:
            decomp_res, temp_dir = decompile_apk(tmp_path, apk_id)
            decompiled_info = {}

            if "apktool_zip" in decomp_res:
                apktool_minio_key = f"{apk_id}/decompiled_apktool.zip"
                with open(decomp_res["apktool_zip"], "rb") as f:
                    _upload_to_minio(f"apk-uploads/{apktool_minio_key}", f.read())
                decompiled_info["apktool_path"] = f"apk-uploads/{apktool_minio_key}"
                logger.info("[bg-decompile] APKTool zip uploaded for apk_id=%s", apk_id)

            if "jadx_zip" in decomp_res:
                jadx_minio_key = f"{apk_id}/decompiled_jadx.zip"
                with open(decomp_res["jadx_zip"], "rb") as f:
                    _upload_to_minio(f"apk-uploads/{jadx_minio_key}", f.read())
                decompiled_info["jadx_path"] = f"apk-uploads/{jadx_minio_key}"
                logger.info("[bg-decompile] JADX zip uploaded for apk_id=%s", apk_id)

            shutil.rmtree(temp_dir, ignore_errors=True)

            # Update the backend DB via internal API so decompiled paths are saved.
            # Retry with backoff because the main pipeline may not have saved the
            # AnalysisResult row to the DB yet when decompilation finishes early.
            import urllib.request, json as _json
            import time as _time
            patch_payload = _json.dumps({"apk_id": apk_id, "decompiled": decompiled_info}).encode()
            patch_ok = False
            for attempt, delay in enumerate([0, 15, 30, 60], start=1):
                if delay:
                    _time.sleep(delay)
                try:
                    req = urllib.request.Request(
                        f"http://backend:8000/api/analysis/{apk_id}/decompiled",
                        data=patch_payload,
                        headers={"Content-Type": "application/json"},
                        method="PATCH",
                    )
                    urllib.request.urlopen(req, timeout=10)
                    patch_ok = True
                    logger.info("[bg-decompile] Patched decompiled paths for apk_id=%s (attempt %d)", apk_id, attempt)
                    break
                except Exception as patch_exc:
                    logger.warning("[bg-decompile] Patch attempt %d failed for %s: %s", attempt, apk_id, patch_exc)
            if not patch_ok:
                logger.error("[bg-decompile] All patch attempts failed for apk_id=%s — decompiled source won't appear in UI", apk_id)

            logger.info("[bg-decompile] Decompilation complete for apk_id=%s", apk_id)
        except Exception as exc:
            logger.exception("[bg-decompile] Failed for apk_id=%s: %s", apk_id, exc)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


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
        # Step 1: Run fast Androguard analysis — this is what the pipeline needs for scoring
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_analysis, tmp_path, ref.apk_id)

        # Step 2: Kick off decompilation in the background (APKTool + JADX)
        # This does NOT block the response — decompiled source appears in the UI
        # once the background task completes (usually 1-3 min for large APKs)
        _run_decompilation_background(tmp_path, ref.apk_id)

        return result
    except Exception as exc:
        logger.exception("Analysis failed for %s: %s", ref.apk_id, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return _stub_result(ref.apk_id)


def _stub_result(apk_id: str) -> dict:
    """
    Returned when MinIO fetch fails or analysis crashes.
    MUST be a neutral/empty result — never fake malware signals.
    A Hello World APK that fails to analyze should NOT score 85.
    """
    return {
        "apk_id": apk_id,
        "_stub": True,
        "_stub_reason": "Analysis unavailable — APK could not be fetched or parsed",
        "permissions": [],
        "dangerous_permission_count": 0,
        "manifest": {"package_name": "unknown", "min_sdk": "unknown", "target_sdk": "unknown"},
        "suspicious_apis": [],
        "obfuscation_detected": False,
        "dynamic_code_loading": False,
        "hardcoded_urls": [],
        "hardcoded_ips": [],
        "yara_matches": [],
        "risk_indicator_count": 0,
        "iocs": {"domains": [], "ips": []},
        "quark_crime_count": 0,
        "quark_max_confidence": 0.0,
        "quark_avg_confidence": 0.0,
        "quark_banking_crime": False,
        "quark_sms_crime": False,
        "quark_crimes": [],
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "static-analysis"}
