import asyncio
import io
import logging
import os
import tempfile
from typing import Any, Dict

import boto3
import httpx
from botocore.client import Config

logger = logging.getLogger(__name__)

MOBSF_URL = os.getenv("MOBSF_URL", "http://mobsf:8008")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")
ANALYSIS_TIMEOUT = int(os.getenv("MOBSF_TIMEOUT", "300"))

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "sentinel_minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "sentinel_minio_pass")


def _minio_client():
    return boto3.client(
        "s3",
        endpoint_url=f"http://{MINIO_ENDPOINT}",
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def _fetch_apk(minio_path: str) -> bytes:
    client = _minio_client()
    bucket, key = minio_path.split("/", 1)
    return client.get_object(Bucket=bucket, Key=key)["Body"].read()


def _mobsf_headers() -> dict:
    return {"Authorization": MOBSF_API_KEY}


async def _mobsf_upload(apk_bytes: bytes, filename: str) -> str:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/upload",
            headers=_mobsf_headers(),
            files={"file": (filename, apk_bytes, "application/octet-stream")},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["hash"]


async def _mobsf_start_dynamic(file_hash: str) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/dynamic/start_analysis",
            headers=_mobsf_headers(),
            data={"hash": file_hash},
        )
        resp.raise_for_status()


async def _mobsf_stop_dynamic(file_hash: str) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/dynamic/stop_analysis",
            headers=_mobsf_headers(),
            data={"hash": file_hash},
        )
        resp.raise_for_status()


async def _mobsf_get_report(file_hash: str) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/dynamic/report_json",
            headers=_mobsf_headers(),
            data={"hash": file_hash},
        )
        resp.raise_for_status()
        return resp.json()


async def _mobsf_static_report(file_hash: str) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/report_json",
            headers=_mobsf_headers(),
            data={"hash": file_hash},
        )
        resp.raise_for_status()
        return resp.json()


def _parse_network_activity(report: dict) -> list:
    requests = []
    for item in report.get("network_list", []):
        url = item.get("url") or item.get("ip", "")
        if not url:
            continue
        suspicious = any(kw in url.lower() for kw in ["c2", "payload", ".dex", "bot", "cmd"])
        requests.append({
            "url": url,
            "method": item.get("method", "GET"),
            "suspicious": suspicious,
            "bytes_sent": item.get("bytes_sent", 0),
        })
    return requests


def _parse_sms_events(report: dict) -> list:
    sms = []
    for item in report.get("sms", []):
        body = item.get("body") or item.get("message", "")
        if body:
            sms.append(body)
    return sms


def _parse_accessibility(report: dict) -> list:
    events = []
    for item in report.get("accessibility_events", []):
        action = item.get("action") or item.get("event_type", "")
        if action:
            events.append(action)
    return events


def _parse_file_ops(report: dict) -> list:
    files = []
    for item in report.get("file_log", []):
        path = item.get("path") or item.get("file", "")
        op = item.get("operation", "write")
        if path and op in ("write", "create", "delete"):
            files.append(path)
    return list(set(files))[:20]


def _parse_services(report: dict) -> list:
    services = []
    for item in report.get("services", []):
        name = item.get("name") or item.get("service", "")
        if name:
            services.append(name)
    return services[:10]


def _parse_mobsf_report(dynamic_report: dict, apk_id: str) -> dict:
    network_requests = _parse_network_activity(dynamic_report)
    sms_events = _parse_sms_events(dynamic_report)
    accessibility_events = _parse_accessibility(dynamic_report)
    file_writes = _parse_file_ops(dynamic_report)
    background_services = _parse_services(dynamic_report)

    runtime_downloads = [
        r["url"] for r in network_requests
        if r.get("method") == "GET" and any(ext in r.get("url", "") for ext in [".dex", ".apk", ".so"])
    ]

    c2_connections = [r for r in network_requests if r.get("suspicious")]

    return {
        "apk_id": apk_id,
        "source": "mobsf",
        "network_requests": network_requests,
        "c2_connections": len(c2_connections),
        "sms_intercepted": len(sms_events) > 0,
        "sms_content_samples": sms_events[:5],
        "accessibility_abuse": len(accessibility_events) > 0,
        "accessibility_actions": accessibility_events[:10],
        "file_writes": file_writes,
        "background_services": background_services,
        "runtime_downloads": runtime_downloads,
        "contacts_accessed": bool(dynamic_report.get("contacts_log")),
        "microphone_accessed": bool(dynamic_report.get("audio_log")),
        "camera_accessed": bool(dynamic_report.get("camera_log")),
        "sandbox_duration_seconds": ANALYSIS_TIMEOUT,
        "mobsf_score": dynamic_report.get("score"),
        "malware_classification": dynamic_report.get("classification"),
    }


async def run_dynamic_analysis(apk_id: str, minio_path: str) -> Dict[str, Any]:
    logger.info("Starting MobSF dynamic analysis for apk_id=%s", apk_id)

    if not MOBSF_API_KEY:
        logger.warning("MOBSF_API_KEY not set — skipping dynamic analysis")
        raise RuntimeError("MobSF API key not configured")

    apk_bytes = _fetch_apk(minio_path)
    filename = minio_path.split("/")[-1]
    if not filename.endswith(".apk"):
        filename = f"{apk_id}.apk"

    file_hash = await _mobsf_upload(apk_bytes, filename)
    logger.info("MobSF upload complete, hash=%s", file_hash)

    await _mobsf_start_dynamic(file_hash)
    logger.info("MobSF dynamic analysis started, waiting %ds", ANALYSIS_TIMEOUT)

    await asyncio.sleep(ANALYSIS_TIMEOUT)

    await _mobsf_stop_dynamic(file_hash)
    logger.info("MobSF dynamic analysis stopped, fetching report")

    dynamic_report = await _mobsf_get_report(file_hash)
    return _parse_mobsf_report(dynamic_report, apk_id)
