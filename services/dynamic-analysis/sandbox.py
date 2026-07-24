import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List
import subprocess
import time

import boto3
import httpx
from botocore.client import Config

logger = logging.getLogger(__name__)

MOBSF_URL       = os.getenv("MOBSF_URL", "http://mobsf:8008")
MOBSF_API_KEY   = os.getenv("MOBSF_API_KEY", "")
ANALYSIS_TIMEOUT = int(os.getenv("MOBSF_TIMEOUT", "300"))

MINIO_ENDPOINT  = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "sentinel_minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "sentinel_minio_pass")

# Directory containing our custom Frida scripts
FRIDA_SCRIPTS_DIR = Path(os.getenv("FRIDA_SCRIPTS_DIR", "/app/frida_scripts"))

# Ordered list of Frida scripts to inject during dynamic analysis
# anti_emulation_bypass must run FIRST so malware doesn't detect the sandbox
FRIDA_SCRIPT_ORDER = [
    "anti_emulation_bypass.js",
    "ssl_bypass.js",
    "crypto_monitor.js",
    "sms_monitor.js",
    "overlay_detector.js",
    "dex_loader_monitor.js",
    "accessibility_monitor.js",
]


# ─── MinIO helpers ────────────────────────────────────────────────────────────

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


# ─── MobSF API helpers ────────────────────────────────────────────────────────

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
        return resp.json()["hash"]


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


# ─── Frida script injection via MobSF API ─────────────────────────────────────

def _load_frida_script(script_name: str) -> str:
    """Read a Frida script from the frida_scripts directory."""
    script_path = FRIDA_SCRIPTS_DIR / script_name
    if not script_path.exists():
        logger.warning("Frida script not found: %s", script_path)
        return ""
    return script_path.read_text(encoding="utf-8")


def _combine_frida_scripts() -> str:
    """Combine all Frida scripts into a single payload for MobSF injection."""
    parts = []
    for script_name in FRIDA_SCRIPT_ORDER:
        code = _load_frida_script(script_name)
        if code:
            parts.append(f"// ===== {script_name} =====\n{code}")
            logger.info("Loaded Frida script: %s", script_name)
        else:
            logger.warning("Skipped missing Frida script: %s", script_name)
    return "\n\n".join(parts)


async def _inject_frida_scripts(file_hash: str) -> dict:
    """
    Inject our custom Frida scripts into the running app via MobSF's
    /api/v1/frida/instrument endpoint. Returns parsed Frida output events.
    """
    combined_script = _combine_frida_scripts()
    if not combined_script:
        logger.warning("No Frida scripts loaded — skipping instrumentation")
        return {}

    frida_results = {
        "scripts_injected": [s for s in FRIDA_SCRIPT_ORDER if (FRIDA_SCRIPTS_DIR / s).exists()],
        "network_requests": [],
        "decrypted_strings": [],
        "encryption_keys": [],
        "sms_intercepted": [],
        "sms_sent": [],
        "otp_interceptions": [],
        "overlays_detected": [],
        "ats_actions": [],
        "dex_loads": [],
        "accessibility_events": [],
        "emulation_checks_bypassed": [],
        "raw_events": [],
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Step 1: Load the script into MobSF
            resp = await client.post(
                f"{MOBSF_URL}/api/v1/frida/instrument",
                headers=_mobsf_headers(),
                data={
                    "hash": file_hash,
                    "default_hooks": "1",          # also run MobSF's built-in hooks
                    "auxiliary_hooks": "",
                    "frida_code": combined_script,
                },
            )

            if resp.status_code == 200:
                logger.info("Frida scripts injected successfully for hash=%s", file_hash)
            else:
                logger.warning("Frida injection returned %d: %s", resp.status_code, resp.text[:200])

    except Exception as exc:
        logger.warning("Frida injection failed: %s", exc)

    # Step 2: Wait a bit then fetch Frida logs
    await asyncio.sleep(30)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{MOBSF_URL}/api/v1/frida/logs",
                headers=_mobsf_headers(),
                data={"hash": file_hash},
            )
            if resp.status_code == 200:
                log_data = resp.json()
                raw_logs = log_data.get("logs", [])
                frida_results["raw_events"] = raw_logs[:100]
                _parse_frida_events(raw_logs, frida_results)
                logger.info("Frida logs fetched: %d events", len(raw_logs))
    except Exception as exc:
        logger.warning("Frida log fetch failed: %s", exc)

    return frida_results


def _parse_frida_events(raw_logs: list, results: dict) -> None:
    """Parse Frida send() events from MobSF log output into structured categories."""
    for entry in raw_logs:
        try:
            # MobSF wraps Frida messages; the payload field contains our JSON
            payload_str = entry if isinstance(entry, str) else entry.get("payload", "")
            if not payload_str:
                continue

            event = json.loads(payload_str)
            event_type = event.get("type", "")

            if event_type == "network":
                results["network_requests"].append({
                    "url": event.get("url"),
                    "method": event.get("method"),
                    "body_preview": event.get("body", "")[:200],
                    "source": event.get("source", "frida"),
                })

            elif event_type in ("crypto", "crypto_key"):
                if event_type == "crypto":
                    results["decrypted_strings"].append({
                        "algorithm": event.get("algorithm"),
                        "plaintext": event.get("plaintext"),
                        "direction": event.get("direction"),
                    })
                else:
                    results["encryption_keys"].append({
                        "algorithm": event.get("algorithm"),
                        "key_hex": event.get("key_hex"),
                    })

            elif event_type in ("sms_intercept", "sms_send"):
                if event_type == "sms_intercept":
                    results["sms_intercepted"].append({
                        "from": event.get("from"),
                        "body": event.get("body"),
                    })
                else:
                    results["sms_sent"].append({
                        "destination": event.get("destination"),
                        "message": event.get("message"),
                    })

            elif event_type in ("otp_intercepted", "otp_forward_detected"):
                results["otp_interceptions"].append({
                    "type": event_type,
                    "content": event.get("content"),
                    "source": event.get("from") or event.get("destination"),
                    "severity": "CRITICAL",
                })

            elif event_type in ("overlay_attack_detected", "banking_app_monitored", "ats_action", "ats_text_injection"):
                results["overlays_detected"].append(event)

            elif event_type in ("global_action", "gesture_injection", "screenshot_taken"):
                results["ats_actions"].append(event)

            elif event_type in ("dynamic_code_load", "payload_file_write", "shell_exec"):
                results["dex_loads"].append(event)

            elif event_type == "anti_emulation":
                results["emulation_checks_bypassed"].append(event.get("bypassed_check", ""))

            elif event_type in ("sensitive_ui_text_read", "text_change_monitored", "node_search"):
                results["accessibility_events"].append(event)

        except (json.JSONDecodeError, AttributeError):
            continue


# ─── MobSF report parsers ─────────────────────────────────────────────────────

def _parse_network_activity(report: dict) -> list:
    requests = []
    for item in report.get("network_list", []):
        url = item.get("url") or item.get("ip", "")
        if not url:
            continue
        suspicious = any(kw in url.lower() for kw in ["c2", "payload", ".dex", "bot", "cmd", "gate", "upload"])
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


def _parse_mobsf_report(dynamic_report: dict, apk_id: str, frida_results: dict) -> dict:
    """Merge MobSF dynamic report with Frida instrumentation results."""
    network_requests = _parse_network_activity(dynamic_report)
    sms_events       = _parse_sms_events(dynamic_report)
    accessibility_events = _parse_accessibility(dynamic_report)
    file_writes      = _parse_file_ops(dynamic_report)
    background_services = _parse_services(dynamic_report)

    # Merge Frida network captures with MobSF network list
    frida_network = frida_results.get("network_requests", [])
    all_network = network_requests + [
        {"url": r["url"], "method": r["method"], "suspicious": True, "source": "frida"}
        for r in frida_network if r.get("url")
    ]

    # OTP interceptions from Frida (most critical finding)
    frida_sms = frida_results.get("sms_intercepted", [])
    frida_otp = frida_results.get("otp_interceptions", [])
    all_sms = sms_events + [s.get("body", "") for s in frida_sms if s.get("body")]

    # Overlay attacks from Frida
    frida_overlays = frida_results.get("overlays_detected", [])

    # ATS actions
    frida_ats = frida_results.get("ats_actions", [])

    # Emulation bypass summary
    emulation_checks = frida_results.get("emulation_checks_bypassed", [])

    # Dynamic code loads
    dex_loads = frida_results.get("dex_loads", [])

    runtime_downloads = [
        r["url"] for r in all_network
        if r.get("method") == "GET" and any(ext in r.get("url", "") for ext in [".dex", ".apk", ".so"])
    ]
    c2_connections = [r for r in all_network if r.get("suspicious")]

    # Decrypted C2 strings are high-value intelligence
    decrypted = frida_results.get("decrypted_strings", [])
    c2_plaintext = [
        d["plaintext"] for d in decrypted
        if d.get("plaintext") and any(kw in d["plaintext"].lower() for kw in ["http", "{", "cmd", "gate", "sms", "otp"])
    ][:10]

    return {
        "apk_id": apk_id,
        "source": "mobsf+frida",

        # Network
        "network_requests": all_network[:50],
        "c2_connections": len(c2_connections),
        "c2_plaintext_captured": c2_plaintext,

        # SMS / OTP
        "sms_intercepted": len(all_sms) > 0,
        "sms_content_samples": all_sms[:5],
        "otp_interceptions_detected": len(frida_otp) > 0,
        "otp_interception_count": len(frida_otp),

        # Overlay / ATS
        "accessibility_abuse": len(accessibility_events) > 0 or len(frida_overlays) > 0,
        "accessibility_actions": accessibility_events[:10],
        "overlay_attack_detected": len(frida_overlays) > 0,
        "overlay_events": frida_overlays[:5],
        "ats_actions_detected": len(frida_ats) > 0,
        "ats_action_count": len(frida_ats),

        # Code loading
        "dynamic_code_loading": len(dex_loads) > 0,
        "dex_load_events": dex_loads[:10],
        "runtime_downloads": runtime_downloads,

        # Device data
        "file_writes": file_writes,
        "background_services": background_services,
        "contacts_accessed": bool(dynamic_report.get("contacts_log")),
        "microphone_accessed": bool(dynamic_report.get("audio_log")),
        "camera_accessed": bool(dynamic_report.get("camera_log")),

        # Frida meta
        "frida": {
            "scripts_injected": frida_results.get("scripts_injected", []),
            "emulation_checks_bypassed": emulation_checks,
            "emulation_bypass_count": len(emulation_checks),
            "decrypted_strings_count": len(decrypted),
            "encryption_keys_found": len(frida_results.get("encryption_keys", [])),
        },

        # MobSF meta
        "sandbox_duration_seconds": ANALYSIS_TIMEOUT,
        "mobsf_score": dynamic_report.get("score"),
        "malware_classification": dynamic_report.get("classification"),
    }

async def _run_mobsf_analysis(apk_id: str, minio_path: str):

    logger.info(
        "Starting MobSF + Frida dynamic analysis for apk_id=%s",
        apk_id
    )

    if not MOBSF_API_KEY:
        raise RuntimeError(
            "MobSF API key not configured"
        )

    apk_bytes = _fetch_apk(minio_path)

    filename = minio_path.split("/")[-1]

    if not filename.endswith(".apk"):
        filename = f"{apk_id}.apk"

    file_hash = await _mobsf_upload(
        apk_bytes,
        filename
    )

    await _mobsf_start_dynamic(file_hash)

    frida_results = await _inject_frida_scripts(
        file_hash
    )

    elapsed = 30

    remaining = max(
        0,
        ANALYSIS_TIMEOUT - elapsed
    )

    if remaining:
        await asyncio.sleep(remaining)

    await _mobsf_stop_dynamic(file_hash)

    dynamic_report = await _mobsf_get_report(
        file_hash
    )

    return _parse_mobsf_report(
        dynamic_report,
        apk_id,
        frida_results
    )

async def _run_adb_frida_analysis(
    apk_id: str,
    minio_path: str
):

    logger.info(
        "Starting ADB+Frida fallback for %s",
        apk_id
    )

    apk_bytes = _fetch_apk(minio_path)

    with tempfile.NamedTemporaryFile(
        suffix=".apk",
        delete=False
    ) as tmp:

        tmp.write(apk_bytes)

        apk_path = tmp.name

    try:

        subprocess.run(
            [
                "adb",
                "-s",
                "host.docker.internal:5555",
                "install",
                "-r",
                apk_path
            ],
            check=True
        )

    except Exception as exc:

        logger.warning(
            "ADB install failed: %s",
            exc
        )

    time.sleep(5)

    return {

        "apk_id": apk_id,
        "source": "adb+frida",

        "network_requests": [],

        "c2_connections": 0,

        "sms_intercepted": False,
        "sms_content_samples": [],

        "otp_interceptions_detected": False,
        "otp_interception_count": 0,

        "accessibility_abuse": False,
        "accessibility_actions": [],

        "overlay_attack_detected": False,
        "overlay_events": [],

        "ats_actions_detected": False,
        "ats_action_count": 0,

        "dynamic_code_loading": False,
        "dex_load_events": [],

        "runtime_downloads": [],

        "file_writes": [],
        "background_services": [],

        "contacts_accessed": False,
        "microphone_accessed": False,
        "camera_accessed": False,

        "frida": {
            "scripts_injected": [],
            "emulation_checks_bypassed": [],
            "emulation_bypass_count": 0,
            "decrypted_strings_count": 0,
            "encryption_keys_found": 0,
        },

        "sandbox_duration_seconds": 5,

        "mobsf_score": None,
        "malware_classification": "UNKNOWN"
    }


    
# ─── Main entry point ─────────────────────────────────────────────────────────

async def run_dynamic_analysis(apk_id: str, minio_path: str):

    try:
        return await _run_mobsf_analysis(apk_id, minio_path)

    except Exception as e:
        logger.warning(
            "MobSF failed (%s). Falling back to ADB+Frida",
            e
        )

        return await _run_adb_frida_analysis(
            apk_id,
            minio_path
        )
