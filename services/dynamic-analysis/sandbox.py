import asyncio
import hashlib
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

MOBSF_URL       = os.getenv("MOBSF_URL", "http://mobsf:8000")
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


async def _mobsf_scan(file_hash: str) -> None:
    """Run MobSF static scan to populate MobSF database before starting dynamic analysis."""
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{MOBSF_URL}/api/v1/scan",
            headers=_mobsf_headers(),
            data={"hash": file_hash},
        )
        resp.raise_for_status()


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

            elif event_type in ("sms_intercept", "sms_send", "sms_multipart_send"):
                # NOTE: "sms_multipart_send" was previously unhandled — banking trojans
                # often use sendMultipartTextMessage to forward long OTP exfil messages.
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

            # --- Previously unhandled event types from crypto_monitor.js and dex_loader_monitor.js ---
            elif event_type == "base64_decode":
                results["decrypted_strings"].append({
                    "algorithm": "base64",
                    "plaintext": event.get("decoded"),
                    "direction": "decoded",
                })

            elif event_type == "decoded_string":
                results["decrypted_strings"].append({
                    "algorithm": "string_decode",
                    "plaintext": event.get("value"),
                    "direction": "decoded",
                })

            elif event_type == "reflection_class_load":
                # Suspicious reflection calls (non-system classes) from dex_loader_monitor
                results["dex_loads"].append({
                    "type": "reflection_class_load",
                    "class_name": event.get("class_name"),
                })

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

async def _run_mobsf_analysis(apk_id: str, minio_path: str, sha256: str = ""):

    logger.info(
        "Starting MobSF + Frida dynamic analysis for apk_id=%s",
        apk_id
    )

    if not MOBSF_API_KEY:
        raise RuntimeError(
            "MobSF API key not configured"
        )

    apk_bytes = _fetch_apk(minio_path)

    # Verify APK integrity against expected SHA-256 to detect MinIO swap attacks.
    if sha256:
        actual_sha256 = hashlib.sha256(apk_bytes).hexdigest()
        if actual_sha256.lower() != sha256.lower():
            raise RuntimeError(
                f"SHA-256 mismatch for apk_id={apk_id}: "
                f"expected={sha256}, got={actual_sha256}"
            )
        logger.info("SHA-256 verified for apk_id=%s", apk_id)

    filename = minio_path.split("/")[-1]

    if not filename.endswith(".apk"):
        filename = f"{apk_id}.apk"

    file_hash = await _mobsf_upload(
        apk_bytes,
        filename
    )

    await _mobsf_scan(file_hash)

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
    minio_path: str,
    sha256: str = "",
):
    logger.info("Starting ADB + Frida dynamic fallback execution for %s", apk_id)
    apk_bytes = _fetch_apk(minio_path)

    # Verify integrity if SHA-256 was provided
    if sha256:
        actual_sha256 = hashlib.sha256(apk_bytes).hexdigest()
        if actual_sha256.lower() != sha256.lower():
            raise RuntimeError(
                f"SHA-256 mismatch for apk_id={apk_id}: "
                f"expected={sha256}, got={actual_sha256}"
            )
        logger.info("SHA-256 verified for apk_id=%s", apk_id)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_bytes)
        apk_path = tmp.name

    installed_pkg = None
    sms_found = False
    overlay_found = False
    accessibility_found = False
    frida_injected = False

    try:
        # Ensure ADB daemon in container is connected to host emulator
        subprocess.run(
            ["adb", "connect", "host.docker.internal:5555"],
            capture_output=True, timeout=10
        )

        # Get list of installed packages before
        proc1 = subprocess.run(
            ["adb", "-s", "host.docker.internal:5555", "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True, timeout=10
        )
        pkgs_before = set(proc1.stdout.strip().splitlines())

        # Install APK onto live emulator
        logger.info("Installing APK onto emulator via ADB: %s", apk_path)
        subprocess.run(
            ["adb", "-s", "host.docker.internal:5555", "install", "-r", apk_path],
            check=True, capture_output=True, timeout=30
        )

        # Get list of installed packages after
        proc2 = subprocess.run(
            ["adb", "-s", "host.docker.internal:5555", "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True, timeout=10
        )
        pkgs_after = set(proc2.stdout.strip().splitlines())
        new_pkgs = pkgs_after - pkgs_before

        if new_pkgs:
            installed_pkg = list(new_pkgs)[0].replace("package:", "").strip()

        if installed_pkg:
            logger.info("Launching installed package on emulator via monkey: %s", installed_pkg)
            subprocess.run(
                ["adb", "-s", "host.docker.internal:5555", "shell", "monkey", "-p", installed_pkg,
                 "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=10
            )

            # Give the app 3 seconds to start before attaching Frida
            time.sleep(3)

            # --- Inject Frida scripts via frida CLI ---
            # Write combined Frida script to a temp file so frida CLI can load it
            combined_script = _combine_frida_scripts()
            if combined_script:
                with tempfile.NamedTemporaryFile(
                    suffix=".js", delete=False, mode="w", encoding="utf-8"
                ) as script_tmp:
                    script_tmp.write(combined_script)
                    script_path = script_tmp.name
                try:
                    logger.info(
                        "Injecting Frida scripts into %s on emulator", installed_pkg
                    )
                    subprocess.run(
                        [
                            "frida", "-U", "-l", script_path,
                            "-f", installed_pkg,
                            "--no-pause",
                            "--runtime=v8",
                        ],
                        capture_output=True, timeout=30
                    )
                    frida_injected = True
                    logger.info("Frida injection complete for %s", installed_pkg)
                except Exception as frida_exc:
                    logger.warning("Frida CLI injection failed: %s", frida_exc)
                finally:
                    try:
                        os.unlink(script_path)
                    except Exception:
                        pass

        # Capture logcat after Frida instrumentation window
        logcat_res = subprocess.run(
            ["adb", "-s", "host.docker.internal:5555", "logcat", "-d", "-t", "500"],
            capture_output=True, text=True, timeout=15
        )
        log_text = logcat_res.stdout or ""

        # Parse basic findings from logcat
        sms_found = any(k in log_text.lower() for k in ["sms", "otp", "telephony", "receiver"])
        overlay_found = any(k in log_text.lower() for k in ["overlay", "alert_window", "system_alert"])
        accessibility_found = any(k in log_text.lower() for k in ["accessibility", "accessibilityservice"])

    except Exception as exc:
        logger.warning("ADB install/launch fallback failed: %s", exc)
    finally:
        try:
            os.unlink(apk_path)
        except Exception:
            pass

    injected_scripts = FRIDA_SCRIPT_ORDER if frida_injected else []

    return {
        "apk_id": apk_id,
        "source": "adb+frida" if frida_injected else "adb_only",
        "installed_package": installed_pkg or "unknown",
        "network_requests": [],
        "c2_connections": 0,
        "sms_intercepted": sms_found,
        "sms_content_samples": ["Logcat telemetry captured from active emulator"] if sms_found else [],
        "otp_interceptions_detected": sms_found,
        "otp_interception_count": 1 if sms_found else 0,
        "accessibility_abuse": accessibility_found,
        "accessibility_actions": ["Accessibility service detected in logcat"] if accessibility_found else [],
        "overlay_attack_detected": overlay_found,
        "overlay_events": ["System alert overlay detected in logcat"] if overlay_found else [],
        "ats_actions_detected": False,
        "ats_action_count": 0,
        "dynamic_code_loading": False,
        "dex_load_events": [],
        "runtime_downloads": [],
        "file_writes": [],
        "background_services": [installed_pkg] if installed_pkg else [],
        "contacts_accessed": False,
        "microphone_accessed": False,
        "camera_accessed": False,
        "frida": {
            "scripts_injected": injected_scripts,
            "emulation_checks_bypassed": [],
            "emulation_bypass_count": 0,
            "decrypted_strings_count": 0,
            "encryption_keys_found": 0,
        },
        "sandbox_duration_seconds": 33,  # 3s startup + 30s frida window
        "mobsf_score": 100 if (sms_found or overlay_found) else 0,
        "malware_classification": "SUSPICIOUS" if (sms_found or overlay_found) else "BENIGN_LAUNCHED"
    }


    
# ─── Main entry point ─────────────────────────────────────────────────────────

async def run_dynamic_analysis(apk_id: str, minio_path: str, sha256: str = ""):

    try:
        return await _run_mobsf_analysis(apk_id, minio_path, sha256=sha256)

    except Exception as e:
        logger.warning(
            "MobSF failed (%s). Falling back to ADB+Frida",
            e
        )

        return await _run_adb_frida_analysis(
            apk_id,
            minio_path,
            sha256=sha256,
        )
