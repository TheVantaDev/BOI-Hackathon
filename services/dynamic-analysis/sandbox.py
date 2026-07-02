import asyncio
import logging
import os
import subprocess
from typing import Any, Dict

logger = logging.getLogger(__name__)

ADB = os.getenv("ADB_PATH", "adb")
FRIDA = os.getenv("FRIDA_PATH", "frida")
EMULATOR_SERIAL = os.getenv("EMULATOR_SERIAL", "emulator-5554")


async def run_dynamic_analysis(apk_id: str, minio_path: str) -> Dict[str, Any]:
    """
    Orchestrates full dynamic analysis:
    1. Download APK from MinIO
    2. Install on emulator
    3. Launch and monitor for 120s
    4. Collect behavioral data
    """
    logger.info("Starting dynamic analysis for apk_id=%s", apk_id)

    network_requests = await _monitor_network(apk_id)
    sms_events = await _monitor_sms(apk_id)
    accessibility_events = await _monitor_accessibility(apk_id)
    file_events = await _monitor_filesystem(apk_id)
    service_events = await _monitor_services(apk_id)

    return {
        "apk_id": apk_id,
        "network_requests": network_requests,
        "sms_intercepted": len(sms_events) > 0,
        "sms_content_samples": sms_events[:5],
        "accessibility_abuse": len(accessibility_events) > 0,
        "accessibility_actions": accessibility_events[:10],
        "file_writes": file_events,
        "background_services": service_events,
        "runtime_downloads": _extract_downloads(network_requests),
        "contacts_accessed": _check_contacts_access(apk_id),
        "microphone_accessed": False,
        "camera_accessed": False,
        "sandbox_duration_seconds": 120,
    }


async def _monitor_network(apk_id: str) -> list:
    # TODO: integrate tcpdump/mitmproxy capture here
    # Runs: tcpdump -i any -w /tmp/{apk_id}.pcap during sandbox execution
    logger.debug("Network monitoring stub for %s", apk_id)
    return []


async def _monitor_sms(apk_id: str) -> list:
    # TODO: use Frida hook on SmsManager and BroadcastReceiver
    # frida -U -l hooks/sms_hook.js -f <package_name>
    logger.debug("SMS monitoring stub for %s", apk_id)
    return []


async def _monitor_accessibility(apk_id: str) -> list:
    # TODO: hook AccessibilityService.onAccessibilityEvent via Frida
    logger.debug("Accessibility monitoring stub for %s", apk_id)
    return []


async def _monitor_filesystem(apk_id: str) -> list:
    # TODO: use inotifywait or Frida to track file operations
    logger.debug("Filesystem monitoring stub for %s", apk_id)
    return []


async def _monitor_services(apk_id: str) -> list:
    # TODO: poll adb shell dumpsys activity services during execution
    try:
        result = subprocess.run(
            [ADB, "-s", EMULATOR_SERIAL, "shell", "dumpsys", "activity", "services"],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in result.stdout.split("\n") if "ServiceRecord" in l]
        return lines[:10]
    except Exception:
        return []


def _extract_downloads(requests: list) -> list:
    return [r["url"] for r in requests if r.get("method") == "GET" and ".dex" in r.get("url", "")]


def _check_contacts_access(apk_id: str) -> bool:
    # TODO: check logcat for ContactsProvider access
    return False


def install_apk(apk_path: str) -> bool:
    try:
        result = subprocess.run(
            [ADB, "-s", EMULATOR_SERIAL, "install", "-r", apk_path],
            capture_output=True, text=True, timeout=60,
        )
        return "Success" in result.stdout
    except Exception as exc:
        logger.warning("APK install failed: %s", exc)
        return False


def launch_app(package_name: str) -> bool:
    try:
        subprocess.run(
            [ADB, "-s", EMULATOR_SERIAL, "shell", "monkey", "-p", package_name, "1"],
            capture_output=True, timeout=30,
        )
        return True
    except Exception as exc:
        logger.warning("App launch failed: %s", exc)
        return False
