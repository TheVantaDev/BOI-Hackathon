import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "RECORD_AUDIO", "CAMERA",
    "READ_CALL_LOG", "WRITE_CALL_LOG",
    "PROCESS_OUTGOING_CALLS",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "GET_ACCOUNTS", "USE_CREDENTIALS",
    "SYSTEM_ALERT_WINDOW",
    "RECEIVE_BOOT_COMPLETED",
    "PACKAGE_USAGE_STATS",
    "REQUEST_INSTALL_PACKAGES",
}

SUSPICIOUS_APIS = [
    "getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber",
    "sendTextMessage", "sendMultipartTextMessage",
    "execCommand", "Runtime.getRuntime",
    "DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader",
    "AccessibilityService", "performGlobalAction",
    "getInstalledPackages", "getInstalledApplications",
    "Cipher.getInstance", "SecretKeySpec",
    "Base64.decode", "getDeclaredMethod",
]


def _parse_apk(apk_path: str) -> Tuple:
    from androguard.misc import AnalyzeAPK
    return AnalyzeAPK(apk_path)


def extract_permissions(a) -> List[Dict]:
    try:
        permissions = []
        for perm in a.get_permissions():
            short = perm.split(".")[-1]
            permissions.append({
                "name": short,
                "full": perm,
                "dangerous": short in DANGEROUS_PERMISSIONS,
            })
        return permissions
    except Exception as exc:
        logger.warning("Permission extraction failed: %s", exc)
        return []


def extract_manifest_info(a) -> Dict:
    try:
        return {
            "package_name": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "activities": [str(x) for x in a.get_activities()],
            "services": [str(x) for x in a.get_services()],
            "receivers": [str(x) for x in a.get_receivers()],
        }
    except Exception as exc:
        logger.warning("Manifest extraction failed: %s", exc)
        return {}


def detect_suspicious_apis(dx) -> List[str]:
    found = set()
    try:
        for method in dx.get_methods():
            src = str(method.get_method())
            for api in SUSPICIOUS_APIS:
                if api in src:
                    found.add(api)
    except Exception as exc:
        logger.warning("API detection failed: %s", exc)
    return list(found)


def check_obfuscation(dx) -> bool:
    try:
        short_names, total = 0, 0
        for cls in dx.get_classes():
            name = cls.get_vm_class().get_name().split("/")[-1].strip(";")
            total += 1
            if len(name) <= 2 and name.isalpha():
                short_names += 1
        return total > 0 and (short_names / total) > 0.3
    except Exception:
        return False


def detect_dynamic_code_loading(dx) -> bool:
    loaders = {"DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader"}
    try:
        for method in dx.get_methods():
            method_str = str(method.get_method())
            if any(loader in method_str for loader in loaders):
                return True
    except Exception:
        pass
    return False


def extract_strings(a, d) -> Dict:
    urls, ips = [], []
    url_re = re.compile(r'https?://[^\s"\'<>]{8,}')
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    try:
        for dex in d:
            for s in dex.get_strings():
                text = str(s)
                urls += url_re.findall(text)
                ips += ip_re.findall(text)
    except Exception as exc:
        logger.warning("String extraction failed: %s", exc)
    return {
        "hardcoded_urls": list(set(urls))[:30],
        "hardcoded_ips": list(set(ips))[:20],
    }


def run_yara_scan(apk_path: str, rules_dir: str) -> List[str]:
    matches = []
    try:
        import yara
        for rule_file in Path(rules_dir).glob("*.yar"):
            rules = yara.compile(str(rule_file))
            matches.extend(str(m) for m in rules.match(apk_path))
    except Exception as exc:
        logger.warning("YARA scan failed: %s", exc)
    return matches


def analyze_apk(apk_path: str, rules_dir: str = "/app/rules") -> Dict:
    try:
        a, d, dx = _parse_apk(apk_path)
    except Exception as exc:
        logger.error("APK parsing failed: %s", exc)
        return {
            "permissions": [], "dangerous_permission_count": 0,
            "manifest": {}, "suspicious_apis": [],
            "obfuscation_detected": False, "dynamic_code_loading": False,
            "hardcoded_urls": [], "hardcoded_ips": [],
            "yara_matches": [], "risk_indicator_count": 0,
            "iocs": {"domains": [], "ips": []},
        }

    permissions = extract_permissions(a)
    manifest = extract_manifest_info(a)
    suspicious_apis = detect_suspicious_apis(dx)
    obfuscated = check_obfuscation(dx)
    dynamic_loading = detect_dynamic_code_loading(dx)
    strings = extract_strings(a, d)
    yara_matches = run_yara_scan(apk_path, rules_dir)

    dangerous = [p for p in permissions if p["dangerous"]]
    risk_score = len(dangerous) + len(suspicious_apis) + len(yara_matches) * 3
    if obfuscated:
        risk_score += 5
    if dynamic_loading:
        risk_score += 4

    return {
        "permissions": permissions,
        "dangerous_permission_count": len(dangerous),
        "manifest": manifest,
        "suspicious_apis": suspicious_apis,
        "obfuscation_detected": obfuscated,
        "dynamic_code_loading": dynamic_loading,
        "hardcoded_urls": strings["hardcoded_urls"],
        "hardcoded_ips": strings["hardcoded_ips"],
        "yara_matches": yara_matches,
        "risk_indicator_count": risk_score,
        "iocs": {
            "domains": list({u.split("/")[2] for u in strings["hardcoded_urls"] if "://" in u}),
            "ips": strings["hardcoded_ips"],
        },
    }


def decompile_apk(apk_path: str, apk_id: str) -> tuple:
    results = {}

    temp_dir = Path(tempfile.mkdtemp(prefix=f"decompile_{apk_id}_"))

    apktool_out = temp_dir / "apktool_out"
    jadx_out = temp_dir / "jadx_out"

    apktool_out.mkdir(parents=True, exist_ok=True)
    jadx_out.mkdir(parents=True, exist_ok=True)

    try:
        logger.info("Running APKTool for apk_id=%s", apk_id)
        apktool_proc = subprocess.run(
            ["java", "-jar", "/usr/local/bin/apktool.jar", "d", apk_path, "-o", str(apktool_out), "-f"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if apktool_proc.returncode != 0:
            logger.warning("APKTool failed for %s: %s", apk_id, apktool_proc.stderr)
        else:
            logger.info("APKTool finished successfully for apk_id=%s", apk_id)
            apktool_zip = shutil.make_archive(str(temp_dir / f"{apk_id}_apktool"), "zip", apktool_out)
            results["apktool_zip"] = apktool_zip
    except Exception as exc:
        logger.exception("Exception running APKTool for %s: %s", apk_id, exc)

    try:
        logger.info("Running JADX for apk_id=%s", apk_id)
        jadx_proc = subprocess.run(
            ["jadx", "-d", str(jadx_out), apk_path, "--no-res"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if jadx_proc.returncode != 0:
            logger.warning("JADX failed for %s: %s", apk_id, jadx_proc.stderr)
        else:
            logger.info("JADX finished successfully for apk_id=%s", apk_id)
            jadx_zip = shutil.make_archive(str(temp_dir / f"{apk_id}_jadx"), "zip", jadx_out)
            results["jadx_zip"] = jadx_zip
    except Exception as exc:
        logger.exception("Exception running JADX for %s: %s", apk_id, exc)

    return results, temp_dir
