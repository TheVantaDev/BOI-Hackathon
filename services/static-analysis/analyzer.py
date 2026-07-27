import logging
import ipaddress
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
    # SYSTEM_ALERT_WINDOW intentionally excluded: used by many legitimate apps
    # (calculators, screen rulers, floating widgets). Real overlay attacks are
    # detected by the dynamic sandbox (overlay_attack_detected) and YARA rules.
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


def extract_all_api_classes(dx) -> List[str]:
    """
    Extract ALL class and method references the APK calls at the bytecode level.

    This is what the DREBIN dataset captured for each APK — the full set of
    referenced Android/Java classes and methods. We need the same signals at
    inference time so the model's 215 features can be matched correctly.

    Returns a list of normalised strings like:
      'android.telephony.SmsManager'
      'Runtime.exec'
      'DexClassLoader'
      'TelephonyManager.getDeviceId'
    """
    found = set()
    try:
        for cls in dx.get_classes():
            raw = cls.get_vm_class().get_name()   # e.g. "Landroid/telephony/SmsManager;"
            # Normalise Dalvik format → dotted Java name
            name = raw.lstrip("L").rstrip(";").replace("/", ".")
            if name.startswith("android.") or name.startswith("javax.") or \
               name.startswith("java.") or name.startswith("org."):
                found.add(name)                    # e.g. "android.telephony.SmsManager"
                short = name.split(".")[-1]         # e.g. "SmsManager"
                if len(short) > 3:
                    found.add(short)
    except Exception as exc:
        logger.warning("All-API class extraction failed: %s", exc)

    # Also walk method invocations to capture method-level DREBIN features
    # like Runtime.exec, TelephonyManager.getDeviceId
    try:
        for method in dx.get_methods():
            m = method.get_method()
            cls_name = str(m.get_class_name()).lstrip("L").rstrip(";").replace("/", ".")
            meth_name = str(m.get_name())
            short_cls = cls_name.split(".")[-1]
            if len(short_cls) > 3 and len(meth_name) > 2:
                # e.g. "TelephonyManager.getDeviceId"
                found.add(f"{short_cls}.{meth_name}")
                found.add(meth_name)   # bare method name: "getDeviceId"
    except Exception as exc:
        logger.warning("Method reference extraction failed: %s", exc)

    return list(found)


def extract_intent_actions(a) -> List[str]:
    """Extract intent action strings from the manifest (receivers, services)."""
    actions = set()
    try:
        for receiver in a.get_receivers():
            actions.add(str(receiver))
        for intent_filter in a.get_declared_permissions():
            actions.add(str(intent_filter))
    except Exception:
        pass
    return list(actions)


def _is_public_ip(ip_str: str) -> bool:
    """Return True only for globally routable IPs, filter out private/loopback/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )
    except ValueError:
        return False


# Known safe domains from legitimate ad SDKs, analytics, game engines, and CDNs.
# URLs matching these domains are excluded from hardcoded_url_count so that
# apps like Ludo, Candy Crush, etc. are not falsely flagged for embedding ad SDK URLs.
_SAFE_DOMAINS = {
    # Google / Firebase
    "googleapis.com", "gstatic.com", "google.com", "firebaseio.com",
    "firebase.google.com", "googletagmanager.com", "doubleclick.net",
    "googlesyndication.com", "googleadservices.com", "admob.com",
    # Facebook / Meta
    "facebook.com", "fbcdn.net", "instagram.com", "graph.facebook.com",
    "an.facebook.com",
    # Unity
    "unity3d.com", "unityads.unity3d.com", "unity.com",
    "dashboard.unity3d.com",
    # Ad Networks & Analytics
    "applovin.com", "mopub.com", "ironsrc.com", "startapp.com",
    "chartboost.com", "vungle.com", "adcolony.com", "inmobi.com",
    "tapjoy.com", "fyber.com", "mintegral.com",
    # Attribution / Analytics SDKs
    "adjust.com", "appsflyer.com", "branch.io", "kochava.com",
    "amplitude.com", "mixpanel.com", "segment.com", "clevertap.com",
    # App stores & CDN
    "play.google.com", "apple.com", "amazonaws.com", "cloudfront.net",
    "akamaihd.net", "fastly.net",
    # Crash reporting
    "crashlytics.com", "bugsnag.com", "sentry.io", "datadog.com",
}


def _is_safe_url(url: str) -> bool:
    """Return True if the URL belongs to a known safe ad/analytics/SDK domain."""
    try:
        # Extract hostname from URL (strip scheme and path)
        host = url.split("://", 1)[1].split("/")[0].lower().strip()
        # Remove port if present
        host = host.split(":")[0]
        # Check if host or any parent domain is in the safe list
        parts = host.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in _SAFE_DOMAINS:
                return True
    except Exception:
        pass
    return False


def extract_strings(a, d) -> Dict:
    urls, ips = [], []
    url_re = re.compile(r'https?://[^\s"\'<>]{8,}')
    # Restrict to valid dotted-quad IPs; filter private ranges below
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    try:
        for dex in d:
            for s in dex.get_strings():
                text = str(s)
                found_urls = url_re.findall(text)
                # Filter out known safe SDK/ad-network domains so games and
                # ad-supported apps don't get falsely flagged
                urls += [u for u in found_urls if not _is_safe_url(u)]
                # Only include publicly routable IPs — skip 127.x, 192.168.x, 0.0.0.0, etc.
                ips += [ip for ip in ip_re.findall(text) if _is_public_ip(ip)]
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


# Keywords used to identify high-risk banking/SMS crime descriptions from Quark rules
_BANKING_KEYWORDS = ["overlay", "phish", "banking", "credential", "login", "inject"]
_SMS_KEYWORDS     = ["sms", "otp", "text message", "intercept", "forward"]


def run_quark_analysis(apk_path: str) -> Dict:
    """
    Run QuarkEngine behavioral crime scoring on an APK.

    QuarkEngine uses Order Theory — it traces API call sequences at the Dalvik
    bytecode level to detect criminal behaviours (e.g. getDeviceId → sendTextMessage).
    This works even on obfuscated code and gives near-zero scores to benign apps
    like calculators that have permissions but no malicious API sequences.

    Returns a dict with:
      - quark_crime_count      : number of confirmed crimes (confidence >= 60%)
      - quark_max_confidence   : highest single crime confidence (0.0 – 1.0)
      - quark_avg_confidence   : average confidence across all detected crimes
      - quark_banking_crime    : True if any high-confidence banking-related crime
      - quark_sms_crime        : True if any high-confidence SMS/OTP-related crime
      - quark_crimes           : list of crime detail dicts for the report
    """
    result = {
        "quark_crime_count": 0,
        "quark_max_confidence": 0.0,
        "quark_avg_confidence": 0.0,
        "quark_banking_crime": False,
        "quark_sms_crime": False,
        "quark_crimes": [],
    }

    try:
        from quark.report import Report

        # QuarkEngine v26+ API: analysis(apk, rule) — one rule file at a time.
        # Rules are downloaded at build time by freshquark into ~/.quark/quark-rules/
        rules_dir = Path.home() / ".quark" / "quark-rules"

        if not rules_dir.exists() or not any(rules_dir.glob("*.json")):
            logger.warning("QuarkEngine: no rules found at %s — was freshquark run at build time?", rules_dir)
            return result

        # Only run rules relevant to banking malware to keep analysis fast.
        # Running all 400+ rules on every APK would take minutes.
        RELEVANT_KEYWORDS = [
            "sms", "otp", "telephony", "sendtext",    # SMS interception
            "overlay", "systemalert", "alertwindow",   # Overlay attacks
            "accessibility", "performglobal",           # ATS abuse
            "deviceid", "imei", "subscriberId",        # Device fingerprinting
            "dexclass", "classloader", "reflect",      # Dynamic loading
            "cipher", "aes", "encrypt", "base64",      # Crypto (data exfil)
            "credential", "banking", "phish",          # Banking fraud
            "contact", "calllog", "location",          # Data theft
        ]

        all_rules = list(rules_dir.glob("*.json"))
        relevant_rules = [
            r for r in all_rules
            if any(kw in r.stem.lower() for kw in RELEVANT_KEYWORDS)
        ]
        # Fallback: if keyword filter matches nothing, use all rules (small APK set)
        rules_to_run = relevant_rules if relevant_rules else all_rules[:50]

        logger.info("QuarkEngine: running %d/%d rules on %s", len(rules_to_run), len(all_rules), apk_path)

        confirmed = []
        for rule_file in rules_to_run:
            try:
                report = Report()
                report.analysis(apk_path, str(rule_file))
                crimes = report.get_report("json") or []

                for crime in crimes:
                    raw_conf = str(crime.get("confidence", "0%")).replace("%", "").strip()
                    try:
                        confidence = float(raw_conf) / 100.0
                    except ValueError:
                        confidence = 0.0

                    if confidence < 0.6:
                        continue

                    description = str(crime.get("crime", "")).lower()
                    confirmed.append({
                        "crime": crime.get("crime", ""),
                        "confidence": round(confidence, 4),
                        "permissions": crime.get("permissions", []),
                        "native_api": crime.get("native_api", []),
                    })
                    if any(kw in description for kw in _BANKING_KEYWORDS):
                        result["quark_banking_crime"] = True
                    if any(kw in description for kw in _SMS_KEYWORDS):
                        result["quark_sms_crime"] = True

            except Exception:
                continue   # skip individual rule failures silently

        if confirmed:
            confidences = [c["confidence"] for c in confirmed]
            result["quark_crime_count"]    = len(confirmed)
            result["quark_max_confidence"] = round(max(confidences), 4)
            result["quark_avg_confidence"] = round(sum(confidences) / len(confidences), 4)
            result["quark_crimes"]         = confirmed[:20]

        logger.info(
            "QuarkEngine: %d confirmed crimes (max conf=%.2f) for %s",
            result["quark_crime_count"], result["quark_max_confidence"], apk_path,
        )

    except ImportError:
        logger.warning("quark-engine not installed — skipping behavioral analysis")
    except Exception as exc:
        logger.warning("QuarkEngine analysis failed: %s", exc)

    return result


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
            "quark_crime_count": 0, "quark_max_confidence": 0.0,
            "quark_avg_confidence": 0.0, "quark_banking_crime": False,
            "quark_sms_crime": False, "quark_crimes": [],
        }

    permissions = extract_permissions(a)
    manifest = extract_manifest_info(a)
    suspicious_apis = detect_suspicious_apis(dx)
    all_api_classes = extract_all_api_classes(dx)   # ALL class/method refs for DREBIN matching
    intent_actions  = extract_intent_actions(a)
    obfuscated = check_obfuscation(dx)
    dynamic_loading = detect_dynamic_code_loading(dx)
    strings = extract_strings(a, d)
    yara_matches = run_yara_scan(apk_path, rules_dir)
    quark_results = run_quark_analysis(apk_path)

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
        "all_api_classes": all_api_classes,   # full bytecode class/method refs for DREBIN
        "intent_actions":  intent_actions,     # manifest intent filters
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
        # QuarkEngine behavioral crime scores
        "quark_crime_count":    quark_results["quark_crime_count"],
        "quark_max_confidence": quark_results["quark_max_confidence"],
        "quark_avg_confidence": quark_results["quark_avg_confidence"],
        "quark_banking_crime":  quark_results["quark_banking_crime"],
        "quark_sms_crime":      quark_results["quark_sms_crime"],
        "quark_crimes":         quark_results["quark_crimes"],
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
