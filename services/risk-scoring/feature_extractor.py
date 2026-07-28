"""
feature_extractor.py — DREBIN-215 feature extraction aligned to model training schema.

The model was trained on 215 binary features from the DREBIN dataset.
Feature names fall into these categories (inspected from model JSON):
  - Short permission names : SEND_SMS, READ_SMS, CAMERA  (no android.permission. prefix)
  - Method/class names     : Runtime.exec, DexClassLoader, TelephonyManager.getDeviceId
  - Intent actions         : android.intent.action.BOOT_COMPLETED
  - Shell paths/commands   : /system/bin, chmod, mount
  - Full class paths       : android.telephony.SmsManager, Ljavax.crypto.Cipher

At inference time we extract ALL of these from the APK via Androguard and
match them against the exact 215 feature names the model was trained on.
NO hardcoded dangerous list — the model decides weights from data.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)

# ── Load feature names from model artifact ───────────────────────────────────
_MODELS_DIR = Path(os.getenv("MODEL_PATH", "/app/models/xgb_risk_model.json")).parent
_FEATURE_NAMES_PATH = _MODELS_DIR / "drebin_feature_names.json"

DREBIN_FEATURE_NAMES: List[str] = []
_meta_loaded = False


def _load_feature_names() -> List[str]:
    global DREBIN_FEATURE_NAMES, _meta_loaded
    if _meta_loaded:
        return DREBIN_FEATURE_NAMES

    _meta_loaded = True
    if _FEATURE_NAMES_PATH.exists():
        with open(_FEATURE_NAMES_PATH) as f:
            meta = json.load(f)
        DREBIN_FEATURE_NAMES = meta["feature_names"]
        logger.info("Loaded %d DREBIN feature names from %s",
                    len(DREBIN_FEATURE_NAMES), _FEATURE_NAMES_PATH)
    else:
        logger.warning("drebin_feature_names.json not found at %s — heuristic mode",
                       _FEATURE_NAMES_PATH)
        DREBIN_FEATURE_NAMES = []

    return DREBIN_FEATURE_NAMES


# ── Build APK signal sets from static analysis output ───────────────────────

def _build_apk_signals(data: Dict[str, Any]) -> Dict[str, set]:
    """
    Extract every signal from the static/dynamic analysis output and
    normalise them into lookup sets so we can match DREBIN feature names fast.
    """
    static  = data.get("static",  {})
    dynamic = data.get("dynamic", {})

    # ── 1. Permissions ───────────────────────────────────────────────────────
    # DREBIN stores SHORT names: SEND_SMS, READ_SMS (no android.permission. prefix)
    perm_short: set = set()
    perm_full:  set = set()

    # Static analysis returns permissions in TWO possible formats:
    #   A) list[str | dict]  — e.g. ["android.permission.SEND_SMS", ...]
    #   B) dict               — e.g. {"total_count": 11, "dangerous_permissions": [...], "all_permissions": [...]}
    raw_perms = static.get("permissions", [])
    if isinstance(raw_perms, dict):
        # Format B: extract from nested lists
        perm_list = []
        for key in ("all_permissions", "dangerous_permissions"):
            entries = raw_perms.get(key, [])
            if isinstance(entries, list):
                perm_list.extend(entries)
        if not perm_list:
            perm_list = []  # safety
    else:
        perm_list = raw_perms if isinstance(raw_perms, list) else []

    for p in perm_list:
        if isinstance(p, dict):
            full  = p.get("full",  "")
            short = p.get("name",  full.split(".")[-1])
        else:
            full  = str(p)
            short = full.split(".")[-1]
        perm_short.add(short.upper())           # e.g. "SEND_SMS"
        perm_full.add(full.lower())             # e.g. "android.permission.send_sms"

    # ── 2. API methods / classes — ALL of them from bytecode ─────────────────
    # The static analyzer returns both a short suspicious_apis list (18 known
    # bad names) AND the full all_api_classes list (every class/method ref from
    # bytecode).  The DREBIN-215 binary model needs the FULL list so that all
    # 215 independently-weighted features can match.  (The old 12-feature count
    # model would have been overwhelmed by benign API names inflating counts,
    # but the new model uses binary 0/1 per feature — no dilution possible.)
    api_strings: set = set()
    for api in static.get("suspicious_apis", []):
        api_strings.add(str(api))
    # Full class/method references extracted by Androguard — needed for DREBIN
    # features like transact, Ljava.lang.Class.getCanonicalName, Ljavax.crypto.Cipher
    for cls in static.get("all_api_classes", []):
        api_strings.add(str(cls))

    # ── 3. Intent actions ────────────────────────────────────────────────────
    intents: set = set()
    manifest = static.get("manifest", {})
    for svc in manifest.get("receivers", []):
        intents.add(str(svc).lower())
    for intent_str in static.get("intent_actions", []):
        intents.add(str(intent_str).lower())
    # Also pull intent-filter actions directly from the manifest receivers/services
    # so DREBIN intent features like android.intent.action.BOOT_COMPLETED match
    for receiver in manifest.get("receivers", []):
        intents.add(str(receiver).lower())
    for service in manifest.get("services", []):
        intents.add(str(service).lower())

    # ── 4. Shell commands / paths in code ────────────────────────────────────
    shell_strings: set = set()
    for url in static.get("hardcoded_urls", []):
        shell_strings.add(str(url).lower())
    for ip in static.get("hardcoded_ips", []):
        shell_strings.add(str(ip))
    # Dynamic signals map back to API features
    # Dynamic analyzer uses both field name variants depending on version
    if dynamic.get("sms_intercepted") or dynamic.get("sms_interception"):
        perm_short.update({"SEND_SMS", "RECEIVE_SMS", "READ_SMS"})
        api_strings.add("sendTextMessage")
    if dynamic.get("accessibility_abuse"):
        perm_short.add("BIND_ACCESSIBILITY_SERVICE")
    if dynamic.get("overlay_attack_detected") or dynamic.get("overlay_attacks"):
        perm_short.add("SYSTEM_ALERT_WINDOW")

    return {
        "perm_short":   perm_short,
        "perm_full":    perm_full,
        "api_strings":  api_strings,
        "intents":      intents,
        "shell":        shell_strings,
    }


def _feature_hit(fname: str, signals: Dict[str, set]) -> bool:
    """
    Returns True if the DREBIN feature name is present in this APK.

    Matching strategy per feature name format:
    - Short uppercase word (SEND_SMS)         → perm_short lookup
    - android.intent.action.* / intent.*      → intents lookup
    - android.*/Landroid.*                    → full class name → api_strings
    - TelephonyManager.* / Runtime.* etc.     → method name → api_strings
    - /system/bin, chmod, mount etc.           → shell strings
    - Ljavax.crypto.* / Ljava.lang.*           → api_strings
    """
    ps   = signals["perm_short"]
    pa   = signals["perm_full"]
    apis = signals["api_strings"]
    ints = signals["intents"]
    sh   = signals["shell"]

    # Intent actions
    if "intent.action" in fname.lower() or fname.lower().startswith("intent.action"):
        return fname.lower() in ints or any(fname.lower() in s for s in ints)

    # Shell paths / commands (start with / or are short known shell commands)
    if fname.startswith("/") or fname in {"chmod", "chown", "mount", "remount",
                                          "createSubprocess", "ProcessBuilder"}:
        return fname.lower() in sh or any(fname.lower() in s for s in sh) or fname in apis

    # Short ALL-CAPS permission names (SEND_SMS, CAMERA, etc.)
    if fname == fname.upper() and fname.replace("_", "").isalpha():
        return fname in ps

    # Full android.permission.* style
    if ".permission." in fname:
        short = fname.split(".")[-1].upper()
        return short in ps or fname.lower() in pa

    # Match against api_strings by:
    #   - exact match
    #   - fname is a suffix of any api string  (e.g. "DexClassLoader" in "android.DexClassLoader")
    #   - api string contains fname as substring
    fname_lower = fname.lower().replace("ljava", "java").replace("landroid", "android")
    for api in apis:
        api_lower = api.lower()
        if (fname_lower == api_lower
                or fname_lower in api_lower
                or api_lower in fname_lower
                or fname.split(".")[-1].lower() in api_lower):
            return True

    # Also check short permission name (some DREBIN API names overlap with permission shorts)
    if fname.upper() in ps:
        return True

    return False


def extract_drebin_features(data: Dict[str, Any]) -> np.ndarray:
    """
    Build the 215-dim binary feature vector matching the DREBIN training schema.
    Returns empty array if drebin_feature_names.json is not loaded (triggers heuristic).
    """
    feature_names = _load_feature_names()
    if not feature_names:
        return np.array([], dtype=np.float32)

    signals = _build_apk_signals(data)
    vector  = np.zeros(len(feature_names), dtype=np.float32)

    for i, fname in enumerate(feature_names):
        try:
            vector[i] = 1.0 if _feature_hit(fname, signals) else 0.0
        except Exception:
            vector[i] = 0.0

    active = int(vector.sum())
    logger.info("DREBIN feature vector: %d / %d features active", active, len(feature_names))
    if active == 0:
        logger.warning(
            "All DREBIN features are 0 — APK signals may not be extracted correctly. "
            "Check that static-analysis service is returning permissions and apis."
        )
    return vector


def extract_xgboost_features(data: Dict[str, Any]) -> np.ndarray:
    """Entry point for model.py — returns DREBIN vector or legacy 12-feature fallback."""
    drebin = extract_drebin_features(data)
    if len(drebin) > 0:
        return drebin
    # Legacy fallback: old 12-feature model (no drebin_feature_names.json)
    base, _ = _base_counts(data)
    return np.array(base, dtype=np.float32)


# ── Legacy heuristic features (used only when XGBoost model is absent) ───────

XGBOOST_FEATURE_NAMES = []   # populated lazily from drebin_feature_names.json

FEATURE_NAMES = [
    "dangerous_perm_count", "suspicious_api_count", "yara_match_count",
    "obfuscation_detected", "dynamic_code_loading", "hardcoded_url_count",
    "malicious_ioc_count", "sms_intercepted", "accessibility_abuse",
    "c2_connection_count", "runtime_downloads", "ai_confidence",
    "quark_crime_count", "quark_max_confidence",
    "quark_banking_crime", "quark_sms_crime",
]

# Heuristic-only dangerous permissions (used ONLY in fallback scorer, not for XGBoost)
_HEURISTIC_DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES",
    "GET_ACCOUNTS", "USE_CREDENTIALS", "WRITE_EXTERNAL_STORAGE",
}


def _base_counts(data: Dict[str, Any]):
    static  = data.get("static",  {})
    dynamic = data.get("dynamic", {})
    ti      = data.get("threat_intel", {})

    permissions = static.get("permissions", [])
    if isinstance(permissions, list):
        dangerous_perm_count = sum(
            1 for p in permissions
            if (isinstance(p, dict) and p.get("dangerous"))
            or (isinstance(p, str) and p.split(".")[-1] in _HEURISTIC_DANGEROUS)
        )
    else:
        dangerous_perm_count = int(static.get("dangerous_permission_count", 0))

    malicious_ioc_count = int(ti.get("malicious_count", 0))
    indicators = ti.get("indicators", [])
    if isinstance(indicators, list) and malicious_ioc_count == 0:
        malicious_ioc_count = sum(
            1 for ind in indicators
            if isinstance(ind, dict) and ind.get("malicious")
        )

    base = [
        float(dangerous_perm_count),
        float(len(static.get("suspicious_apis", []))),
        float(len(static.get("yara_matches", []))),
        1.0 if static.get("obfuscation_detected") else 0.0,
        1.0 if static.get("dynamic_code_loading") else 0.0,
        float(len(static.get("hardcoded_urls", []))),
        float(malicious_ioc_count),
        1.0 if dynamic.get("sms_intercepted") else 0.0,
        1.0 if dynamic.get("accessibility_abuse") else 0.0,
        float(len([r for r in dynamic.get("network_requests", [])
                   if isinstance(r, dict) and r.get("suspicious")])),
        float(len(dynamic.get("runtime_downloads", []))),
        float(data.get("ai_confidence", 0.0)),
    ]
    return base, static


def extract_features(data: Dict[str, Any]) -> np.ndarray:
    """16-feature heuristic vector — only used when no XGBoost model is loaded."""
    base, static = _base_counts(data)
    quark = [
        float(static.get("quark_crime_count", 0)),
        float(static.get("quark_max_confidence", 0.0)),
        1.0 if static.get("quark_banking_crime") else 0.0,
        1.0 if static.get("quark_sms_crime") else 0.0,
    ]
    return np.array(base + quark, dtype=np.float32)
