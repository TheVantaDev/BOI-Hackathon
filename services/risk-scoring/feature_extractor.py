import numpy as np
from typing import Any, Dict


# Features the XGBoost model was TRAINED on — do NOT change this list.
# Adding features here will break the model (feature_names mismatch crash).
XGBOOST_FEATURE_NAMES = [
    "dangerous_perm_count",
    "suspicious_api_count",
    "yara_match_count",
    "obfuscation_detected",
    "dynamic_code_loading",
    "hardcoded_url_count",
    "malicious_ioc_count",
    "sms_intercepted",
    "accessibility_abuse",
    "c2_connection_count",
    "runtime_downloads",
    "ai_confidence",
]

# All features including QuarkEngine additions — used by the heuristic scorer.
FEATURE_NAMES = XGBOOST_FEATURE_NAMES + [
    "quark_crime_count",
    "quark_max_confidence",
    "quark_banking_crime",
    "quark_sms_crime",
]


def _base_counts(data: Dict[str, Any]):
    """Shared extraction logic used by both XGBoost and heuristic feature sets."""
    static = data.get("static", {})
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    permissions = static.get("permissions", [])
    if isinstance(permissions, list):
        dangerous_perm_count = sum(
            1 for p in permissions
            if (isinstance(p, dict) and p.get("dangerous"))
            or (isinstance(p, str) and p.split(".")[-1] in {
                "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS",
                "WRITE_CONTACTS", "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG",
                "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
                "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
                "GET_ACCOUNTS", "USE_CREDENTIALS", "WRITE_EXTERNAL_STORAGE",
            })
        )
    else:
        dangerous_perm_count = int(static.get("dangerous_permission_count", 0))

    malicious_ioc_count = int(ti.get("malicious_count", 0))
    indicators = ti.get("indicators", [])
    if isinstance(indicators, list) and malicious_ioc_count == 0:
        malicious_ioc_count = sum(1 for i in indicators if isinstance(i, dict) and i.get("malicious"))

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
        float(len([r for r in dynamic.get("network_requests", []) if isinstance(r, dict) and r.get("suspicious")])),
        float(len(dynamic.get("runtime_downloads", []))),
        float(data.get("ai_confidence", 0.5)),
    ]
    return base, static


def extract_xgboost_features(data: Dict[str, Any]) -> np.ndarray:
    """
    Returns exactly the 12 features the XGBoost model was trained on.
    Do NOT add Quark or any new features here — it will break the model.
    """
    base, _ = _base_counts(data)
    return np.array(base, dtype=np.float32)


def extract_features(data: Dict[str, Any]) -> np.ndarray:
    """
    Returns all 16 features (12 original + 4 QuarkEngine) for the heuristic scorer.
    QuarkEngine features dramatically reduce false positives on benign apps (Ludo, Calculator)
    by adding behavioral crime signals that permission counts alone cannot provide.
    """
    base, static = _base_counts(data)
    quark_features = [
        float(static.get("quark_crime_count", 0)),
        float(static.get("quark_max_confidence", 0.0)),
        1.0 if static.get("quark_banking_crime") else 0.0,
        1.0 if static.get("quark_sms_crime") else 0.0,
    ]
    return np.array(base + quark_features, dtype=np.float32)


