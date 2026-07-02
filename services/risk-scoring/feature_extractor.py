import numpy as np
from typing import Any, Dict


FEATURE_NAMES = [
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


def extract_features(data: Dict[str, Any]) -> np.ndarray:
    static = data.get("static", {})
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    features = [
        float(static.get("dangerous_permission_count", 0)),
        float(len(static.get("suspicious_apis", []))),
        float(len(static.get("yara_matches", []))),
        1.0 if static.get("obfuscation_detected") else 0.0,
        1.0 if static.get("dynamic_code_loading") else 0.0,
        float(len(static.get("hardcoded_urls", []))),
        float(ti.get("malicious_count", 0)),
        1.0 if dynamic.get("sms_intercepted") else 0.0,
        1.0 if dynamic.get("accessibility_abuse") else 0.0,
        float(len([r for r in dynamic.get("network_requests", []) if r.get("suspicious")])),
        float(len(dynamic.get("runtime_downloads", []))),
        float(data.get("ai_confidence", 0.5)),
    ]

    return np.array(features, dtype=np.float32)
