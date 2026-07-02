import json
import logging
import os
from typing import Any, Dict

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3:8b-instruct"

INTENT_CLASSES = [
    "credential_theft",
    "otp_interception",
    "account_takeover",
    "data_exfiltration",
    "overlay_attack",
    "device_takeover",
    "fraud_transaction",
]


def predict_intent(analysis_summary: str, indicators: Dict[str, Any]) -> Dict[str, Any]:
    static = indicators.get("static", {})
    dynamic = indicators.get("dynamic", {})

    features = {
        "sms_interception": dynamic.get("sms_intercepted", False),
        "accessibility_abuse": dynamic.get("accessibility_abuse", False),
        "obfuscation": static.get("obfuscation_detected", False),
        "dangerous_permissions": static.get("dangerous_permission_count", 0),
        "yara_matches": static.get("yara_matches", []),
        "c2_connections": len([r for r in dynamic.get("network_requests", []) if r.get("suspicious")]),
    }

    prompt = f"""You are a fraud analyst specializing in mobile banking threats. Based on the analysis summary and behavioral indicators of a malicious Android APK, determine the attacker's primary fraud intent.

Analysis Summary:
{analysis_summary}

Behavioral Indicators:
{json.dumps(features, indent=2)}

Available intent categories: {', '.join(INTENT_CLASSES)}

Respond with JSON containing:
- "primary_intent": the most likely intent from the list above
- "secondary_intents": list of other applicable intents
- "confidence": float 0-1
- "rationale": one sentence explanation"""

    try:
        client = ollama.Client(host=OLLAMA_HOST)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 256},
        )
        raw = resp["message"]["content"].strip()

        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
    except Exception as exc:
        logger.warning("Intent prediction via Ollama failed: %s", exc)

    return _rule_based_intent(features)


def _rule_based_intent(features: Dict) -> Dict:
    if features["sms_interception"] and features["accessibility_abuse"]:
        primary = "account_takeover"
        secondary = ["otp_interception", "credential_theft"]
        rationale = "SMS interception combined with accessibility abuse indicates full account takeover capability."
    elif features["sms_interception"]:
        primary = "otp_interception"
        secondary = ["credential_theft"]
        rationale = "SMS interception capability targets banking OTP theft."
    elif features["accessibility_abuse"]:
        primary = "overlay_attack"
        secondary = ["credential_theft"]
        rationale = "Accessibility service abuse enables overlay phishing of banking credentials."
    elif features["c2_connections"] > 0:
        primary = "data_exfiltration"
        secondary = ["device_takeover"]
        rationale = "Active C2 communication suggests data collection and exfiltration."
    else:
        primary = "credential_theft"
        secondary = []
        rationale = "Dangerous permissions and suspicious APIs indicate credential harvesting intent."

    confidence = min(0.6 + 0.1 * features["dangerous_permissions"] + 0.1 * len(features["yara_matches"]), 0.95)

    return {
        "primary_intent": primary,
        "secondary_intents": secondary,
        "confidence": round(confidence, 2),
        "rationale": rationale,
    }
