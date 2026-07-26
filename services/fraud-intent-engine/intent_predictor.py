import json
import logging
import os
from typing import Any, Dict

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3:8b"
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 512},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return ""


def predict_intent(analysis_summary: str, indicators: Dict[str, Any]) -> Dict[str, Any]:
    static = indicators.get("static", {})
    dynamic = indicators.get("dynamic", {})

    features = {
        "sms_interception": dynamic.get("sms_intercepted", False),
        "accessibility_abuse": dynamic.get("accessibility_abuse", False),
        "overlay_attack": dynamic.get("overlay_attack_detected", False),
        "obfuscation": static.get("obfuscation_detected", False),
        "dangerous_permissions": static.get("dangerous_permission_count", 0),
        "yara_matches": static.get("yara_matches", []),
        "c2_connections": len([r for r in dynamic.get("network_requests", []) if r.get("suspicious")]),
    }

    # Only call LLM if there are actual malicious signals — otherwise rule-based
    # is sufficient and faster (no Ollama call needed for clean APKs).
    # Obfuscation (ProGuard/R8) is present in virtually every production APK
    # and is NOT a malicious signal on its own. Calling the LLM for obfuscated
    # but otherwise clean apps causes hallucinated labels like "otp_interception".
    # Only call the LLM when at least ONE confirmed threat indicator is present.
    has_signals = any([
        features["sms_interception"],
        features["accessibility_abuse"],
        features["overlay_attack"],
        features["c2_connections"] > 0,
        len(features["yara_matches"]) > 0,
        # NOTE: obfuscation deliberately excluded — see comment above
    ])

    if has_signals:
        prompt = f"""You are a fraud analyst specializing in mobile banking threats. Based on the analysis summary and behavioral indicators of an Android APK, determine the attacker's primary fraud intent.

Analysis Summary:
{analysis_summary}

Behavioral Indicators:
{json.dumps(features, indent=2)}

Available intent categories: credential_theft, otp_interception, account_takeover, data_exfiltration, overlay_attack, device_takeover, fraud_transaction, benign

Respond with JSON containing:
- "primary_intent": the most likely intent from the list above (use "benign" if no malicious intent found)
- "secondary_intents": list of other applicable intents (empty list if benign)
- "confidence": float 0-1
- "rationale": one sentence explanation"""

        try:
            client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
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
    sms = features["sms_interception"]
    accessibility = features["accessibility_abuse"]
    overlay = features.get("overlay_attack", False)
    c2 = features["c2_connections"]
    yara = features["yara_matches"]
    obfuscation = features["obfuscation"]
    perms = features["dangerous_permissions"]

    # Check if ANY confirmed malicious signal exists.
    # Obfuscation (ProGuard/R8) is deliberately EXCLUDED — virtually every
    # production APK uses it.  Including it caused Hello World apps to be
    # classified as "credential_theft" / "otp_interception".
    has_any_signal = sms or accessibility or overlay or c2 > 0 or len(yara) > 0

    if not has_any_signal:
        # Truly clean app — no malicious runtime or static signals
        return {
            "primary_intent": "benign",
            "secondary_intents": [],
            "confidence": round(max(0.0, 0.1 - 0.01 * perms), 2),  # lower confidence if more perms
            "rationale": "No malicious behavioral signals detected. App appears to be benign.",
            "predicted_intent": "No Malicious Intent Detected",
        }

    if sms and accessibility:
        primary = "account_takeover"
        secondary = ["otp_interception", "credential_theft"]
        rationale = "SMS interception combined with accessibility abuse indicates full account takeover capability."
    elif sms:
        primary = "otp_interception"
        secondary = ["credential_theft"]
        rationale = "SMS interception capability targets banking OTP theft."
    elif overlay or accessibility:
        primary = "overlay_attack"
        secondary = ["credential_theft"]
        rationale = "Accessibility service abuse or overlay capability enables phishing of banking credentials."
    elif c2 > 0:
        primary = "data_exfiltration"
        secondary = ["device_takeover"]
        rationale = "Active C2 communication suggests data collection and exfiltration."
    else:
        # Has YARA matches but no dynamic signals — flag but at lower confidence.
        # NOTE: this branch no longer triggers for obfuscation-only apps (excluded above).
        primary = "credential_theft"
        secondary = []
        rationale = "YARA signatures matched known malware patterns. No confirmed dynamic behaviour yet."

    # Confidence based on confirmed threat signals only — obfuscation excluded
    signal_count = sum([bool(sms), bool(accessibility), bool(overlay), c2 > 0, len(yara) > 0])
    confidence = min(0.4 + 0.1 * signal_count, 0.95)

    return {
        "primary_intent": primary,
        "secondary_intents": secondary,
        "confidence": round(confidence, 2),
        "rationale": rationale,
        "predicted_intent": primary.replace("_", " ").title(),
    }
