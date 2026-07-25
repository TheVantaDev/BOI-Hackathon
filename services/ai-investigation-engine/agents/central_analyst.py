import json
import logging
import os
from typing import Any, Dict, List

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3:8b"

# Generous timeout: llama3:8b on M5 Metal generates ~70 tok/s.
# 1024 tokens ÷ 70 = ~15s. Give 120s headroom for cold starts / CPU fallback.
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 1024},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return ""


def consolidate(
    static_summary: str,
    dynamic_summary: str,
    threat_intel_summary: str,
    knowledge_summary: str,
    raw_data: Dict[str, Any],
) -> Dict[str, Any]:
    mitre = raw_data.get("threat_intel", {}).get("mitre_techniques", [])
    yara = raw_data.get("static", {}).get("yara_matches", [])
    malicious_count = raw_data.get("threat_intel", {}).get("malicious_count", 0)

    # Determine if this looks like a genuinely clean app so we can frame the
    # prompt neutrally instead of assuming it's malicious.
    static = raw_data.get("static", {})
    dynamic = raw_data.get("dynamic", {})
    has_malicious_signals = bool(
        yara
        or malicious_count > 0
        or dynamic.get("sms_intercepted")
        or dynamic.get("accessibility_abuse")
        or dynamic.get("overlay_attack_detected")
        or static.get("obfuscation_detected")
    )

    framing = (
        "You have received findings from four specialist agents investigating an Android APK "
        "that shows signs of malicious behavior."
        if has_malicious_signals
        else "You have received findings from four specialist agents investigating an Android APK. "
             "Determine objectively whether it is malicious or benign based solely on the evidence."
    )

    prompt = f"""You are the lead malware investigator for the Bank of India's cybersecurity team. {framing}

Static Analysis Agent:
{static_summary}

Dynamic Analysis Agent:
{dynamic_summary}

Threat Intelligence Agent:
{threat_intel_summary}

Knowledge Base Agent:
{knowledge_summary}

Based on all findings, provide:
1. A comprehensive executive summary (4-5 sentences) describing the threat level and what evidence supports it
2. The malware classification — use "Benign Application" if no malicious signals are present
3. Three specific actionable recommendations appropriate to the actual threat level found

Format your response as JSON with keys: "summary", "classification", "recommendations" (list of 3 strings)."""

    raw = _call_llm(prompt)

    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(raw[start:end])
            return {
                "summary": parsed.get("summary", _fallback_summary(yara, malicious_count, has_malicious_signals)),
                "classification": parsed.get("classification", _infer_classification(yara, has_malicious_signals)),
                "recommendations": parsed.get("recommendations", _default_recommendations(has_malicious_signals)),
                "mitre_mappings": mitre,
                "confidence": _compute_confidence(raw_data),
            }
    except json.JSONDecodeError:
        pass

    return {
        "summary": _fallback_summary(yara, malicious_count, has_malicious_signals),
        "classification": _infer_classification(yara, has_malicious_signals),
        "recommendations": _default_recommendations(has_malicious_signals),
        "mitre_mappings": mitre,
        "confidence": _compute_confidence(raw_data),
    }


def _infer_classification(yara_matches: List[str], has_malicious_signals: bool) -> str:
    if not has_malicious_signals:
        return "Benign Application"
    yara_str = " ".join(yara_matches).lower()
    if "smsinterceptor" in yara_str or "otpstealer" in yara_str:
        return "OTP Stealer / Banking Trojan"
    if "overlayattack" in yara_str or "credentialharvester" in yara_str:
        return "Banking Trojan with Overlay Attack"
    if "dynamiccodeloading" in yara_str:
        return "Dropper / Loader Malware"
    if yara_matches:
        return "Android Malware"
    return "Potentially Unwanted Application"


def _fallback_summary(yara: List[str], malicious_iocs: int, has_malicious_signals: bool) -> str:
    # Previously: always said "banking trojan" regardless of actual findings.
    # Now: conditional on real signals being present.
    if not has_malicious_signals:
        return (
            "Static and dynamic analysis found no significant indicators of malicious behavior. "
            "No YARA rules matched known malware signatures. "
            "No suspicious runtime behavior, SMS interception, or overlay attacks were detected. "
            "Threat intelligence found no associated malicious network indicators. "
            "This application appears to be benign based on available evidence."
        )
    return (
        f"This APK exhibits high-confidence indicators of malicious behavior consistent with an Android banking trojan. "
        f"YARA analysis matched {len(yara)} malware signature rules"
        + (f": {', '.join(yara[:3])}" if yara else "") + ". "
        f"Threat intelligence corroborated {malicious_iocs} malicious network indicators linked to known fraud infrastructure. "
        f"The combination of detected behaviors strongly suggests this application is designed to facilitate "
        f"banking account takeover through credential harvesting and data exfiltration."
    )


def _default_recommendations(has_malicious_signals: bool) -> List[str]:
    if not has_malicious_signals:
        return [
            "No immediate action required. Continue routine monitoring.",
            "Verify the APK's origin and distribution channel as a precaution.",
            "Re-scan periodically if the app requests new permissions in future updates.",
        ]
    return [
        "Immediately block all identified malicious domains and IP addresses at the network perimeter.",
        "Alert customers who may have installed this application and prompt immediate password resets.",
        "Submit the APK hash to CERT-In and coordinate with Google Play Protect for broader ecosystem detection.",
    ]


def _compute_confidence(data: Dict) -> float:
    # Previously started at 0.5 (every APK was 50% malicious by default).
    # Now starts at 0.0 — confidence is earned by actual malicious evidence only.
    score = 0.0
    static = data.get("static", {})
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    if static.get("yara_matches"):
        score += 0.35
    if static.get("obfuscation_detected"):
        score += 0.10
    if dynamic.get("sms_intercepted"):
        score += 0.20
    if dynamic.get("accessibility_abuse"):
        score += 0.15
    if dynamic.get("overlay_attack_detected"):
        score += 0.15
    if ti.get("malicious_count", 0) > 0:
        score += 0.15
    if static.get("dynamic_code_loading"):
        score += 0.10

    return min(round(score, 2), 0.99)
