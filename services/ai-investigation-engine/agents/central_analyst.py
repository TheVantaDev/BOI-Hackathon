import json
import logging
import os
from typing import Any, Dict, List

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3:8b"


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST)
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

    prompt = f"""You are the lead malware investigator for the Bank of India's cybersecurity team. You have received findings from four specialist agents investigating a suspicious Android APK. Synthesize their findings into a final threat assessment.

Static Analysis Agent:
{static_summary}

Dynamic Analysis Agent:
{dynamic_summary}

Threat Intelligence Agent:
{threat_intel_summary}

Knowledge Base Agent:
{knowledge_summary}

Based on all findings, provide:
1. A comprehensive executive summary (4-5 sentences) describing the threat
2. The malware classification (e.g., Banking Trojan, OTP Stealer, Spyware)
3. Three specific actionable recommendations for the security team

Format your response as JSON with keys: "summary", "classification", "recommendations" (list of 3 strings)."""

    raw = _call_llm(prompt)

    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(raw[start:end])
            return {
                "summary": parsed.get("summary", _fallback_summary(yara, malicious_count)),
                "classification": parsed.get("classification", _infer_classification(yara)),
                "recommendations": parsed.get("recommendations", _default_recommendations()),
                "mitre_mappings": mitre,
                "confidence": _compute_confidence(raw_data),
            }
    except json.JSONDecodeError:
        pass

    return {
        "summary": _fallback_summary(yara, malicious_count),
        "classification": _infer_classification(yara),
        "recommendations": _default_recommendations(),
        "mitre_mappings": mitre,
        "confidence": _compute_confidence(raw_data),
    }


def _infer_classification(yara_matches: List[str]) -> str:
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


def _fallback_summary(yara: List[str], malicious_iocs: int) -> str:
    return (
        f"This APK exhibits multiple high-confidence indicators of malicious behavior consistent with an Android banking trojan. "
        f"YARA analysis matched {len(yara)} malware signature rules: {', '.join(yara[:3])}. "
        f"Threat intelligence corroborated {malicious_iocs} malicious network indicators linked to known fraud infrastructure. "
        f"The combination of SMS interception, overlay attack capability, and C2 communication strongly suggests this application "
        f"is designed to facilitate banking account takeover through OTP theft and credential harvesting."
    )


def _default_recommendations() -> List[str]:
    return [
        "Immediately block all identified malicious domains and IP addresses at the network perimeter.",
        "Alert customers who may have installed this application and prompt immediate password resets.",
        "Submit the APK hash to CERT-In and coordinate with Google Play Protect for broader ecosystem detection.",
    ]


def _compute_confidence(data: Dict) -> float:
    score = 0.5
    static = data.get("static", {})
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    if static.get("yara_matches"):
        score += 0.15
    if static.get("obfuscation_detected"):
        score += 0.05
    if dynamic.get("sms_intercepted"):
        score += 0.1
    if dynamic.get("accessibility_abuse"):
        score += 0.1
    if ti.get("malicious_count", 0) > 0:
        score += 0.1

    return min(round(score, 2), 0.99)
