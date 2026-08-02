import logging
import os
from typing import Any, Dict, List

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

# 300 tokens ÷ ~70 tok/s on M-series = ~4s per call.
# 120s gives ample headroom for cold-start / CPU fallback.
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


def _call_llm(prompt: str, max_tokens: int = 300) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": max_tokens},
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

    static = raw_data.get("static", {})
    dynamic = raw_data.get("dynamic", {})
    # Obfuscation alone is NOT a malicious signal — every production app uses ProGuard/R8.
    # Only flag as malicious when there is at least one CONFIRMED threat indicator.
    has_malicious_signals = bool(
        yara
        or malicious_count > 0
        or dynamic.get("sms_intercepted")
        or dynamic.get("accessibility_abuse")
        or dynamic.get("overlay_attack_detected")
    )

    threat_level = "MALICIOUS" if has_malicious_signals else "POTENTIALLY BENIGN"

    # ── Call 1: Plain-text executive summary ──────────────────────────────────
    # We intentionally avoid asking for JSON here.
    # llama3:8b truncates mid-JSON when the context is large, causing parse errors.
    # Two short focused plain-text calls are faster and 100% reliable.
    summary_prompt = (
        f"You are the lead malware investigator for the Bank of India's cybersecurity team.\n"
        f"Four specialist agents have analysed an Android APK. Overall threat level: {threat_level}.\n\n"
        f"Static Analysis:\n{static_summary[:600]}\n\n"
        f"Dynamic Analysis:\n{dynamic_summary[:600]}\n\n"
        f"Threat Intelligence:\n{threat_intel_summary[:400]}\n\n"
        f"Write a 4-5 sentence executive summary for a security report. "
        f"Be factual and based ONLY on the findings above. "
        f"If the APK shows no confirmed malicious behaviour, state that clearly. "
        f"Do NOT invent threats that are not present in the data. "
        f"Reply with ONLY the summary paragraph — no headings, no JSON, no bullet points."
    )
    ai_summary = _call_llm(summary_prompt, max_tokens=300)

    # ── Call 2: One-label classification ─────────────────────────────────────
    yara_str = ", ".join(yara[:3]) if yara else "none"
    classification_prompt = (
        f"Android APK analysis results:\n"
        f"- YARA matches: {len(yara)} ({yara_str})\n"
        f"- Malicious IOCs: {malicious_count}\n"
        f"- SMS interception: {dynamic.get('sms_intercepted', False)}\n"
        f"- Overlay attack: {dynamic.get('overlay_attack_detected', False)}\n"
        f"- Accessibility abuse: {dynamic.get('accessibility_abuse', False)}\n"
        f"- Code obfuscation: {static.get('obfuscation_detected', False)}\n\n"
        f"Pick the single best label from this exact list:\n"
        f"Benign Application | Potentially Unwanted Application | Android Adware | "
        f"Android Spyware | OTP Stealer / Banking Trojan | "
        f"Banking Trojan with Overlay Attack | Dropper / Loader Malware | Confirmed Malware\n\n"
        f"Reply with ONLY the label — nothing else."
    )
    ai_classification = _call_llm(classification_prompt, max_tokens=20).strip()

    known_labels = {
        "Benign Application", "Potentially Unwanted Application", "Android Adware",
        "Android Spyware", "OTP Stealer / Banking Trojan",
        "Banking Trojan with Overlay Attack", "Dropper / Loader Malware",
        "Confirmed Malware",
    }
    if ai_classification not in known_labels:
        ai_classification = _infer_classification(yara, has_malicious_signals)

    if not ai_summary:
        ai_summary = _fallback_summary(yara, malicious_count, has_malicious_signals)

    return {
        "summary": ai_summary,
        "classification": ai_classification,
        "recommendations": _build_recommendations(raw_data, has_malicious_signals),
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
    """Last-resort summary used only when Ollama is completely unavailable."""
    if not has_malicious_signals:
        return (
            "Static and dynamic analysis found no significant indicators of malicious behavior. "
            "No YARA rules matched known malware signatures. "
            "No suspicious runtime behaviour, SMS interception, or overlay attacks were detected. "
            "Threat intelligence found no associated malicious network indicators. "
            "This application appears to be benign based on available evidence."
        )
    return (
        f"This APK exhibits high-confidence indicators of malicious behaviour. "
        f"YARA analysis matched {len(yara)} malware signature rules"
        + (f": {', '.join(yara[:3])}" if yara else "") + ". "
        f"Threat intelligence corroborated {malicious_iocs} malicious network indicators. "
        f"The detected behaviours strongly suggest this application is designed to facilitate "
        f"banking account takeover through credential harvesting and data exfiltration."
    )


def _build_recommendations(data: Dict[str, Any], has_malicious_signals: bool) -> List[str]:
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    if not has_malicious_signals:
        return [
            "No immediate action required. Continue routine monitoring.",
            "Verify the APK's origin and distribution channel as a precaution.",
            "Re-scan periodically if the app requests new permissions in future updates.",
        ]

    recs: List[str] = []
    if ti.get("malicious_count", 0) > 0:
        recs.append(
            "Immediately block all identified malicious domains and IP addresses at the network perimeter."
        )
    if dynamic.get("sms_intercepted"):
        recs.append(
            "Alert customers who may have installed this application and prompt immediate OTP/password resets."
        )
    if dynamic.get("overlay_attack_detected"):
        recs.append(
            "Warn customers about credential-harvesting overlays — reset all banking credentials immediately."
        )
    if not recs:
        recs.append(
            "Investigate and block suspicious network endpoints identified in threat intelligence."
        )
    recs.append(
        "Submit the APK hash to CERT-In and coordinate with Google Play Protect for broader ecosystem detection."
    )
    recs.append(
        "Conduct forensic analysis on devices where this APK was installed to check for data exfiltration."
    )
    return recs[:3]


def _compute_confidence(data: Dict) -> float:
    """Confidence is earned by actual malicious evidence — starts at 0.0.
    Obfuscation (ProGuard/R8) and dynamic code loading (DexClassLoader / Unity)
    are both normal in production APKs and contribute ZERO confidence here.
    Only confirmed dynamic signals or threat-intel matches carry real weight.
    """
    score = 0.0
    static = data.get("static", {})
    dynamic = data.get("dynamic", {})
    ti = data.get("threat_intel", {})

    if static.get("yara_matches"):
        score += 0.35
    # obfuscation_detected intentionally excluded: ProGuard/R8 is standard
    # dynamic_code_loading intentionally excluded: Unity/game SDKs use DexClassLoader
    if dynamic.get("sms_intercepted"):
        score += 0.20
    if dynamic.get("accessibility_abuse"):
        score += 0.15
    if dynamic.get("overlay_attack_detected"):
        score += 0.15
    if ti.get("malicious_count", 0) > 0:
        score += 0.15

    return min(round(score, 2), 0.99)
