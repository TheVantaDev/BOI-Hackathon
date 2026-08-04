import asyncio
import logging
from typing import Any, Dict

import httpx

from config import settings

logger = logging.getLogger(__name__)

# Per-service timeouts:
# - Dynamic analysis: up to ~620s (300s sandbox + Frida sleep + overhead)
# - AI investigation: 5 LLM sub-agent calls × ~60s each + consolidation = ~360s min.
#   Give 600s total headroom for CPU-only llama3:8b inference.
# - Standard: all other microservices should complete in under 90s.
TIMEOUT_DYNAMIC  = httpx.Timeout(620.0, connect=10.0)
TIMEOUT_AI       = httpx.Timeout(600.0, connect=10.0)
TIMEOUT_STANDARD = httpx.Timeout(90.0,  connect=10.0)


async def _post(
    client: httpx.AsyncClient,
    url: str,
    payload: dict,
    timeout: httpx.Timeout = TIMEOUT_STANDARD,
) -> dict:
    try:
        resp = await client.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("Service call failed: %s — %s", url, exc)
        return {}


def _build_fraud_summary(static: dict, dynamic: dict, threat_intel: dict) -> str:
    """
    Build a human-readable behavioural summary for the fraud intent classifier.
    Previously this was just passing manifest.package_name (a single word),
    giving the classifier no useful context to work with.
    """
    pkg  = static.get("manifest", {}).get("package_name", "unknown")
    perm_count   = static.get("dangerous_permission_count", 0)
    yara         = static.get("yara_matches", [])
    obfuscated   = static.get("obfuscation_detected", False)
    dyn_code     = static.get("dynamic_code_loading", False)
    hardcoded    = static.get("hardcoded_urls", [])

    sms          = dynamic.get("sms_intercepted", False)
    otp          = dynamic.get("otp_interceptions_detected", False)
    overlay      = dynamic.get("overlay_attack_detected", False)
    accessibility= dynamic.get("accessibility_abuse", False)
    ats          = dynamic.get("ats_actions_detected", False)
    c2_count     = dynamic.get("c2_connections", 0)
    downloads    = dynamic.get("runtime_downloads", [])

    ioc_count    = threat_intel.get("malicious_count", 0)
    mal_domains  = threat_intel.get("malicious_domains", [])

    parts = [f"Package: {pkg}."]
    parts.append(f"Dangerous permissions: {perm_count}.")
    if yara:
        parts.append(f"YARA matches: {', '.join(yara[:3])}.")
    if obfuscated:
        parts.append("Code obfuscation detected.")
    if dyn_code:
        parts.append("Dynamic code loading (DexClassLoader) present.")
    if hardcoded:
        parts.append(f"Hardcoded URLs found: {len(hardcoded)}.")
    if sms or otp:
        parts.append("SMS/OTP interception detected at runtime.")
    if overlay:
        parts.append("Overlay attack on banking app detected.")
    if accessibility:
        parts.append("Accessibility service abuse detected (possible ATS).")
    if ats:
        parts.append("Automatic Transfer System gesture injection detected.")
    if c2_count:
        parts.append(f"C2 connections: {c2_count}.")
    if downloads:
        parts.append(f"Runtime payload downloads: {len(downloads)}.")
    if ioc_count:
        parts.append(f"Known malicious IOCs: {ioc_count}.")
    if mal_domains:
        parts.append(f"Malicious domains: {', '.join(mal_domains[:3])}.")

    return " ".join(parts)


async def run_pipeline(apk_id: str, minio_path: str, sha256: str) -> Dict[str, Any]:
    apk_ref = {"apk_id": apk_id, "minio_path": minio_path, "sha256": sha256}

    # Use a long-timeout client for dynamic analysis; standard for everything else.
    async with httpx.AsyncClient(timeout=TIMEOUT_DYNAMIC) as client:

        # Stage 1: Static + Dynamic run IN PARALLEL — they don't depend on each other
        static, dynamic = await asyncio.gather(
            _post(client, f"{settings.static_analysis_url}/analyze",  apk_ref, timeout=TIMEOUT_STANDARD),
            _post(client, f"{settings.dynamic_analysis_url}/analyze", apk_ref, timeout=TIMEOUT_DYNAMIC),
        )

        # Stage 2: Threat intel (needs static IOCs)
        # Extract domains from hardcoded URLs, not the raw URL strings themselves
        raw_urls = static.get("hardcoded_urls", [])
        domains = list({
            u.split("/")[2].lower()
            for u in raw_urls
            if "://" in u and len(u.split("/")) > 2
        })
        iocs = {
            "domains": domains,
            "ips":     static.get("hardcoded_ips", []),
            "hashes":  [sha256],
            "urls":    raw_urls[:10],
            # Static signals for MITRE ATT&CK mapping
            "permissions": static.get("permissions", []),
            "suspicious_apis": static.get("suspicious_apis", []),
            "dynamic_code_loading": bool(static.get("dynamic_code_loading")),
        }
        threat_intel = await _post(
            client, f"{settings.threat_intel_url}/lookup", iocs, timeout=TIMEOUT_STANDARD
        )

        combined = {
            "apk_id": apk_id,
            "static": static,
            "dynamic": dynamic,
            "threat_intel": threat_intel,
        }

        # Stage 3: Build a meaningful fraud summary before calling the classifier
        fraud_summary = _build_fraud_summary(static, dynamic, threat_intel)

        # Stage 3: AI investigation + Fraud intent run IN PARALLEL
        ai_result, fraud_result = await asyncio.gather(
            _post(client, f"{settings.ai_engine_url}/investigate", combined, timeout=TIMEOUT_AI),
            _post(client, f"{settings.fraud_engine_url}/predict", {
                "apk_id": apk_id,
                "analysis_summary": fraud_summary,   # ← was: package_name (bug fixed)
                "indicators": combined,
            }, timeout=TIMEOUT_STANDARD),
        )

        # Stage 4: Risk scoring (needs everything)
        scoring_payload = {
            "static": static,
            "dynamic": dynamic,
            "threat_intel": threat_intel,
            "ai_confidence": ai_result.get("confidence", 0.0),
            "minio_path": minio_path,  # CNN needs raw APK for DEX extraction
        }
        score_result = await _post(
            client, f"{settings.risk_scoring_url}/score", scoring_payload, timeout=TIMEOUT_STANDARD
        )

    return {
        "static_analysis": static,
        "dynamic_analysis": dynamic,
        "threat_intel": threat_intel,
        "ai_investigation": ai_result,
        "fraud_intent": fraud_result,
        "risk_score": score_result,
    }
