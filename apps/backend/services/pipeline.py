import logging
from typing import Any, Dict

import httpx

from config import settings

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(600.0, connect=10.0)


async def _post(client: httpx.AsyncClient, url: str, payload: dict) -> dict:
    try:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("Service call failed: %s — %s", url, exc)
        return {}


async def run_pipeline(apk_id: str, minio_path: str, sha256: str) -> Dict[str, Any]:
    apk_ref = {"apk_id": apk_id, "minio_path": minio_path, "sha256": sha256}

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        static = await _post(client, f"{settings.static_analysis_url}/analyze", apk_ref)
        dynamic = await _post(client, f"{settings.dynamic_analysis_url}/analyze", apk_ref)

        iocs = {
            "domains": static.get("hardcoded_urls", []),
            "ips": static.get("hardcoded_ips", []),
            "hashes": [sha256],
        }
        threat_intel = await _post(client, f"{settings.threat_intel_url}/lookup", iocs)

        combined = {
            "apk_id": apk_id,
            "static": static,
            "dynamic": dynamic,
            "threat_intel": threat_intel,
        }

        ai_result = await _post(client, f"{settings.ai_engine_url}/investigate", combined)

        fraud_result = await _post(
            client,
            f"{settings.fraud_engine_url}/predict",
            {
                "apk_id": apk_id,
                "analysis_summary": ai_result.get("summary", ""),
                "indicators": combined,
            },
        )

        scoring_payload = {
            "static": static,
            "dynamic": dynamic,
            "threat_intel": threat_intel,
            "ai_confidence": ai_result.get("confidence", 0.5),
        }
        score_result = await _post(client, f"{settings.risk_scoring_url}/score", scoring_payload)

    return {
        "static_analysis": static,
        "dynamic_analysis": dynamic,
        "threat_intel": threat_intel,
        "ai_investigation": ai_result,
        "fraud_intent": fraud_result,
        "risk_score": score_result,
    }
