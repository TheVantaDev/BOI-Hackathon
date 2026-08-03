"""Call AI engine /recommend-actions. Never raises — returns a status blob."""
import logging
from typing import Any, Dict

import httpx

from config import settings

logger = logging.getLogger(__name__)

# One LLM call (30s) + RAG (20s) + overhead; never blocks pipeline more than a minute
_TIMEOUT = httpx.Timeout(60.0, connect=10.0)


def fetch_recommended_actions(payload: Dict[str, Any]) -> Dict[str, Any]:
    apk_id = payload.get("apk_id", "unknown")
    try:
        resp = httpx.post(
            f"{settings.ai_engine_url}/recommend-actions",
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("recommend-actions returned non-object")
        return data
    except Exception as exc:
        logger.warning("recommend-actions failed for apk_id=%s: %s", apk_id, exc)
        return {
            "apk_id": apk_id,
            "status": "failed",
            "generated_at": None,
            "query_used": None,
            "sources": [],
            "actions": [],
            "error": str(exc),
        }
