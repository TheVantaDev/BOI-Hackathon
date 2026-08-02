import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from agents.action_recommender import MODEL, OLLAMA_HOST, RAG_URL, recommend_actions
from orchestrator import run_investigation

app = FastAPI(title="AI Investigation Engine")
logger = logging.getLogger(__name__)


class InvestigationRequest(BaseModel):
    apk_id: str
    static: Dict[str, Any] = {}
    dynamic: Dict[str, Any] = {}
    threat_intel: Dict[str, Any] = {}


class RecommendActionsRequest(BaseModel):
    apk_id: str
    filename: Optional[str] = None
    package_name: Optional[str] = None
    severity: Optional[str] = None
    classification: Optional[str] = None
    fraud_intent: Optional[str] = None
    risk_score: Optional[float] = None
    executive_summary: Optional[str] = None
    static: Dict[str, Any] = {}
    dynamic: Dict[str, Any] = {}
    threat_intel: Dict[str, Any] = {}


@app.post("/investigate")
async def investigate(req: InvestigationRequest):
    try:
        result = await run_investigation(req.dict())
        result["apk_id"] = req.apk_id
        return result
    except Exception as exc:
        logger.exception("Investigation failed for %s: %s", req.apk_id, exc)
        return {
            "apk_id": req.apk_id,
            "summary": f"AI investigation could not complete. Check that Ollama is running with {MODEL}.",
            "classification": "Unknown",
            "recommendations": [
                "Ensure Ollama service is running",
                f"Pull model: docker compose exec ollama ollama pull {MODEL}",
            ],
            "mitre_mappings": [],
            "confidence": 0.0,
        }


@app.post("/recommend-actions")
def recommend_actions_endpoint(req: RecommendActionsRequest):
    """Bank playbook from findings + RAG/Ollama. Never raises — always returns a blob."""
    try:
        result = recommend_actions(req.dict())
        result["apk_id"] = req.apk_id
        return result
    except Exception as exc:
        logger.exception("Action recommendation failed for %s: %s", req.apk_id, exc)
        return {
            "apk_id": req.apk_id,
            "status": "failed",
            "generated_at": None,
            "query_used": None,
            "sources": [],
            "actions": [],
            "error": str(exc),
            "model": MODEL,
            "rag_hit_count": 0,
        }


def _check_ollama() -> Dict[str, Any]:
    try:
        resp = httpx.get(f"{OLLAMA_HOST.rstrip('/')}/api/tags", timeout=5.0)
        resp.raise_for_status()
        names = [m.get("name", "") for m in resp.json().get("models", [])]
        return {
            "ollama_ok": True,
            "model": MODEL,
            "model_present": any(MODEL in n or n.startswith(MODEL.split(":")[0]) for n in names),
            "models": names[:20],
        }
    except Exception as exc:
        return {"ollama_ok": False, "model": MODEL, "model_present": False, "error": str(exc)}


def _check_rag() -> Dict[str, Any]:
    try:
        resp = httpx.get(f"{RAG_URL.rstrip('/')}/health", timeout=5.0)
        resp.raise_for_status()
        return {"rag_ok": True, "rag_url": RAG_URL}
    except Exception as exc:
        return {"rag_ok": False, "rag_url": RAG_URL, "error": str(exc)}


@app.get("/health")
def health():
    ollama = _check_ollama()
    rag = _check_rag()
    ok = ollama.get("ollama_ok") and ollama.get("model_present") and rag.get("rag_ok")
    return {
        "status": "ok" if ok else "degraded",
        "service": "ai-investigation-engine",
        "ollama_url": OLLAMA_HOST,
        **ollama,
        **rag,
    }
