import logging

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict

from orchestrator import run_investigation

app = FastAPI(title="AI Investigation Engine")
logger = logging.getLogger(__name__)


class InvestigationRequest(BaseModel):
    apk_id: str
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
            "summary": "AI investigation could not complete. Check that Ollama is running with llama3:8b-instruct.",
            "classification": "Unknown",
            "recommendations": ["Ensure Ollama service is running", "Pull llama3:8b-instruct model"],
            "mitre_mappings": [],
            "confidence": 0.0,
        }


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-investigation-engine"}
