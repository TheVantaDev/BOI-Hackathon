import logging
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from feature_extractor import extract_features
from model import predict_score, explain_score
from classifier import classify

app = FastAPI(title="Risk Scoring Service")
logger = logging.getLogger(__name__)


class ScoringRequest(BaseModel):
    static: Dict[str, Any] = {}
    dynamic: Dict[str, Any] = {}
    threat_intel: Dict[str, Any] = {}
    ai_confidence: float = 0.5


@app.post("/score")
def score(req: ScoringRequest):
    try:
        data = req.dict()
        features = extract_features(data)
        risk_score = predict_score(features)
        severity_info = classify(risk_score)
        shap_values = explain_score(features)

        return {
            "score": risk_score,
            "severity": severity_info["severity"],
            "classification": severity_info["classification"],
            "recommended_action": severity_info["action"],
            "shap_values": shap_values,
        }
    except Exception as exc:
        logger.exception("Risk scoring failed: %s", exc)
        return {
            "score": 50.0,
            "severity": "Suspicious",
            "classification": "Unknown",
            "recommended_action": "Manual review recommended.",
            "shap_values": [],
        }


@app.get("/health")
def health():
    return {"status": "ok", "service": "risk-scoring"}
