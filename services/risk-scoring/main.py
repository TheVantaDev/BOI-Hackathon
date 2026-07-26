import logging
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from feature_extractor import extract_features
from model import predict_score, predict_class, explain_score
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
        features = extract_features(data)          # 16 features — for heuristic
        risk_score = predict_score(features, data)  # XGBoost uses 12 internally
        malware_class = predict_class(features, data)
        severity_info = classify(risk_score)
        shap_values = explain_score(features)

        return {
            "score": risk_score,
            "severity": severity_info["severity"],
            "classification": severity_info["classification"],
            "malware_family": malware_class["class"],
            "class_probabilities": malware_class.get("probabilities", {}),
            "recommended_action": severity_info["action"],
            "shap_values": shap_values,
        }
    except Exception as exc:
        logger.exception("Risk scoring failed: %s", exc)
        return {
            "score": 50.0,
            "severity": "Suspicious",
            "classification": "Unknown",
            "malware_family": "Unknown",
            "class_probabilities": {},
            "recommended_action": "Manual review recommended.",
            "shap_values": [],
        }


@app.get("/health")
def health():
    return {"status": "ok", "service": "risk-scoring"}
