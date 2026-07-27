import logging
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from feature_extractor import extract_features, extract_xgboost_features
from model import predict_score, predict_class, explain_score
from classifier import classify

app = FastAPI(title="Risk Scoring Service")
logger = logging.getLogger(__name__)


class ScoringRequest(BaseModel):
    static: Dict[str, Any] = {}
    dynamic: Dict[str, Any] = {}
    threat_intel: Dict[str, Any] = {}
    ai_confidence: float = 0.0   # 0.0 matches training default (was 0.5 — wrong)


@app.post("/score")
def score(req: ScoringRequest):
    try:
        data = req.dict()

        # DREBIN 215-feature vector — used by XGBoost for scoring AND SHAP explanation
        xgb_features = extract_xgboost_features(data)

        # 16-feature heuristic vector — only used if XGBoost model is absent
        heuristic_features = extract_features(data)

        risk_score    = predict_score(heuristic_features, data)
        malware_class = predict_class(heuristic_features, data)
        severity_info = classify(risk_score)

        # Pass DREBIN features to explain_score so SHAP shows real feature names
        shap_values = explain_score(xgb_features if len(xgb_features) > 16 else heuristic_features)

        return {
            "score":              risk_score,
            "severity":           severity_info["severity"],
            "classification":     severity_info["classification"],
            "malware_family":     malware_class["class"],
            "class_probabilities": malware_class.get("probabilities", {}),
            "recommended_action": severity_info["action"],
            "shap_values":        shap_values,
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


@app.post("/debug/score")
def debug_score(req: ScoringRequest):
    """
    Debug endpoint — returns the raw DREBIN feature vector so you can see
    exactly what the model receives. Use this to diagnose all-zeros problems.
    """
    import numpy as np
    from feature_extractor import _load_feature_names, extract_drebin_features, _build_apk_signals

    data          = req.dict()
    feature_names = _load_feature_names()
    signals       = _build_apk_signals(data)
    vector        = extract_drebin_features(data)

    active_features = [
        {"index": i, "name": feature_names[i], "value": float(vector[i])}
        for i in range(len(vector)) if vector[i] > 0
    ]

    return {
        "total_features":   len(vector),
        "active_count":     int(vector.sum()),
        "active_features":  active_features,
        "signals_extracted": {
            "perm_short_count":  len(signals["perm_short"]),
            "perm_short":        sorted(signals["perm_short"])[:20],
            "api_strings_count": len(signals["api_strings"]),
            "api_strings_sample": sorted(signals["api_strings"])[:30],
            "intents_count":     len(signals["intents"]),
        },
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "risk-scoring"}
