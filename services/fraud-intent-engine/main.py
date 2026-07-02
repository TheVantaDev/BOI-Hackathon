import logging
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from intent_predictor import predict_intent
from journey_builder import build_fraud_journey

app = FastAPI(title="Fraud Intent Engine")
logger = logging.getLogger(__name__)


class PredictRequest(BaseModel):
    apk_id: str
    analysis_summary: str = ""
    indicators: Dict[str, Any] = {}


@app.post("/predict")
async def predict(req: PredictRequest):
    try:
        intent_result = predict_intent(req.analysis_summary, req.indicators)
        primary_intent = intent_result.get("primary_intent", "credential_theft")
        journey = build_fraud_journey(primary_intent, req.indicators)

        return {
            "apk_id": req.apk_id,
            "intent": primary_intent,
            "secondary_intents": intent_result.get("secondary_intents", []),
            "confidence": intent_result.get("confidence", 0.5),
            "rationale": intent_result.get("rationale", ""),
            "journey": journey,
        }
    except Exception as exc:
        logger.exception("Fraud intent prediction failed: %s", exc)
        return {
            "apk_id": req.apk_id,
            "intent": "credential_theft",
            "secondary_intents": [],
            "confidence": 0.5,
            "rationale": "Default classification due to analysis error.",
            "journey": build_fraud_journey("credential_theft", {}),
        }


@app.get("/health")
def health():
    return {"status": "ok", "service": "fraud-intent-engine"}
