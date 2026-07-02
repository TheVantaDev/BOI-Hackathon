import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from feature_extractor import extract_features, FEATURE_NAMES

logger = logging.getLogger(__name__)
MODEL_PATH = Path("/app/models/xgb_risk_model.pkl")

_model = None


def _load_or_create_model():
    global _model
    if _model is not None:
        return _model

    if MODEL_PATH.exists():
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("Loaded XGBoost model from %s", MODEL_PATH)
    else:
        logger.warning("No trained model found — using heuristic scoring")
        _model = "heuristic"

    return _model


def predict_score(features: np.ndarray) -> float:
    model = _load_or_create_model()

    if model == "heuristic":
        return _heuristic_score(features)

    try:
        import xgboost as xgb
        dmatrix = xgb.DMatrix(features.reshape(1, -1), feature_names=FEATURE_NAMES)
        prob = model.predict(dmatrix)[0]
        return round(float(prob) * 100, 1)
    except Exception as exc:
        logger.warning("XGBoost prediction failed, using heuristic: %s", exc)
        return _heuristic_score(features)


def _heuristic_score(features: np.ndarray) -> float:
    weights = np.array([
        4.0,   # dangerous_perm_count
        3.0,   # suspicious_api_count
        8.0,   # yara_match_count
        10.0,  # obfuscation_detected
        8.0,   # dynamic_code_loading
        2.0,   # hardcoded_url_count
        12.0,  # malicious_ioc_count
        15.0,  # sms_intercepted
        15.0,  # accessibility_abuse
        6.0,   # c2_connection_count
        5.0,   # runtime_downloads
        10.0,  # ai_confidence
    ], dtype=np.float32)

    normalizers = np.array([10, 10, 5, 1, 1, 10, 5, 1, 1, 5, 3, 1], dtype=np.float32)
    normalized = np.clip(features / normalizers, 0, 1)
    raw = float(np.dot(normalized, weights))
    return round(min(raw, 100.0), 1)


def explain_score(features: np.ndarray) -> List[Dict]:
    model = _load_or_create_model()

    try:
        import shap
        import xgboost as xgb

        if model == "heuristic":
            raise ValueError("No model for SHAP")

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features.reshape(1, -1))[0]

        return [
            {
                "feature": name,
                "value": float(features[i]),
                "shap_value": round(float(shap_values[i]), 4),
                "direction": "increases_risk" if shap_values[i] > 0 else "decreases_risk",
            }
            for i, name in enumerate(FEATURE_NAMES)
        ]
    except Exception:
        return _heuristic_explanation(features)


def _heuristic_explanation(features: np.ndarray) -> List[Dict]:
    contrib_weights = [4, 3, 8, 10, 8, 2, 12, 15, 15, 6, 5, 10]
    return [
        {
            "feature": FEATURE_NAMES[i],
            "value": float(features[i]),
            "shap_value": round(float(features[i]) * contrib_weights[i] / 100, 4),
            "direction": "increases_risk" if features[i] > 0 else "neutral",
        }
        for i in range(len(FEATURE_NAMES))
    ]


def train_model(X: np.ndarray, y: np.ndarray):
    import xgboost as xgb
    import joblib

    dtrain = xgb.DMatrix(X, label=y, feature_names=FEATURE_NAMES)
    params = {
        "objective": "reg:squarederror",
        "max_depth": 4,
        "eta": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "eval_metric": "rmse",
    }
    model = xgb.train(params, dtrain, num_boost_round=100)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("Model trained and saved to %s", MODEL_PATH)
    return model
