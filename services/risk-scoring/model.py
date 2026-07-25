import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from feature_extractor import extract_features, FEATURE_NAMES

logger = logging.getLogger(__name__)
MODEL_PATH = Path(os.getenv("MODEL_PATH", "/app/models/xgb_risk_model.json"))

# Severity scores per class — must match training order in notebook
# CLASSES = ["Benign", "Riskware", "Adware", "SMS", "Banking"]
SEVERITY_VEC = np.array([5, 35, 55, 75, 95], dtype=np.float32)
CLASS_NAMES = ["Benign", "Riskware", "Adware", "SMS", "Banking"]

_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model

    if MODEL_PATH.exists():
        import xgboost as xgb
        _model = xgb.Booster()
        _model.load_model(str(MODEL_PATH))
        logger.info("Loaded XGBoost model from %s", MODEL_PATH)
    else:
        logger.warning("No trained model found at %s — using heuristic scoring", MODEL_PATH)
        _model = "heuristic"

    return _model


def predict_score(features: np.ndarray) -> float:
    model = _load_model()

    if model == "heuristic":
        return _heuristic_score(features)

    try:
        import xgboost as xgb

        dmatrix = xgb.DMatrix(features.reshape(1, -1), feature_names=FEATURE_NAMES)

        # model was trained with multi:softprob — output shape is (n_samples, n_classes)
        best_iteration = getattr(model, 'best_iteration', 0)
        kwargs = {}
        if best_iteration > 0:
            kwargs["iteration_range"] = (0, best_iteration + 1)
        proba = model.predict(dmatrix, **kwargs)
        proba = np.array(proba).reshape(-1, len(CLASS_NAMES))

        # weighted sum: proba[0] @ severity_vec gives a continuous 0-100 risk score
        risk_score = float(proba[0] @ SEVERITY_VEC)
        return round(min(max(risk_score, 0.0), 100.0), 1)

    except Exception as exc:
        logger.warning("XGBoost prediction failed, falling back to heuristic: %s", exc)
        return _heuristic_score(features)


def predict_class(features: np.ndarray) -> Dict:
    model = _load_model()

    if model == "heuristic":
        return {"class": "Unknown", "probabilities": {}}

    try:
        import xgboost as xgb

        dmatrix = xgb.DMatrix(features.reshape(1, -1), feature_names=FEATURE_NAMES)
        best_iteration = getattr(model, 'best_iteration', 0)
        kwargs = {}
        if best_iteration > 0:
            kwargs["iteration_range"] = (0, best_iteration + 1)
        proba = model.predict(dmatrix, **kwargs)
        proba = np.array(proba).reshape(-1, len(CLASS_NAMES))[0]

        pred_idx = int(np.argmax(proba))
        return {
            "class": CLASS_NAMES[pred_idx],
            "confidence": round(float(proba[pred_idx]), 4),
            "probabilities": {cls: round(float(p), 4) for cls, p in zip(CLASS_NAMES, proba)},
        }
    except Exception as exc:
        logger.warning("Class prediction failed: %s", exc)
        return {"class": "Unknown", "probabilities": {}}


def explain_score(features: np.ndarray) -> List[Dict]:
    model = _load_model()

    if model == "heuristic":
        return _heuristic_explanation(features)

    try:
        import shap
        import xgboost as xgb

        explainer = shap.TreeExplainer(model)
        raw_shap = explainer.shap_values(features.reshape(1, -1))

        sv = np.asarray(raw_shap) if not isinstance(raw_shap, list) else np.stack(raw_shap, axis=0)

        # Collapse every axis except the one matching len(FEATURE_NAMES)
        feat_axis = sv.shape.index(len(FEATURE_NAMES))
        other_axes = tuple(a for a in range(sv.ndim) if a != feat_axis)

        # Use absolute mean for magnitude, signed mean for direction.
        # Previous bug: computed np.abs().mean() for both — direction was always
        # "increases_risk" because abs values are never negative.
        mean_abs_shap  = np.abs(sv).mean(axis=other_axes)   # magnitude
        mean_sign_shap = sv.mean(axis=other_axes)            # direction (signed)

        return [
            {
                "feature": FEATURE_NAMES[i],
                "value": float(features[i]),
                "shap_value": round(float(mean_abs_shap[i]), 4),
                "direction": (
                    "increases_risk" if mean_sign_shap[i] > 0
                    else "decreases_risk" if mean_sign_shap[i] < 0
                    else "neutral"
                ),
            }
            for i in range(len(FEATURE_NAMES))
        ]
    except Exception as exc:
        logger.warning("SHAP explanation failed: %s", exc)
        return _heuristic_explanation(features)


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
    raw = round(min(float(np.dot(normalized, weights)), 100.0), 1)

    # If ZERO confirmed dynamic threats (no SMS, no accessibility abuse, no C2,
    # no runtime downloads) AND no YARA matches AND no malicious IOCs,
    # cap at 40 (Low Risk / Suspicious at most).
    # This prevents ad-SDK apps (Ludo, games, OEM tools) with many static
    # permissions from being falsely flagged as Highly Malicious.
    has_dynamic_signal = (
        features[7] > 0   # sms_intercepted
        or features[8] > 0  # accessibility_abuse
        or features[9] > 0  # c2_connection_count
        or features[10] > 0  # runtime_downloads
        or features[2] > 0   # yara_match_count
        or features[6] > 0   # malicious_ioc_count
    )
    if not has_dynamic_signal:
        raw = min(raw, 40.0)

    return raw



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
