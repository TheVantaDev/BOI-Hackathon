"""
model.py — Risk scoring using DREBIN-215 raw feature XGBoost model.

Model trained with binary:logistic outputs a single p(malicious) float.
Score formula:  risk_score = p_malicious × 100.0
"""
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from feature_extractor import (
    extract_features,
    extract_xgboost_features,
    _load_feature_names,
    FEATURE_NAMES,
)

logger = logging.getLogger(__name__)

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/app/models/xgb_risk_model.json"))

CLASS_NAMES  = ["Benign", "Malicious"]
SEVERITY_MAX = 100.0  # p_malicious × 100.0  (full probability → full score range)

_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model

    if MODEL_PATH.exists():
        import xgboost as xgb
        _model = xgb.Booster()
        _model.load_model(str(MODEL_PATH))
        # Pre-load feature names so the first request is fast
        _load_feature_names()
        logger.info("Loaded XGBoost model from %s", MODEL_PATH)
    else:
        logger.warning("No model at %s — using heuristic scoring", MODEL_PATH)
        _model = "heuristic"

    return _model


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_p_malicious(model, raw_data: dict) -> float:
    """
    Run the XGBoost model and return p(malicious) in [0, 1].

    The new model uses binary:logistic so model.predict() returns a
    1-D array of shape (n_samples,) — one probability per sample.
    """
    import xgboost as xgb
    from feature_extractor import DREBIN_FEATURE_NAMES, _load_feature_names

    feature_names = _load_feature_names()
    xgb_features  = extract_xgboost_features(raw_data)

    dmatrix = xgb.DMatrix(
        xgb_features.reshape(1, -1),
        feature_names=feature_names if feature_names else None,
    )

    best_iter = getattr(model, "best_iteration", 0)
    kwargs = {"iteration_range": (0, best_iter + 1)} if best_iter > 0 else {}

    raw = model.predict(dmatrix, **kwargs)
    raw = np.array(raw).ravel()

    # binary:logistic → shape (1,): single p(malicious)
    if raw.shape[0] == 1:
        return float(raw[0])

    # Fallback: multi:softprob with 2 classes → shape (1, 2)
    proba = raw.reshape(-1, 2)
    return float(proba[0][1])


def _confirmed_signal(raw_data: dict) -> bool:
    """True when at least one hard runtime/IOC threat signal is confirmed."""
    static  = raw_data.get("static",  {})
    dynamic = raw_data.get("dynamic", {})
    ti      = raw_data.get("threat_intel", {})
    return bool(
        static.get("yara_matches")
        or dynamic.get("sms_intercepted")
        or dynamic.get("sms_interception")         # dynamic analyzer field variant
        or dynamic.get("accessibility_abuse")
        or dynamic.get("overlay_attack_detected")
        or dynamic.get("overlay_attacks")           # dynamic analyzer field variant
        or ti.get("malicious_count", 0) > 0
        or any(isinstance(r, dict) and r.get("suspicious")
               for r in dynamic.get("network_requests", []))
    )


# ── Public API ───────────────────────────────────────────────────────────────

def predict_score(features: np.ndarray, _raw_data: dict = None) -> float:
    model = _load_model()

    if model == "heuristic":
        return _heuristic_score(features)

    try:
        p_mal = _get_p_malicious(model, _raw_data or {})

        # score = p(malicious) × 100
        risk_score = round(min(max(p_mal * SEVERITY_MAX, 0.0), 100.0), 1)

        # Confidence-aware safety cap when no confirmed runtime/IOC signals.
        # High-confidence ML predictions are trusted even without dynamic data;
        # low-confidence ones are capped to prevent false positives from
        # benign apps that happen to have suspicious-looking permissions.
        if _raw_data is not None and not _confirmed_signal(_raw_data):
            if p_mal >= 0.8:
                # Model is highly confident — trust the ML prediction
                pass
            elif p_mal >= 0.5:
                # Moderate confidence — allow "Suspicious" but not "Highly Malicious"
                cap = 55.0
                if risk_score > cap:
                    logger.info(
                        "Score capped at %.0f (moderate confidence, no confirmed signals): %.1f → %.1f",
                        cap, risk_score, cap,
                    )
                    risk_score = cap
            else:
                # Low confidence without signals — cap at Low Risk
                cap = 35.0
                if risk_score > cap:
                    logger.info(
                        "Score capped at %.0f (low confidence, no confirmed signals): %.1f → %.1f",
                        cap, risk_score, cap,
                    )
                    risk_score = cap

        return risk_score

    except Exception as exc:
        logger.warning("XGBoost prediction failed, falling back to heuristic: %s", exc)
        return _heuristic_score(features)


def predict_class(features: np.ndarray, _raw_data: dict = None) -> Dict:
    model = _load_model()

    if model == "heuristic":
        return {"class": "Unknown", "probabilities": {}}

    try:
        p_mal = _get_p_malicious(model, _raw_data or {})
        p_ben = 1.0 - p_mal
        pred  = "Malicious" if p_mal >= 0.5 else "Benign"
        return {
            "class":         pred,
            "confidence":    round(max(p_mal, p_ben), 4),
            "probabilities": {
                "Benign":    round(p_ben, 4),
                "Malicious": round(p_mal, 4),
            },
        }
    except Exception as exc:
        logger.warning("Class prediction failed: %s", exc)
        return {"class": "Unknown", "probabilities": {}}


def explain_score(features: np.ndarray) -> List[Dict]:
    """
    SHAP explanation. With 214 features the model can produce per-feature
    importance values automatically — no manual weight list needed.
    Falls back to heuristic explanation if SHAP fails.
    """
    model = _load_model()

    if model == "heuristic":
        return _heuristic_explanation(features)

    try:
        import shap
        from feature_extractor import _load_feature_names

        feature_names = _load_feature_names()
        if len(features) != len(feature_names):
            raise ValueError(
                f"Feature vector length {len(features)} != "
                f"expected {len(feature_names)}"
            )

        explainer  = shap.TreeExplainer(model)
        shap_vals  = explainer.shap_values(features.reshape(1, -1))
        sv         = np.array(shap_vals).ravel()   # (n_features,) for binary

        return [
            {
                "feature":    feature_names[i],
                "value":      float(features[i]),
                "shap_value": round(float(abs(sv[i])), 4),
                "direction":  (
                    "increases_risk" if sv[i] > 0
                    else "decreases_risk" if sv[i] < 0
                    else "neutral"
                ),
            }
            for i in range(len(feature_names))
        ]

    except Exception as exc:
        logger.warning("SHAP explanation failed: %s", exc)
        return _heuristic_explanation(features)


# ── Heuristic fallback (runs when no model file present) ─────────────────────

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
        10.0,  # quark_crime_count
        20.0,  # quark_max_confidence
        8.0,   # quark_banking_crime
        8.0,   # quark_sms_crime
    ], dtype=np.float32)

    normalizers = np.array(
        [10, 10, 5, 1, 1, 10, 5, 1, 1, 5, 3, 1, 10, 1, 1, 1],
        dtype=np.float32,
    )
    normalized = np.clip(features / normalizers, 0, 1)
    raw = round(min(float(np.dot(normalized, weights)), 100.0), 1)

    has_dynamic_signal = (
        features[7]  > 0  # sms_intercepted
        or features[8]  > 0  # accessibility_abuse
        or features[9]  > 0  # c2_connection_count
        or features[10] > 0  # runtime_downloads
        or features[2]  > 0  # yara_match_count
        or features[6]  > 0  # malicious_ioc_count
        or features[12] > 0  # quark_crime_count
        or features[13] > 0  # quark_max_confidence
    )
    if not has_dynamic_signal:
        raw = min(raw, 35.0)

    return raw


def _heuristic_explanation(features: np.ndarray) -> List[Dict]:
    contrib_weights = [4, 3, 8, 10, 8, 2, 12, 15, 15, 6, 5, 10, 10, 20, 8, 8]
    names = FEATURE_NAMES[:len(features)]
    return [
        {
            "feature":    names[i],
            "value":      float(features[i]),
            "shap_value": round(float(features[i]) * contrib_weights[i] / 100, 4),
            "direction":  "increases_risk" if features[i] > 0 else "neutral",
        }
        for i in range(len(names))
    ]
