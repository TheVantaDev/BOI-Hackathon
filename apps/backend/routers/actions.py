"""Bank recommended actions — separate from the investigation report."""
import uuid
from io import BytesIO
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from models.apk import APKUpload, AnalysisResult, RiskReport
from services.action_client import fetch_recommended_actions
from services.db import get_db
from services.pdf_utils import html_to_pdf, render_template

router = APIRouter()


def _empty_actions(apk_id: str, status: str = "pending") -> Dict[str, Any]:
    return {
        "apk_id": apk_id,
        "status": status,
        "generated_at": None,
        "query_used": None,
        "sources": [],
        "actions": [],
    }


def _parse_apk_id(apk_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(apk_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid apk_id — use the real UUID from upload/dashboard, not <APK_ID>",
        )


def _load_apk_analysis(apk_id: str, db: Session):
    apk_uuid = _parse_apk_id(apk_id)
    apk = db.query(APKUpload).filter(APKUpload.id == apk_uuid).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")
    analysis = db.query(AnalysisResult).filter(AnalysisResult.apk_id == apk_uuid).first()
    if apk.status in ("pending", "processing") and not analysis:
        raise HTTPException(status_code=202, detail="Analysis still in progress")
    return apk, analysis


def _actions_payload(apk: APKUpload, analysis: Optional[AnalysisResult]) -> Dict[str, Any]:
    blob = (analysis.recommended_actions if analysis else None) or {}
    if not isinstance(blob, dict):
        blob = {}
    return {
        "apk_id": str(apk.id),
        "filename": apk.filename,
        "sha256": apk.sha256,
        "status": blob.get("status") or ("pending" if not blob else "unknown"),
        "generated_at": blob.get("generated_at"),
        "query_used": blob.get("query_used"),
        "sources": blob.get("sources") or [],
        "actions": blob.get("actions") or [],
        "error": blob.get("error"),
    }


@router.get("/{apk_id}")
def get_actions(apk_id: str, db: Session = Depends(get_db)):
    apk, analysis = _load_apk_analysis(apk_id, db)
    if not analysis or not analysis.recommended_actions:
        if apk.status in ("pending", "processing"):
            raise HTTPException(status_code=202, detail="Analysis still in progress")
        return _empty_actions(str(apk.id), status="missing")
    return _actions_payload(apk, analysis)


@router.get("/{apk_id}/pdf")
def download_actions_pdf(apk_id: str, db: Session = Depends(get_db)):
    apk, analysis = _load_apk_analysis(apk_id, db)
    payload = _actions_payload(apk, analysis)
    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()

    html = render_template(
        "actions.html",
        data=payload,
        severity=(report.severity if report else None),
        classification=(report.classification if report else None),
        risk_score=(report.risk_score if report else None),
    )
    pdf_bytes = html_to_pdf(html)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="actions-{apk_id}.pdf"'
        },
    )


@router.post("/{apk_id}/regenerate")
def regenerate_actions(apk_id: str, db: Session = Depends(get_db)):
    """Re-run recommender and overwrite stored playbook. Does not change the report."""
    apk, analysis = _load_apk_analysis(apk_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    static = analysis.static_analysis or {}
    package_name = (
        static.get("package_name")
        or (static.get("manifest") or {}).get("package_name")
        or (static.get("manifest") or {}).get("package")
        or ""
    )

    recommended = fetch_recommended_actions(
        {
            "apk_id": apk_id,
            "filename": apk.filename,
            "package_name": package_name,
            "severity": (report.severity if report else None) or "Unknown",
            "classification": (report.classification if report else None) or "Unknown",
            "fraud_intent": (report.fraud_intent if report else None) or "Unknown",
            "risk_score": report.risk_score if report else None,
            "executive_summary": (report.executive_summary if report else None) or "",
            "static": static if isinstance(static, dict) else {},
            "dynamic": analysis.dynamic_analysis if isinstance(analysis.dynamic_analysis, dict) else {},
            "threat_intel": analysis.threat_intel if isinstance(analysis.threat_intel, dict) else {},
        }
    )
    analysis.recommended_actions = recommended
    db.commit()
    db.refresh(analysis)
    return _actions_payload(apk, analysis)
