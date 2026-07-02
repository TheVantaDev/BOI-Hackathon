from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.apk import APKUpload, RiskReport
from services.db import get_db

router = APIRouter()


@router.get("/{apk_id}")
def get_report(apk_id: str, db: Session = Depends(get_db)):
    apk = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")

    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    if not report:
        if apk.status in ("pending", "processing"):
            raise HTTPException(status_code=202, detail="Analysis still in progress")
        raise HTTPException(status_code=404, detail="Report not generated yet")

    return {
        "apk_id": str(apk.id),
        "filename": apk.filename,
        "sha256": apk.sha256,
        "upload_time": apk.upload_time,
        "risk_score": report.risk_score,
        "severity": report.severity,
        "classification": report.classification,
        "fraud_intent": report.fraud_intent,
        "fraud_journey": report.fraud_journey,
        "executive_summary": report.executive_summary,
        "recommendations": report.recommendations,
        "mitre_mappings": report.mitre_mappings,
        "shap_explanations": report.shap_explanations,
        "created_at": report.created_at,
    }


@router.get("/{apk_id}/pdf")
def download_pdf(apk_id: str, db: Session = Depends(get_db)):
    report = db.query(RiskReport).filter(RiskReport.apk_id == apk_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    # TODO: generate PDF using weasyprint or reportlab
    return {"message": "PDF generation not yet implemented", "apk_id": apk_id}
