from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.apk import APKUpload, AnalysisResult
from services.db import get_db

router = APIRouter()


@router.get("/{apk_id}")
def get_analysis(apk_id: str, db: Session = Depends(get_db)):
    apk = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")

    result = db.query(AnalysisResult).filter(AnalysisResult.apk_id == apk_id).first()

    return {
        "apk_id": str(apk.id),
        "filename": apk.filename,
        "sha256": apk.sha256,
        "file_size": apk.file_size,
        "upload_time": apk.upload_time,
        "status": apk.status,
        "static_analysis": result.static_analysis if result else None,
        "dynamic_analysis": result.dynamic_analysis if result else None,
        "threat_intel": result.threat_intel if result else None,
        "ai_summary": result.ai_summary if result else None,
    }


@router.get("/{apk_id}/status")
def get_status(apk_id: str, db: Session = Depends(get_db)):
    apk = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
    if not apk:
        raise HTTPException(status_code=404, detail="APK not found")
    return {"apk_id": str(apk.id), "status": apk.status}
