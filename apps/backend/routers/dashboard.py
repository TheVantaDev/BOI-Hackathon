from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.apk import APKUpload, RiskReport
from services.db import get_db

router = APIRouter()


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(APKUpload.id)).scalar() or 0
    completed = db.query(func.count(APKUpload.id)).filter(APKUpload.status == "completed").scalar() or 0
    processing = db.query(func.count(APKUpload.id)).filter(APKUpload.status == "processing").scalar() or 0
    failed = db.query(func.count(APKUpload.id)).filter(APKUpload.status == "failed").scalar() or 0

    severity_rows = (
        db.query(RiskReport.severity, func.count(RiskReport.id))
        .filter(RiskReport.severity.isnot(None))
        .group_by(RiskReport.severity)
        .all()
    )
    severity_distribution = {row[0]: row[1] for row in severity_rows}

    avg_score = db.query(func.avg(RiskReport.risk_score)).scalar()

    recent = (
        db.query(APKUpload)
        .order_by(APKUpload.upload_time.desc())
        .limit(10)
        .all()
    )

    return {
        "total_uploads": total,
        "completed": completed,
        "processing": processing,
        "failed": failed,
        "average_risk_score": round(float(avg_score), 1) if avg_score else 0,
        "severity_distribution": severity_distribution,
        "recent_uploads": [
            {
                "apk_id": str(u.id),
                "filename": u.filename,
                "sha256": u.sha256,
                "status": u.status,
                "upload_time": u.upload_time,
                "file_size": u.file_size,
            }
            for u in recent
        ],
    }


@router.get("/recent")
def get_recent(limit: int = Query(default=20, le=100), db: Session = Depends(get_db)):
    uploads = (
        db.query(APKUpload, RiskReport)
        .outerjoin(RiskReport, APKUpload.id == RiskReport.apk_id)
        .order_by(APKUpload.upload_time.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "apk_id": str(u.id),
            "filename": u.filename,
            "sha256": u.sha256,
            "status": u.status,
            "upload_time": u.upload_time,
            "file_size": u.file_size,
            "risk_score": r.risk_score if r else None,
            "severity": r.severity if r else None,
            "classification": r.classification if r else None,
        }
        for u, r in uploads
    ]
