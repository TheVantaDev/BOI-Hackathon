import asyncio
import hashlib
import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from models.apk import APKUpload, AnalysisResult, RiskReport
from services.db import get_db
from services.pipeline import run_pipeline
from services.storage import upload_apk

router = APIRouter()
logger = logging.getLogger(__name__)


def _sanitize(obj):
    """
    Recursively strip null bytes (\u0000) from all strings in a dict/list structure.
    PostgreSQL cannot store null bytes in text/JSON columns and raises DataError.
    APKs often contain null bytes in embedded metadata strings (e.g. Adobe XMP URLs).
    """
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(i) for i in obj]
    return obj


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _process_apk(apk_id: str, minio_path: str, sha256: str):
    """
    Runs the full analysis pipeline synchronously inside a background thread.
    Uses asyncio.run so we get a fresh event loop per background task.
    """
    from services.db import SessionLocal

    async def _run():
        result = await run_pipeline(apk_id, minio_path, sha256)
        return result

    db = SessionLocal()
    try:
        result = asyncio.run(_run())

        # Sanitize all string values — remove null bytes PostgreSQL can't store
        static  = _sanitize(result.get("static_analysis", {}))
        dynamic = _sanitize(result.get("dynamic_analysis", {}))
        ti      = _sanitize(result.get("threat_intel", {}))
        ai      = _sanitize(result.get("ai_investigation", {}))
        fraud   = _sanitize(result.get("fraud_intent", {}))
        score   = _sanitize(result.get("risk_score", {}))

        analysis = AnalysisResult(
            apk_id=apk_id,
            static_analysis=static,
            dynamic_analysis=dynamic,
            threat_intel=ti,
            ai_summary=ai.get("summary", ""),
        )
        db.add(analysis)

        report = RiskReport(
            apk_id=apk_id,
            risk_score=score.get("score", 0),
            severity=score.get("severity", "Unknown"),
            classification=score.get("classification", "Unknown"),
            fraud_intent=fraud.get("intent", "Unknown"),
            fraud_journey=fraud.get("journey"),
            executive_summary=ai.get("summary", ""),
            recommendations=ai.get("recommendations"),
            mitre_mappings=ti.get("mitre_techniques"),
            shap_explanations=score.get("shap_values"),
        )
        db.add(report)

        record = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
        if record:
            record.status = "completed"

        db.commit()
        logger.info("Pipeline completed for apk_id=%s", apk_id)

    except Exception as exc:
        logger.exception("Pipeline failed for apk_id=%s: %s", apk_id, exc)
        db.rollback()
        record = db.query(APKUpload).filter(APKUpload.id == apk_id).first()
        if record:
            record.status = "failed"
        db.commit()
    finally:
        db.close()


@router.post("/")
async def upload_apk_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    sha256 = _sha256(content)

    existing = db.query(APKUpload).filter(APKUpload.sha256 == sha256).first()
    if existing:
        if existing.status == "failed":
            # Re-run pipeline for failed uploads
            existing.status = "processing"
            db.commit()
            background_tasks.add_task(_process_apk, str(existing.id), existing.minio_path, sha256)
            return {
                "apk_id": str(existing.id),
                "status": "processing",
                "sha256": sha256,
                "duplicate": True,
            }
        else:
            return {
                "apk_id": str(existing.id),
                "status": existing.status,
                "sha256": sha256,
                "duplicate": True,
            }

    apk_id = str(uuid.uuid4())
    object_name = f"{apk_id}/{file.filename}"

    try:
        minio_path = upload_apk(content, object_name)
    except Exception as exc:
        logger.error("MinIO upload failed: %s", exc)
        raise HTTPException(status_code=503, detail="Storage service unavailable")

    record = APKUpload(
        id=apk_id,
        filename=file.filename,
        sha256=sha256,
        file_size=len(content),
        status="processing",
        minio_path=minio_path,
    )
    db.add(record)
    db.commit()

    background_tasks.add_task(_process_apk, apk_id, minio_path, sha256)

    return {
        "apk_id": apk_id,
        "status": "processing",
        "sha256": sha256,
        "filename": file.filename,
        "file_size": len(content),
        "duplicate": False,
    }
