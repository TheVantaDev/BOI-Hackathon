from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
import tempfile
import zipfile
from pathlib import Path

from config import settings
from services.storage import download_apk
from models.apk import APKUpload, AnalysisResult
from services.db import get_db

logger = logging.getLogger(__name__)

CACHE_DIR = Path(tempfile.gettempdir()) / "sentinel_decompiled_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
MAX_CACHE_FILES = 50


def _evict_cache():
    cached = sorted(CACHE_DIR.glob("*.zip"), key=lambda p: p.stat().st_mtime)
    while len(cached) > MAX_CACHE_FILES:
        oldest = cached.pop(0)
        try:
            oldest.unlink()
            logger.info("Evicted cache file: %s", oldest.name)
        except OSError:
            pass


def get_cached_zip(apk_id: str, tool: str, minio_path: str) -> Path:
    cache_file = CACHE_DIR / f"{apk_id}_{tool}.zip"
    if not cache_file.exists():
        bucket_prefix = f"{settings.minio_bucket}/"
        if minio_path.startswith(bucket_prefix):
            object_name = minio_path[len(bucket_prefix):]
        else:
            object_name = minio_path
            
        try:
            logger.info("Downloading decompiled zip %s from MinIO...", object_name)
            zip_bytes = download_apk(object_name)
            with open(cache_file, "wb") as f:
                f.write(zip_bytes)
            _evict_cache()
        except Exception as exc:
            logger.error("Failed to download zip %s: %s", object_name, exc)
            raise HTTPException(status_code=404, detail="Decompiled zip file not found in storage")
            
    return cache_file


def list_zip_dir(zip_path: Path, dir_prefix: str = "") -> list:
    if dir_prefix and not dir_prefix.endswith('/'):
        dir_prefix += '/'
    
    with zipfile.ZipFile(zip_path, 'r') as z:
        names = z.namelist()
        
    files = []
    dirs = []
    
    prefix_len = len(dir_prefix)
    for name in names:
        if name.startswith(dir_prefix) and name != dir_prefix:
            relative = name[prefix_len:]
            parts = relative.split('/')
            if len(parts) == 1:
                if parts[0]:
                    files.append(parts[0])
            elif len(parts) > 1:
                dirs.append(parts[0])
                
    unique_dirs = sorted(list(set(dirs)))
    sorted_files = sorted(files)
    
    result = []
    for d in unique_dirs:
        result.append({
            "name": d,
            "path": (dir_prefix + d).strip('/'),
            "type": "directory"
        })
    for f in sorted_files:
        result.append({
            "name": f,
            "path": (dir_prefix + f).strip('/'),
            "type": "file"
        })
    return result

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


@router.get("/{apk_id}/decompiled/tree")
def get_decompiled_tree(
    apk_id: str,
    tool: str = "jadx",
    path: str = "",
    db: Session = Depends(get_db)
):
    if tool not in ("jadx", "apktool"):
        raise HTTPException(status_code=400, detail="Invalid tool parameter. Must be 'jadx' or 'apktool'")
        
    result = db.query(AnalysisResult).filter(AnalysisResult.apk_id == apk_id).first()
    if not result or not result.static_analysis:
        raise HTTPException(status_code=404, detail="Analysis result not found")
        
    decompiled = result.static_analysis.get("decompiled", {})
    zip_path_minio = decompiled.get(f"{tool}_path")
    if not zip_path_minio:
        raise HTTPException(status_code=404, detail=f"Decompiled files for tool '{tool}' not found")
        
    local_zip = get_cached_zip(apk_id, tool, zip_path_minio)
    
    try:
        tree = list_zip_dir(local_zip, path)
        return {"tree": tree}
    except Exception as exc:
        logger.exception("Failed to build directory tree from zip: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to list directory contents")


@router.get("/{apk_id}/decompiled/file")
def get_decompiled_file(
    apk_id: str,
    tool: str,
    path: str,
    db: Session = Depends(get_db)
):
    if tool not in ("jadx", "apktool"):
        raise HTTPException(status_code=400, detail="Invalid tool parameter. Must be 'jadx' or 'apktool'")
        
    result = db.query(AnalysisResult).filter(AnalysisResult.apk_id == apk_id).first()
    if not result or not result.static_analysis:
        raise HTTPException(status_code=404, detail="Analysis result not found")
        
    decompiled = result.static_analysis.get("decompiled", {})
    zip_path_minio = decompiled.get(f"{tool}_path")
    if not zip_path_minio:
        raise HTTPException(status_code=404, detail=f"Decompiled files for tool '{tool}' not found")
        
    local_zip = get_cached_zip(apk_id, tool, zip_path_minio)
    
    try:
        with zipfile.ZipFile(local_zip, 'r') as z:
            if path not in z.namelist():
                raise HTTPException(status_code=404, detail=f"File '{path}' not found in decompiled archive")
            content = z.read(path).decode("utf-8", errors="replace")
        return {"content": content}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to read file from zip: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read file from archive")
