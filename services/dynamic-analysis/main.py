import logging

from fastapi import FastAPI
from pydantic import BaseModel

from sandbox import run_dynamic_analysis

app = FastAPI(title="Dynamic Analysis Service")
logger = logging.getLogger(__name__)


class APKRef(BaseModel):
    apk_id: str
    minio_path: str
    sha256: str


@app.post("/analyze")
async def analyze(ref: APKRef):
    try:
        result = await run_dynamic_analysis(ref.apk_id, ref.minio_path, sha256=ref.sha256)
        return result
    except RuntimeError as exc:
        logger.warning("Dynamic analysis skipped: %s", exc)
        return {"apk_id": ref.apk_id, "source": "unavailable", "skipped": True,
                "reason": str(exc), "network_requests": [], "sms_intercepted": False,
                "accessibility_abuse": False, "file_writes": [], "background_services": [],
                "runtime_downloads": [], "contacts_accessed": False,
                "microphone_accessed": False, "camera_accessed": False}
    except Exception as exc:
        logger.exception("Dynamic analysis failed for %s: %s", ref.apk_id, exc)
        return {"apk_id": ref.apk_id, "source": "error", "error": str(exc),
                "network_requests": [], "sms_intercepted": False,
                "accessibility_abuse": False, "file_writes": [], "background_services": [],
                "runtime_downloads": [], "contacts_accessed": False,
                "microphone_accessed": False, "camera_accessed": False}


@app.get("/health")
def health():
    return {"status": "ok", "service": "dynamic-analysis"}
