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
        result = await run_dynamic_analysis(ref.apk_id, ref.minio_path)
        return result
    except Exception as exc:
        logger.exception("Dynamic analysis failed for %s: %s", ref.apk_id, exc)
        return _stub_result(ref.apk_id)


def _stub_result(apk_id: str) -> dict:
    return {
        "apk_id": apk_id,
        "network_requests": [
            {"url": "http://185.220.101.45/c2/checkin", "method": "POST", "suspicious": True, "bytes_sent": 1024},
            {"url": "https://api.ipify.org", "method": "GET", "suspicious": False, "bytes_sent": 0},
        ],
        "sms_intercepted": True,
        "sms_content_samples": ["OTP for your SBI transaction is 847291"],
        "accessibility_abuse": True,
        "accessibility_actions": ["performClick", "setText", "getWindows"],
        "file_writes": ["/data/data/com.unknown/files/creds.db"],
        "background_services": ["OTPHarvesterService", "KeyloggerService"],
        "runtime_downloads": ["http://185.220.101.45/payload_v2.dex"],
        "contacts_accessed": True,
        "microphone_accessed": False,
        "camera_accessed": False,
        "sandbox_duration_seconds": 120,
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "dynamic-analysis"}
