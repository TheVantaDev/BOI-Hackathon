import logging
import os
from typing import Any, Dict

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3:8b"


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.2, "num_predict": 512},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return ""


def analyze(dynamic_data: Dict[str, Any]) -> str:
    network = dynamic_data.get("network_requests", [])
    suspicious_net = [r for r in network if r.get("suspicious")]
    sms = dynamic_data.get("sms_intercepted", False)
    accessibility = dynamic_data.get("accessibility_abuse", False)
    services = dynamic_data.get("background_services", [])
    file_writes = dynamic_data.get("file_writes", [])

    prompt = f"""You are a malware analyst reviewing dynamic sandbox analysis results of an Android APK.

Network requests (suspicious): {[r.get("url") for r in suspicious_net]}
SMS interception detected: {sms}
Accessibility service abuse: {accessibility}
Background services spawned: {services}
Suspicious file writes: {file_writes}
Runtime downloads: {dynamic_data.get("runtime_downloads", [])}

Provide a concise technical summary of the runtime behavior in 3-4 sentences. Explain what this behavior indicates about the malware's intent."""

    result = _call_llm(prompt)
    if not result:
        behaviors = []
        if sms:
            behaviors.append("SMS interception for OTP theft")
        if accessibility:
            behaviors.append("accessibility service abuse for overlay attacks")
        if suspicious_net:
            behaviors.append(f"C2 communication with {len(suspicious_net)} malicious endpoints")
        return (
            f"Dynamic analysis revealed: {', '.join(behaviors) if behaviors else 'no significant behavioral indicators'}. "
            f"{len(services)} suspicious background services were spawned during execution."
        )
    return result
