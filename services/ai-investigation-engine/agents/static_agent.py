import logging
import os
from typing import Any, Dict

import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = "llama3.2:3b"
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.2, "num_predict": 512},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return ""


def analyze(static_data: Dict[str, Any]) -> str:
    perms = [p["name"] for p in static_data.get("permissions", []) if p.get("dangerous")]
    apis = static_data.get("suspicious_apis", [])
    yara = static_data.get("yara_matches", [])
    obfuscated = static_data.get("obfuscation_detected", False)

    prompt = f"""You are a malware analyst reviewing static analysis results of an Android APK.

Dangerous permissions: {perms}
Suspicious APIs: {apis}
YARA rule matches: {yara}
Obfuscation detected: {obfuscated}
Dynamic code loading: {static_data.get("dynamic_code_loading", False)}
Hardcoded URLs: {static_data.get("hardcoded_urls", [])}

Provide a concise technical summary of the static analysis findings in 3-4 sentences.
If no dangerous signals are present, say the app appears benign. Only flag concerns that are actually present in the data."""

    result = _call_llm(prompt)
    if not result:
        return (
            f"Static analysis detected {len(perms)} dangerous permissions including {', '.join(perms[:3])}. "
            f"Found {len(apis)} suspicious API calls and {len(yara)} YARA rule matches. "
            f"Code obfuscation {'was' if obfuscated else 'was not'} detected."
        )
    return result
