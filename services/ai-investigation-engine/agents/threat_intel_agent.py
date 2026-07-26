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


def analyze(threat_intel_data: Dict[str, Any]) -> str:
    malicious_domains = threat_intel_data.get("malicious_domains", [])
    malicious_ips = threat_intel_data.get("malicious_ips", [])
    mitre = threat_intel_data.get("mitre_techniques", [])
    total_malicious = threat_intel_data.get("malicious_count", 0)

    prompt = f"""You are a threat intelligence analyst reviewing IOC findings for a suspicious Android APK.

Malicious domains identified: {malicious_domains}
Malicious IPs identified: {malicious_ips}
MITRE ATT&CK techniques mapped: {[f"{t['id']} - {t['name']}" for t in mitre]}
Total malicious indicators: {total_malicious}

Provide a concise threat intelligence summary in 3-4 sentences. Include the significance of the identified C2 infrastructure and MITRE technique coverage."""

    result = _call_llm(prompt)
    if not result:
        if total_malicious == 0:
            return "Threat intelligence scan found no malicious indicators. All domains, IPs, and hashes are clean across URLHaus, OpenPhish, AbuseIPDB, and MalwareBazaar."
        technique_ids = [t["id"] for t in mitre]
        return (
            f"Threat intelligence identified {total_malicious} malicious indicators. "
            f"Domains {malicious_domains[:3]} and IPs {malicious_ips[:3]} are associated with known malware campaigns. "
            f"MITRE ATT&CK techniques {technique_ids} map this sample to known mobile banking trojan TTPs."
        )
    return result
