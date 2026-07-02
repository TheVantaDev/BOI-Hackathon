import logging
import os
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MALWAREBAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")

MITRE_TECHNIQUE_MAP = {
    "READ_SMS": {"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"},
    "RECEIVE_SMS": {"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"},
    "BIND_ACCESSIBILITY_SERVICE": {"id": "T1417", "name": "Input Capture", "tactic": "Collection"},
    "SYSTEM_ALERT_WINDOW": {"id": "T1417", "name": "Input Capture", "tactic": "Collection"},
    "DexClassLoader": {"id": "T1544", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "getDeviceId": {"id": "T1426", "name": "System Information Discovery", "tactic": "Discovery"},
    "sendTextMessage": {"id": "T1582", "name": "SMS Control", "tactic": "Impact"},
    "GET_ACCOUNTS": {"id": "T1516", "name": "Input Injection", "tactic": "Impact"},
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-c2.xyz", "bankingphish.ru", "apk-update.info",
    "secure-banking-in.com", "hdfc-verify.net",
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.45", "194.165.16.98", "45.142.212.100",
    "91.108.56.178", "194.61.24.102",
}


async def check_domain(domain: str) -> Dict:
    domain = domain.strip().lower()
    is_known = domain in KNOWN_MALICIOUS_DOMAINS

    if not is_known and MALWAREBAZAAR_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_taginfo", "tag": domain, "limit": 1},
                )
                data = resp.json()
                is_known = data.get("query_status") == "ok"
        except Exception:
            pass

    return {
        "indicator": domain,
        "type": "domain",
        "malicious": is_known,
        "source": "local_blocklist" if is_known else "clean",
    }


async def check_ip(ip: str) -> Dict:
    ip = ip.strip()
    is_known = ip in KNOWN_MALICIOUS_IPS
    abuse_score = 0

    if not is_known and ABUSEIPDB_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                )
                data = resp.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                is_known = abuse_score >= 50
        except Exception:
            pass

    return {
        "indicator": ip,
        "type": "ip",
        "malicious": is_known,
        "abuse_score": abuse_score,
        "source": "abuseipdb" if ABUSEIPDB_KEY else "local_blocklist",
    }


async def check_hash(sha256: str) -> Dict:
    is_malicious = False

    if MALWAREBAZAAR_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_info", "hash": sha256},
                )
                data = resp.json()
                is_malicious = data.get("query_status") == "ok"
        except Exception:
            pass

    return {
        "indicator": sha256,
        "type": "hash",
        "malicious": is_malicious,
        "source": "malwarebazaar",
    }


def map_to_mitre(static_data: Dict) -> List[Dict]:
    techniques = {}

    for perm in static_data.get("permissions", []):
        name = perm.get("name", "")
        if name in MITRE_TECHNIQUE_MAP:
            t = MITRE_TECHNIQUE_MAP[name]
            techniques[t["id"]] = t

    for api in static_data.get("suspicious_apis", []):
        if api in MITRE_TECHNIQUE_MAP:
            t = MITRE_TECHNIQUE_MAP[api]
            techniques[t["id"]] = t

    if static_data.get("dynamic_code_loading"):
        t = MITRE_TECHNIQUE_MAP["DexClassLoader"]
        techniques[t["id"]] = t

    return list(techniques.values())
