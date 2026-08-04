import asyncio
import logging
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from ioc_lookup import (
    check_domain, check_ip, check_hash,
    check_urls_batch, map_to_mitre,
    _mitre_from_ioc_findings,
)

app = FastAPI(title="Threat Intelligence Service")
logger = logging.getLogger(__name__)


class IOCPayload(BaseModel):
    domains: List[str] = []
    ips: List[str] = []
    hashes: List[str] = []
    urls: List[str] = []
    # Static analysis signals for MITRE mapping (optional)
    permissions: List[dict] = []
    suspicious_apis: List[str] = []
    dynamic_code_loading: bool = False


@app.post("/lookup")
async def lookup_iocs(payload: IOCPayload):
    domain_tasks = [check_domain(d) for d in payload.domains[:20]]
    ip_tasks = [check_ip(ip) for ip in payload.ips[:20]]
    hash_tasks = [check_hash(h) for h in payload.hashes[:5]]

    domain_results, ip_results, hash_results = await asyncio.gather(
        asyncio.gather(*domain_tasks),
        asyncio.gather(*ip_tasks),
        asyncio.gather(*hash_tasks),
    )

    url_results = await check_urls_batch(payload.urls)

    all_indicators = list(domain_results) + list(ip_results) + list(hash_results) + url_results
    malicious = [i for i in all_indicators if i["malicious"]]

    # Build MITRE mapping from TWO sources:
    # 1. IOC findings (malicious domains/IPs/URLs → C2, phishing techniques)
    mitre_from_iocs = _mitre_from_ioc_findings(
        malicious_domains=[i["indicator"] for i in domain_results if i["malicious"]],
        malicious_ips=[i["indicator"] for i in ip_results if i["malicious"]],
        malicious_hashes=[i["indicator"] for i in hash_results if i["malicious"]],
        malicious_urls=[i["indicator"] for i in url_results if i["malicious"]],
    )

    # 2. Static analysis signals (permissions/APIs → collection, discovery, impact)
    static_context = {
        "permissions": payload.permissions,
        "suspicious_apis": payload.suspicious_apis,
        "dynamic_code_loading": payload.dynamic_code_loading,
    }
    mitre_from_static = map_to_mitre(static_context)

    # Merge both sources, dedup by technique ID
    all_mitre = {t["id"]: t for t in mitre_from_iocs}
    for t in mitre_from_static:
        if t["id"] not in all_mitre:
            all_mitre[t["id"]] = t

    return {
        "indicators": all_indicators,
        "malicious_count": len(malicious),
        "malicious_domains": [i["indicator"] for i in domain_results if i["malicious"]],
        "malicious_ips": [i["indicator"] for i in ip_results if i["malicious"]],
        "malicious_hashes": [i["indicator"] for i in hash_results if i["malicious"]],
        "malicious_urls": [i["indicator"] for i in url_results if i["malicious"]],
        "mitre_techniques": list(all_mitre.values()),
        "sources_used": ["urlhaus", "openphish", "abuseipdb", "malwarebazaar", "local_blocklist"],
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "threat-intel"}
