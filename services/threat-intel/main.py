import asyncio
import logging
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from ioc_lookup import (
    check_domain, check_ip, check_hash,
    check_urls_batch, map_to_mitre,
)

app = FastAPI(title="Threat Intelligence Service")
logger = logging.getLogger(__name__)


class IOCPayload(BaseModel):
    domains: List[str] = []
    ips: List[str] = []
    hashes: List[str] = []
    urls: List[str] = []


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

    # Build MITRE mapping from actual threat intel findings.
    # Previous bug: passed domain strings as permission names to map_to_mitre(),
    # which only looks up Android permission/API names — always returned empty.
    mitre_from_iocs = _mitre_from_ioc_findings(
        malicious_domains=[i["indicator"] for i in domain_results if i["malicious"]],
        malicious_ips=[i["indicator"] for i in ip_results if i["malicious"]],
        malicious_hashes=[i["indicator"] for i in hash_results if i["malicious"]],
        malicious_urls=[i["indicator"] for i in url_results if i["malicious"]],
    )

    return {
        "indicators": all_indicators,
        "malicious_count": len(malicious),
        "malicious_domains": [i["indicator"] for i in domain_results if i["malicious"]],
        "malicious_ips": [i["indicator"] for i in ip_results if i["malicious"]],
        "malicious_hashes": [i["indicator"] for i in hash_results if i["malicious"]],
        "malicious_urls": [i["indicator"] for i in url_results if i["malicious"]],
        "mitre_techniques": mitre_from_iocs,
        "sources_used": ["urlhaus", "openphish", "abuseipdb", "malwarebazaar", "local_blocklist"],
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "threat-intel"}
