import logging
import os
import time
from typing import Any, Dict, List
import ipaddress

import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MALWAREBAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

MITRE_TECHNIQUE_MAP = {
    "READ_SMS": {"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"},
    "RECEIVE_SMS": {"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"},
    "BIND_ACCESSIBILITY_SERVICE": {"id": "T1417", "name": "Input Capture", "tactic": "Collection"},
    "SYSTEM_ALERT_WINDOW": {"id": "T1417", "name": "Input Capture", "tactic": "Collection"},
    "DexClassLoader": {"id": "T1544", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "getDeviceId": {"id": "T1426", "name": "System Information Discovery", "tactic": "Discovery"},
    "sendTextMessage": {"id": "T1582", "name": "SMS Control", "tactic": "Impact"},
    "GET_ACCOUNTS": {"id": "T1516", "name": "Input Injection", "tactic": "Impact"},
    "RECORD_AUDIO": {"id": "T1429", "name": "Capture Audio", "tactic": "Collection"},
    "ACCESS_FINE_LOCATION": {"id": "T1430", "name": "Location Tracking", "tactic": "Collection"},
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-c2.xyz", "bankingphish.ru", "apk-update.info",
    "secure-banking-in.com", "hdfc-verify.net", "sbi-reward.com",
    "axis-bank-update.net", "paytm-kyc-verify.xyz",
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.45", "194.165.16.98", "45.142.212.100",
    "91.108.56.178", "194.61.24.102", "31.184.198.23", "5.188.86.172",
}

# In-memory OpenPhish cache with TTL so stale phishing domains get refreshed
_openphish_cache: set = set()
_openphish_loaded_at: float = 0.0
OPENPHISH_TTL_SECONDS = 6 * 3600  # refresh every 6 hours


async def _load_openphish_feed():
    """Load (or refresh) the OpenPhish feed. Re-fetches after OPENPHISH_TTL_SECONDS."""
    global _openphish_cache, _openphish_loaded_at
    now = time.time()
    if now - _openphish_loaded_at < OPENPHISH_TTL_SECONDS:
        return  # Cache still fresh
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(OPENPHISH_FEED_URL)
            if resp.status_code == 200:
                new_cache: set = set()
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("http"):
                        try:
                            domain = line.split("/")[2].lower()
                            new_cache.add(domain)
                        except Exception:
                            pass
                _openphish_cache = new_cache
                _openphish_loaded_at = now
                logger.info("OpenPhish feed refreshed: %d domains", len(_openphish_cache))
    except Exception as exc:
        logger.warning("OpenPhish feed fetch failed: %s", exc)


async def check_url_urlhaus(url: str) -> Dict:
    is_malicious = False
    threat_type = None
    tags = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{URLHAUS_API}/url/",
                data={"url": url},
            )
            data = resp.json()
            if data.get("query_status") == "is_listed":
                is_malicious = True
                threat_type = data.get("threat")
                tags = data.get("tags") or []
    except Exception as exc:
        logger.warning("URLHaus URL check failed: %s", exc)

    return {
        "indicator": url,
        "type": "url",
        "malicious": is_malicious,
        "threat_type": threat_type,
        "tags": tags,
        "source": "urlhaus",
    }


async def check_domain_openphish(domain: str) -> bool:
    await _load_openphish_feed()
    return domain.lower() in _openphish_cache


async def check_domain(domain: str) -> Dict:
    domain = domain.strip().lower()
    is_known = domain in KNOWN_MALICIOUS_DOMAINS
    sources = []

    if is_known:
        sources.append("local_blocklist")

    # OpenPhish check
    if not is_known:
        if await check_domain_openphish(domain):
            is_known = True
            sources.append("openphish")

    # URLHaus domain check
    if not is_known:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{URLHAUS_API}/host/",
                    data={"host": domain},
                )
                data = resp.json()
                if data.get("query_status") == "is_listed":
                    is_known = True
                    sources.append("urlhaus")
        except Exception as exc:
            logger.warning("URLHaus domain check failed: %s", exc)

    # MalwareBazaar tag check
    if not is_known and MALWAREBAZAAR_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_taginfo", "tag": domain, "limit": 1},
                )
                data = resp.json()
                if data.get("query_status") == "ok":
                    is_known = True
                    sources.append("malwarebazaar")
        except Exception:
            pass

    return {
        "indicator": domain,
        "type": "domain",
        "malicious": is_known,
        "source": ", ".join(sources) if sources else "clean",
    }


def _is_public_ip(ip: str) -> bool:
    """Return True only for globally routable IPs — skip private/loopback/reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )
    except ValueError:
        return False  # Not a valid IP at all


async def check_ip(ip: str) -> Dict:
    ip = ip.strip()

    # Skip private/loopback/reserved IPs — they are never IOCs and would waste
    # AbuseIPDB credits. Also avoids false positives from 127.0.0.1, 0.0.0.0, etc.
    if not _is_public_ip(ip):
        return {
            "indicator": ip,
            "type": "ip",
            "malicious": False,
            "abuse_score": 0,
            "source": "skipped_private",
        }

    is_known = ip in KNOWN_MALICIOUS_IPS
    abuse_score = 0
    sources = []

    if is_known:
        sources.append("local_blocklist")

    # URLHaus IP check
    if not is_known:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{URLHAUS_API}/host/",
                    data={"host": ip},
                )
                data = resp.json()
                if data.get("query_status") == "is_listed":
                    is_known = True
                    sources.append("urlhaus")
        except Exception as exc:
            logger.warning("URLHaus IP check failed: %s", exc)

    # AbuseIPDB check
    if ABUSEIPDB_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                )
                data = resp.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                if abuse_score >= 50:
                    is_known = True
                    sources.append("abuseipdb")
        except Exception:
            pass

    return {
        "indicator": ip,
        "type": "ip",
        "malicious": is_known,
        "abuse_score": abuse_score,
        "source": ", ".join(sources) if sources else "clean",
    }


async def check_hash(sha256: str) -> Dict:
    is_malicious = False
    malware_name = None

    # MalwareBazaar hash lookup (works without API key)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
            )
            data = resp.json()
            if data.get("query_status") == "ok":
                is_malicious = True
                info = data.get("data", [{}])
                malware_name = info[0].get("signature") if info else None
    except Exception as exc:
        logger.warning("MalwareBazaar hash check failed: %s", exc)

    return {
        "indicator": sha256,
        "type": "hash",
        "malicious": is_malicious,
        "malware_name": malware_name,
        "source": "malwarebazaar",
    }


async def check_urls_batch(urls: List[str]) -> List[Dict]:
    results = []
    for url in urls[:10]:
        result = await check_url_urlhaus(url)
        results.append(result)
    return results


def _mitre_from_ioc_findings(
    malicious_domains: List[str],
    malicious_ips: List[str],
    malicious_hashes: List[str],
    malicious_urls: List[str],
) -> List[Dict]:
    """
    Map threat intel IOC findings to MITRE ATT&CK techniques.
    Called from threat-intel/main.py after IOC lookup completes.

    Previous bug: main.py built a fake static_context with domain strings as
    'permission names' and passed them to map_to_mitre() which only knows
    Android permission names — the lookup always returned nothing.
    """
    techniques: dict = {}

    def _add(tech_id: str, name: str, tactic: str) -> None:
        if tech_id not in techniques:
            techniques[tech_id] = {"id": tech_id, "name": name, "tactic": tactic}

    if malicious_domains or malicious_urls:
        _add("T1583.001", "Acquire Infrastructure: Domains", "Resource Development")
        _add("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")

    if malicious_ips:
        _add("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")
        _add("T1095",     "Non-Application Layer Protocol", "Command and Control")

    if malicious_hashes:
        _add("T1436",     "Commonly Used Port", "Command and Control")

    if malicious_urls:
        # URLs in threat feeds are typically C2 drop zones or phishing pages
        _add("T1566.002", "Phishing: Spearphishing Link", "Initial Access")

    return list(techniques.values())


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
