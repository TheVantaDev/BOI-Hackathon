"""Post-report bank action playbook: RAG (Chroma) + Ollama, with rule fallback."""
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
RAG_URL = os.getenv("RAG_ENGINE_URL", "http://localhost:8013")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "30"))

OWNERS = {"SOC", "Fraud", "IT", "Legal"}
PRIORITIES = {"P1", "P2", "P3", "P4"}


def recommend_actions(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build structured bank actions from a compact findings summary."""
    signals = _extract_signals(payload)
    query = _build_query(signals)
    rag_results, rag_error = _fetch_rag_context(query) if query else ([], None)
    if query and not rag_results:
        logger.warning("RAG returned 0 docs for query=%r error=%s", query[:120], rag_error)

    sources = [
        {"source": r.get("source", "unknown"), "file": r.get("file", ""), "score": r.get("relevance")}
        for r in rag_results
    ]

    actions: Optional[List[dict]] = None
    status = "fallback"
    llm_error: Optional[str] = None
    parse_error: Optional[str] = None

    if query:
        raw, llm_error = _call_llm(_build_prompt(payload, signals, rag_results))
        if raw:
            actions = _parse_actions(raw)
            if not actions:
                parse_error = f"unparseable LLM JSON: {raw[:200]}"
                logger.warning("Action JSON parse failed: %s", parse_error)
        elif not llm_error:
            llm_error = "empty LLM response"

    if actions:
        status = "ready"
    else:
        actions = _fallback_actions(signals)

    result = {
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "query_used": query or None,
        "sources": sources,
        "actions": actions,
        "model": MODEL,
        "rag_hit_count": len(rag_results),
    }
    if status != "ready":
        if llm_error:
            result["llm_error"] = llm_error
        if parse_error:
            result["parse_error"] = parse_error
        if rag_error:
            result["rag_error"] = rag_error
    return result


def _extract_signals(payload: Dict[str, Any]) -> Dict[str, Any]:
    static = payload.get("static") or {}
    dynamic = payload.get("dynamic") or {}
    ti = payload.get("threat_intel") or {}

    yara = static.get("yara_matches") or []
    if not isinstance(yara, list):
        yara = []

    domains = ti.get("malicious_domains") or []
    ips = ti.get("malicious_ips") or []
    if not isinstance(domains, list):
        domains = []
    if not isinstance(ips, list):
        ips = []

    return {
        "severity": (payload.get("severity") or "Info"),
        "classification": payload.get("classification") or "Unknown",
        "fraud_intent": payload.get("fraud_intent") or "Unknown",
        "risk_score": payload.get("risk_score"),
        "yara": yara[:5],
        "sms": bool(dynamic.get("sms_intercepted") or dynamic.get("otp_interceptions_detected")),
        "overlay": bool(dynamic.get("overlay_attack_detected")),
        "accessibility": bool(dynamic.get("accessibility_abuse")),
        "c2": int(dynamic.get("c2_connections") or 0),
        "malicious_count": int(ti.get("malicious_count") or 0),
        "domains": [str(d) for d in domains[:5]],
        "ips": [str(i) for i in ips[:5]],
        "filename": payload.get("filename") or "",
        "package_name": payload.get("package_name") or static.get("package_name") or "",
    }


def _build_query(signals: Dict[str, Any]) -> str:
    terms = ["Bank of India Android malware incident response", str(signals["severity"])]
    if signals["sms"]:
        terms.append("SMS OTP interception customer alert")
    if signals["overlay"]:
        terms.append("overlay credential harvesting")
    if signals["accessibility"]:
        terms.append("accessibility ATS device takeover")
    if signals["c2"] or signals["malicious_count"] or signals["domains"] or signals["ips"]:
        terms.append("block IOC C2 perimeter")
    if signals["yara"]:
        terms.extend(str(y) for y in signals["yara"][:2])

    # Clean / Info with no signals — still retrieve light IR triage guidance
    if not any(
        [
            signals["sms"],
            signals["overlay"],
            signals["accessibility"],
            signals["c2"],
            signals["malicious_count"],
            signals["yara"],
            signals["domains"],
            signals["ips"],
        ]
    ):
        terms.append("low severity triage archive monitoring")

    return " ".join(terms)


def _fetch_rag_context(query: str) -> tuple:
    """Returns (results, error_message_or_None). Retries once — rag-engine may still be warming."""
    last_err = None
    for attempt in range(2):
        try:
            resp = httpx.post(
                f"{RAG_URL}/retrieve",
                json={"query": query, "top_k": 5},
                timeout=httpx.Timeout(20.0, connect=5.0),
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            if results:
                return results, None
            last_err = "RAG returned zero documents"
        except Exception as exc:
            last_err = str(exc)
            logger.warning("RAG retrieval failed (attempt %d): %s", attempt + 1, exc)
        if attempt == 0:
            import time
            time.sleep(2)
    return [], last_err


def _call_llm(prompt: str) -> tuple:
    """Returns (text, error_message_or_None)."""
    try:
        import ollama  # lazy: local self-check can run without the package

        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": 0.2, "num_predict": 400},
        )
        return resp["message"]["content"].strip(), None
    except Exception as exc:
        logger.warning("Ollama call failed (host=%s model=%s): %s", OLLAMA_HOST, MODEL, exc)
        return "", str(exc)


def _build_prompt(payload: Dict[str, Any], signals: Dict[str, Any], rag_results: List[dict]) -> str:
    # Keep context short — CPU llama3.2:3b truncates/times out on long prompts
    context = "\n---\n".join(
        (r.get("content") or "")[:280] for r in rag_results[:2]
    ) or "No knowledge-base context available."

    findings = {
        "severity": signals["severity"],
        "classification": signals["classification"],
        "yara": signals["yara"][:2],
        "sms": signals["sms"],
        "overlay": signals["overlay"],
        "accessibility": signals["accessibility"],
        "c2": signals["c2"],
        "domains": signals["domains"][:3],
        "ips": signals["ips"][:3],
    }

    example = {
        "actions": [
            {
                "priority": "P1",
                "owner": "SOC",
                "sla": "1 hour",
                "title": "Block malicious C2 domains",
                "steps": ["Block listed domains at proxy", "Monitor for DNS bypass"],
                "rationale": "Threat intel confirmed malicious infrastructure",
            },
            {
                "priority": "P1",
                "owner": "Fraud",
                "sla": "4 hours",
                "title": "Alert customers and reset credentials",
                "steps": ["Identify possible installs", "Force password and OTP reset"],
                "rationale": "SMS or overlay credential theft detected",
            },
            {
                "priority": "P2",
                "owner": "Legal",
                "sla": "24 hours",
                "title": "Escalate sample to CERT-In",
                "steps": ["Submit SHA-256 and IOCs", "Request store takedown if needed"],
                "rationale": "Confirmed banking malware requires external escalation",
            },
        ]
    }
    return f"""You are a Bank of India incident-response advisor.
Using the knowledge context and findings, write 3 concrete bank actions.
Return JSON matching this example shape (replace titles/steps/rationale for THIS case; never leave title or steps empty):

{json.dumps(example, ensure_ascii=False)}

Knowledge context:
{context}

Findings:
{json.dumps(findings, ensure_ascii=False)}
"""


def _normalize_action(item: dict) -> Optional[dict]:
    if not isinstance(item, dict):
        return None
    title = str(item.get("title") or "").strip()
    steps = item.get("steps") or []
    if not title or not isinstance(steps, list) or not steps:
        return None
    priority = str(item.get("priority") or "P3").upper()
    if priority not in PRIORITIES:
        priority = "P3"
    owner = str(item.get("owner") or "SOC")
    if owner not in OWNERS:
        owner = "SOC"
    return {
        "priority": priority,
        "owner": owner,
        "sla": str(item.get("sla") or "24 hours").strip(),
        "title": title[:200],
        "steps": [str(s).strip() for s in steps if str(s).strip()][:8],
        "rationale": str(item.get("rationale") or "").strip()[:500],
    }


def _parse_actions(raw: str) -> Optional[List[dict]]:
    if not raw:
        return None
    text = raw.strip()
    # Strip ```json fences if the model ignores instructions
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()

    data = None
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end])
        except json.JSONDecodeError:
            data = None

    items = data.get("actions") if isinstance(data, dict) else None
    cleaned: List[dict] = []
    if isinstance(items, list):
        for item in items[:6]:
            norm = _normalize_action(item)
            if norm:
                cleaned.append(norm)

    # Truncated LLM output: salvage complete {...} objects via brace depth
    if not cleaned:
        for obj in _extract_json_objects(text):
            norm = _normalize_action(obj)
            if norm:
                cleaned.append(norm)
            if len(cleaned) >= 4:
                break

    # Still truncated mid-object: pull title/owner/priority fields via regex
    if not cleaned:
        cleaned = _parse_partial_fields(text)

    return cleaned or None


def _parse_partial_fields(text: str) -> List[dict]:
    """Last-resort parse when llama truncates mid-JSON (common on CPU)."""
    cleaned: List[dict] = []
    # Split on action-like object starts
    chunks = re.split(r'\{\s*"priority"', text)
    for chunk in chunks[1:]:
        block = '{"priority"' + chunk
        priority_m = re.search(r'"priority"\s*:\s*"([^"]+)"', block)
        owner_m = re.search(r'"owner"\s*:\s*"([^"]+)"', block)
        title_m = re.search(r'"title"\s*:\s*"([^"]+)"', block)
        sla_m = re.search(r'"sla"\s*:\s*"([^"]+)"', block)
        rationale_m = re.search(r'"rationale"\s*:\s*"([^"]*)', block)
        steps = re.findall(r'"steps"\s*:\s*\[((?:[^\[\]]|\[[^\]]*\])*)\]', block)
        step_items: List[str] = []
        if steps:
            step_items = re.findall(r'"([^"]+)"', steps[0])
        if not step_items:
            # truncated steps array — keep any quoted fragments after "steps"
            after = re.search(r'"steps"\s*:\s*\[([\s\S]+)', block)
            if after:
                step_items = re.findall(r'"([^"]+)"', after.group(1))[:2]
        if not title_m:
            continue
        if not step_items:
            step_items = ["Execute this action per bank IR playbook", "Document outcome in the case ticket"]
        norm = _normalize_action(
            {
                "priority": priority_m.group(1) if priority_m else "P3",
                "owner": owner_m.group(1) if owner_m else "SOC",
                "sla": sla_m.group(1) if sla_m else "24 hours",
                "title": title_m.group(1),
                "steps": step_items,
                "rationale": (rationale_m.group(1) if rationale_m else "").rstrip('\\'),
            }
        )
        if norm:
            cleaned.append(norm)
        if len(cleaned) >= 4:
            break
    return cleaned


def _extract_json_objects(text: str) -> List[dict]:
    """Pull complete JSON objects from possibly truncated LLM output."""
    objs: List[dict] = []
    i = 0
    while i < len(text):
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_str = False
        esc = False
        for j in range(i, len(text)):
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[i : j + 1]
                    try:
                        parsed = json.loads(chunk)
                        if isinstance(parsed, dict) and "title" in parsed:
                            objs.append(parsed)
                    except json.JSONDecodeError:
                        pass
                    i = j + 1
                    break
        else:
            break
    return objs


def _fallback_actions(signals: Dict[str, Any]) -> List[dict]:
    """ponytail: rule templates when Ollama/JSON parse fails; upgrade = richer signal matrix."""
    sev = str(signals["severity"]).lower()
    malicious = any(
        [
            signals["sms"],
            signals["overlay"],
            signals["accessibility"],
            signals["c2"] > 0,
            signals["malicious_count"] > 0,
            bool(signals["yara"]),
            bool(signals["domains"]),
            bool(signals["ips"]),
        ]
    )

    if not malicious or sev in ("info", "low", "safe", "low risk"):
        return [
            {
                "priority": "P4",
                "owner": "SOC",
                "sla": "72 hours",
                "title": "Archive sample and continue routine monitoring",
                "steps": [
                    "Store the APK hash and report for baseline comparison",
                    "Re-scan if the app requests new dangerous permissions in updates",
                ],
                "rationale": "No confirmed malicious runtime or threat-intel signals.",
            },
            {
                "priority": "P3",
                "owner": "IT",
                "sla": "72 hours",
                "title": "Verify distribution channel",
                "steps": [
                    "Confirm how the APK was obtained (sideload, phishing, store mirror)",
                    "Add package name to watchlist if origin is untrusted",
                ],
                "rationale": "Low-severity sample still warrants provenance check.",
            },
        ]

    actions: List[dict] = []
    if signals["domains"] or signals["ips"] or signals["malicious_count"] > 0 or signals["c2"] > 0:
        ioc_bits = signals["domains"][:3] + signals["ips"][:3]
        block_detail = ", ".join(ioc_bits) if ioc_bits else "all malicious IOCs from the report"
        actions.append(
            {
                "priority": "P1",
                "owner": "SOC",
                "sla": "1 hour",
                "title": "Block associated IOCs at the network perimeter",
                "steps": [
                    f"Block indicators: {block_detail}",
                    "Update proxy/firewall deny lists and monitor for bypass attempts",
                ],
                "rationale": "Threat intelligence or C2 activity indicates active malicious infrastructure.",
            }
        )
    if signals["sms"] or signals["overlay"]:
        actions.append(
            {
                "priority": "P1",
                "owner": "Fraud",
                "sla": "4 hours",
                "title": "Alert potentially affected customers and force credential reset",
                "steps": [
                    "Identify customers who may have installed this APK",
                    "Prompt immediate password/OTP reset and freeze high-risk transactions if needed",
                ],
                "rationale": "SMS/OTP interception or overlay credential harvesting was detected.",
            }
        )
    if signals["accessibility"]:
        actions.append(
            {
                "priority": "P1",
                "owner": "Fraud",
                "sla": "4 hours",
                "title": "Treat as possible device takeover / ATS risk",
                "steps": [
                    "Flag accounts for enhanced transaction monitoring",
                    "Advise customers to revoke suspicious accessibility services",
                ],
                "rationale": "Accessibility abuse enables automated fraudulent transfers.",
            }
        )
    actions.append(
        {
            "priority": "P2",
            "owner": "Legal",
            "sla": "24 hours",
            "title": "Escalate sample to CERT-In / ecosystem partners",
            "steps": [
                "Submit APK SHA-256 and key IOCs to CERT-In",
                "Coordinate Play Protect / store takedown if distribution is active",
            ],
            "rationale": "Confirmed malicious APK targeting banking users requires external escalation.",
        }
    )
    if not actions:
        actions.append(
            {
                "priority": "P2",
                "owner": "SOC",
                "sla": "24 hours",
                "title": "Investigate and contain suspicious APK",
                "steps": [
                    "Review full analysis findings and block suspicious endpoints",
                    "Monitor for related variants sharing package or certificate",
                ],
                "rationale": f"Severity {signals['severity']} with malicious indicators requires containment.",
            }
        )
    return actions[:6]


if __name__ == "__main__":
    # Minimal checks that don't need Ollama/Chroma running
    parsed = _parse_actions(
        '{"actions":[{"priority":"P1","owner":"SOC","sla":"1h","title":"Block IOCs","steps":["block x"],"rationale":"c2"}]}'
    )
    assert parsed and parsed[0]["title"] == "Block IOCs"
    partial = _parse_actions(
        '{\n  "actions": [\n    {\n      "priority": "P1",\n      "owner": "SOC",\n'
        '      "sla": "1 hour",\n      "title": "Activate IR Team",\n'
        '      "steps": ["Notify SOC team, activ'
    )
    assert partial and partial[0]["title"] == "Activate IR Team", partial
    hot = _fallback_actions(
        _extract_signals(
            {
                "severity": "Critical",
                "static": {"yara_matches": ["Android_Banker"]},
                "dynamic": {"sms_intercepted": True, "c2_connections": 2},
                "threat_intel": {"malicious_count": 1, "malicious_domains": ["evil.example"]},
            }
        )
    )
    assert hot and all(a.get("title") and a.get("steps") for a in hot)
    print("action_recommender self-check OK", len(hot), "fallback,", len(partial), "partial")
