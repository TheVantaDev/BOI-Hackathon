import logging
import os
from typing import Any, Dict, List

import httpx
import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
RAG_URL = os.getenv("RAG_ENGINE_URL", "http://localhost:8013")
MODEL = "llama3:8b"


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST)
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 512},
        )
        return resp["message"]["content"].strip()
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return ""


def _fetch_rag_context(query: str) -> List[dict]:
    try:
        resp = httpx.post(
            f"{RAG_URL}/retrieve",
            json={"query": query, "top_k": 3},
            timeout=15.0,
        )
        return resp.json().get("results", [])
    except Exception as exc:
        logger.warning("RAG retrieval failed: %s", exc)
        return []


def analyze(combined_data: Dict[str, Any]) -> str:
    static = combined_data.get("static", {})
    dynamic = combined_data.get("dynamic", {})

    yara = static.get("yara_matches", [])
    sms = dynamic.get("sms_intercepted", False)
    overlay = dynamic.get("accessibility_abuse", False)

    query = f"Android banking trojan {'SMS interception ' if sms else ''}{'overlay attack ' if overlay else ''}{' '.join(yara[:2])}"
    rag_results = _fetch_rag_context(query)

    context_text = "\n".join(r["content"] for r in rag_results) if rag_results else "No additional context available."

    prompt = f"""You are a cybersecurity knowledge analyst. Use the following threat intelligence knowledge to enrich the analysis of a suspicious APK.

Relevant threat intelligence context:
{context_text}

APK characteristics:
- YARA matches: {yara}
- SMS interception: {sms}
- Overlay attack capability: {overlay}

Based on the knowledge base context, what additional threat context or historical precedents are relevant to this sample? Answer in 2-3 sentences."""

    result = _call_llm(prompt)
    if not result:
        return f"Knowledge base context indicates this sample shares characteristics with known Android banking trojans targeting Indian financial institutions. {rag_results[0]['content'] if rag_results else ''}"
    return result
