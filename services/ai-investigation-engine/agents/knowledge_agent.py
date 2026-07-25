import logging
import os
from typing import Any, Dict, List

import httpx
import ollama

logger = logging.getLogger(__name__)
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://localhost:11434")
RAG_URL = os.getenv("RAG_ENGINE_URL", "http://localhost:8013")
MODEL = "llama3:8b"
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


def _call_llm(prompt: str) -> str:
    try:
        client = ollama.Client(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
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
    overlay = dynamic.get("overlay_attack_detected", False)
    accessibility = dynamic.get("accessibility_abuse", False)
    obfuscated = static.get("obfuscation_detected", False)

    # Build a query that reflects ACTUAL findings, not always "banking trojan".
    # Previously: always queried "Android banking trojan SMS interception overlay attack"
    # even for clean apps — RAG returned banking trojan articles → LLM said "banking trojan".
    signal_terms = []
    if sms:
        signal_terms.append("SMS interception OTP theft")
    if overlay:
        signal_terms.append("overlay attack phishing")
    if accessibility:
        signal_terms.append("accessibility service abuse")
    if obfuscated:
        signal_terms.append("code obfuscation packer")
    if yara:
        signal_terms.extend(yara[:2])

    if not signal_terms:
        # Genuinely clean app — no point querying for malware context
        return "No significant threat intelligence context required. No malicious indicators were identified."

    query = "Android malware " + " ".join(signal_terms)
    rag_results = _fetch_rag_context(query)

    context_text = "\n".join(r["content"] for r in rag_results) if rag_results else "No additional context available."

    prompt = f"""You are a cybersecurity knowledge analyst. Use the following threat intelligence knowledge to enrich the analysis of an Android APK that shows potential malicious indicators.

Relevant threat intelligence context:
{context_text}

APK characteristics:
- YARA matches: {yara}
- SMS interception: {sms}
- Overlay attack capability: {overlay}
- Accessibility abuse: {accessibility}
- Obfuscation: {obfuscated}

Based on the knowledge base context, what additional threat context or historical precedents are relevant to this sample? Answer in 2-3 sentences. If the signals are ambiguous, say so."""

    result = _call_llm(prompt)
    if not result:
        if rag_results:
            return f"Knowledge base indicates similar samples have been associated with targeted Android banking fraud. {rag_results[0]['content']}"
        return f"Identified signals ({', '.join(signal_terms)}) are consistent with known Android malware behavior patterns."
    return result
