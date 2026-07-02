import logging
import os
from typing import List

logger = logging.getLogger(__name__)

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION_NAME = "sentinel_knowledge"
DEFAULT_TOP_K = 5


def retrieve_context(query: str, top_k: int = DEFAULT_TOP_K, source_filter: str = None) -> List[dict]:
    try:
        import chromadb
        from sentence_transformers import SentenceTransformer

        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        collection = client.get_or_create_collection(COLLECTION_NAME)

        embedder = SentenceTransformer(EMBED_MODEL)
        query_embedding = embedder.encode([query])[0].tolist()

        where = {"source": source_filter} if source_filter else None
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        return [
            {
                "content": doc,
                "source": meta.get("source", "unknown"),
                "file": meta.get("file", ""),
                "relevance": round(1 - dist, 4),
            }
            for doc, meta, dist in zip(docs, metas, distances)
        ]

    except Exception as exc:
        logger.warning("ChromaDB retrieval failed: %s", exc)
        return _fallback_context(query)


def _fallback_context(query: str) -> List[dict]:
    query_lower = query.lower()

    if "sms" in query_lower or "otp" in query_lower:
        return [{
            "content": "T1412 - Capture SMS Messages: Adversaries may capture SMS messages to obtain credentials or OTPs sent by banking applications.",
            "source": "mitre",
            "file": "mobile_attack.txt",
            "relevance": 0.85,
        }]
    if "overlay" in query_lower or "accessibility" in query_lower:
        return [{
            "content": "T1417 - Input Capture: Malicious applications abuse Android Accessibility Services to capture user input on banking apps through overlay attacks.",
            "source": "mitre",
            "file": "mobile_attack.txt",
            "relevance": 0.82,
        }]
    return [{
        "content": "Android banking trojans commonly combine multiple attack vectors: SMS interception for OTP theft, overlay attacks for credential harvesting, and C2 communication for data exfiltration.",
        "source": "malware_intel",
        "file": "banking_trojan_overview.txt",
        "relevance": 0.70,
    }]
