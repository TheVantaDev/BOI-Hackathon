#!/usr/bin/env python3
"""
Startup script: waits for ChromaDB to be ready, then ingests the knowledge base.
Runs as a background thread so the FastAPI server starts immediately.
"""
import logging
import os
import sys
import threading
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("startup_ingest")

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
KB_BASE = "/app/knowledge_base"


def _wait_for_chroma(max_retries: int = 30, delay: int = 5) -> bool:
    """Poll ChromaDB until it's available (v2 heartbeat; v1 returns 410 on Chroma >=1.0)."""
    import httpx

    urls = [
        f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/heartbeat",
        f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v1/heartbeat",
    ]
    for attempt in range(max_retries):
        for url in urls:
            try:
                resp = httpx.get(url, timeout=5)
                if resp.status_code == 200:
                    logger.info("ChromaDB is ready via %s (attempt %d)", url, attempt + 1)
                    return True
            except Exception as exc:
                logger.info(
                    "ChromaDB not ready yet (attempt %d/%d) %s: %s",
                    attempt + 1,
                    max_retries,
                    url,
                    exc,
                )
        time.sleep(delay)
    logger.error("ChromaDB did not become ready after %d attempts", max_retries)
    return False


def _already_ingested() -> bool:
    """Check if the collection already has documents (skip re-ingestion on restart)."""
    try:
        import chromadb
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        collection = client.get_or_create_collection("sentinel_knowledge")
        count = collection.count()
        logger.info("ChromaDB sentinel_knowledge collection has %d documents", count)
        return count > 0
    except Exception as exc:
        logger.warning("Could not check ChromaDB collection count: %s", exc)
        return False


def _run_ingestion():
    """Full ingestion pipeline: waits for ChromaDB, then loads all knowledge base docs."""
    if not _wait_for_chroma():
        logger.error("Skipping knowledge base ingestion — ChromaDB unavailable")
        return

    if _already_ingested():
        logger.info("Knowledge base already ingested — skipping (use POST /ingest to force re-ingest)")
        return

    logger.info("Starting knowledge base ingestion...")
    try:
        sys.path.insert(0, "/app")
        from ingestion import ingest_mitre_docs, ingest_capec, ingest_cert_advisories, ingest_malware_intel

        counts = {}

        mitre_dir = os.path.join(KB_BASE, "mitre")
        if os.path.isdir(mitre_dir):
            counts["mitre"] = ingest_mitre_docs(mitre_dir)
            logger.info("MITRE ingestion complete: %d chunks", counts["mitre"])

        capec_dir = os.path.join(KB_BASE, "capec")
        if os.path.isdir(capec_dir):
            counts["capec"] = ingest_capec(capec_dir)
            logger.info("CAPEC ingestion complete: %d chunks", counts["capec"])

        cert_dir = os.path.join(KB_BASE, "cert_in")
        if os.path.isdir(cert_dir):
            counts["cert_in"] = ingest_cert_advisories(cert_dir)
            logger.info("CERT-In ingestion complete: %d chunks", counts["cert_in"])

        mal_dir = os.path.join(KB_BASE, "malware_intel")
        if os.path.isdir(mal_dir):
            counts["malware_intel"] = ingest_malware_intel(mal_dir)
            logger.info("Malware Intel ingestion complete: %d chunks", counts["malware_intel"])

        total = sum(counts.values())
        logger.info("Knowledge base ingestion COMPLETE. Total chunks indexed: %d | Breakdown: %s", total, counts)

    except Exception as exc:
        logger.exception("Knowledge base ingestion failed: %s", exc)


def start_background_ingestion():
    """Start ingestion in a daemon thread so it doesn't block app startup."""
    thread = threading.Thread(target=_run_ingestion, daemon=True, name="kb-ingest")
    thread.start()
    logger.info("Knowledge base ingestion thread started")


if __name__ == "__main__":
    # Allow running directly: python startup_ingest.py
    _run_ingestion()
