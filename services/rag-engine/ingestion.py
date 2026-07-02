import logging
import os
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION_NAME = "sentinel_knowledge"


def _get_chroma_collection():
    import chromadb
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    return client.get_or_create_collection(COLLECTION_NAME)


def _get_embedder():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(EMBED_MODEL)


def ingest_directory(directory: str, source_tag: str):
    collection = _get_chroma_collection()
    embedder = _get_embedder()

    docs = []
    ids = []
    metas = []

    for path in Path(directory).rglob("*.txt"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        chunks = _chunk_text(text, chunk_size=512, overlap=64)
        for i, chunk in enumerate(chunks):
            doc_id = f"{source_tag}_{path.stem}_{i}"
            docs.append(chunk)
            ids.append(doc_id)
            metas.append({"source": source_tag, "file": path.name, "chunk": i})

    if not docs:
        logger.warning("No .txt files found in %s", directory)
        return 0

    embeddings = embedder.encode(docs, show_progress_bar=False).tolist()
    collection.upsert(documents=docs, embeddings=embeddings, ids=ids, metadatas=metas)
    logger.info("Ingested %d chunks from %s into ChromaDB", len(docs), source_tag)
    return len(docs)


def ingest_mitre_docs(base_dir: str = "/app/knowledge_base/mitre"):
    return ingest_directory(base_dir, "mitre")


def ingest_capec(base_dir: str = "/app/knowledge_base/capec"):
    return ingest_directory(base_dir, "capec")


def ingest_cert_advisories(base_dir: str = "/app/knowledge_base/cert_in"):
    return ingest_directory(base_dir, "cert_in")


def ingest_malware_intel(base_dir: str = "/app/knowledge_base/malware_intel"):
    return ingest_directory(base_dir, "malware_intel")


def _chunk_text(text: str, chunk_size: int = 512, overlap: int = 64) -> List[str]:
    words = text.split()
    chunks = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks
