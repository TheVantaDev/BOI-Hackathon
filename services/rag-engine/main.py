import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

from ingestion import ingest_mitre_docs, ingest_capec, ingest_cert_advisories, ingest_malware_intel
from retrieval import retrieve_context
from startup_ingest import start_background_ingestion

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Trigger knowledge base ingestion into ChromaDB on startup (non-blocking)
    start_background_ingestion()
    yield


app = FastAPI(title="RAG Engine Service", lifespan=lifespan)


class RetrieveRequest(BaseModel):
    query: str
    top_k: int = 5
    source_filter: Optional[str] = None


class IngestRequest(BaseModel):
    sources: List[str] = ["mitre", "capec", "cert_in", "malware_intel"]


@app.post("/retrieve")
def retrieve(req: RetrieveRequest):
    results = retrieve_context(req.query, req.top_k, req.source_filter)
    return {
        "query": req.query,
        "results": results,
        "count": len(results),
    }


@app.post("/ingest")
def ingest(req: IngestRequest, background_tasks: BackgroundTasks):
    def _run_ingestion():
        counts = {}
        if "mitre" in req.sources:
            counts["mitre"] = ingest_mitre_docs()
        if "capec" in req.sources:
            counts["capec"] = ingest_capec()
        if "cert_in" in req.sources:
            counts["cert_in"] = ingest_cert_advisories()
        if "malware_intel" in req.sources:
            counts["malware_intel"] = ingest_malware_intel()
        logger.info("Ingestion complete: %s", counts)

    background_tasks.add_task(_run_ingestion)
    return {"message": "Ingestion started in background", "sources": req.sources}


@app.get("/health")
def health():
    return {"status": "ok", "service": "rag-engine"}
