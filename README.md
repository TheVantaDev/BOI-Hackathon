# BOI Sentinel AI

> Generative AI-powered Android APK malware investigation and risk assessment platform for banking security.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2:3b-black?style=flat-square)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0-FF6600?style=flat-square)

---

## Overview

BOI Sentinel AI automates the investigation of suspicious Android APKs targeting banking customers. It combines reverse engineering, static analysis, dynamic sandbox execution, threat intelligence, and multi-agent generative AI to produce explainable risk scores and detailed investigation reports — without requiring manual malware analyst intervention and support.

Built for **Bank of India Hackathon Problem Statement-1**: *Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs*.

---

## Architecture

```
APK Upload
    │
    ▼
┌─────────────────────┐
│   Backend (FastAPI) │  ← SHA256 dedup, MinIO storage, pipeline orchestration
└──────────┬──────────┘
           │ async HTTP
    ┌──────┴───────────────────────────────────────┐
    │                                              │
    ▼                                              ▼
┌─────────────────┐                    ┌─────────────────────┐
│ Static Analysis │                    │  Dynamic Analysis   │
│  Androguard     │                    │  ADB + Frida +      │
│  YARA Rules     │                    │  Tcpdump Sandbox    │
└────────┬────────┘                    └──────────┬──────────┘
         │                                        │
         └──────────────┬─────────────────────────┘
                        │
                        ▼
           ┌─────────────────────┐
           │   Threat Intel      │  ← AbuseIPDB, MalwareBazaar, URLHaus
           │   IOC Lookup +      │
           │   MITRE ATT&CK Map  │
           └──────────┬──────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
           ▼                     ▼
  ┌──────────────┐    ┌─────────────────────────┐
  │  RAG Engine  │    │   AI Investigation      │
  │  ChromaDB +  │───▶│   Engine (5 Agents)     │
  │  BAAI/bge    │    │   llama3.2:3b            │
  └──────────────┘    └──────────┬──────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
       ┌────────────────────┐    ┌────────────────────┐
       │  Fraud Intent      │    │   Risk Scoring     │
       │  Engine            │    │   XGBoost + SHAP   │
       │  Journey Builder   │    │   0-100 Score      │
       └──────────┬─────────┘    └──────────┬─────────┘
                  │                         │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌────────────────────────┐
                  │   Investigation Report  │
                  │   + Risk Score + MITRE │
                  │   + Fraud Journey Graph│
                  └────────────────────────┘
```

---

## Features

| Feature | Description |
|---|---|
| **Automated APK Analysis** | Full pipeline runs without any manual steps |
| **AI Reverse Engineering** | Androguard decompilation with natural language explanation |
| **Static Analysis** | Permissions, APIs, YARA rules, obfuscation, string extraction |
| **Dynamic Sandbox** | ADB + Frida runtime monitoring, SMS/accessibility/network capture |
| **Threat Intelligence** | Domain, IP, and hash lookups against AbuseIPDB, MalwareBazaar, URLHaus |
| **RAG Knowledge Engine** | MITRE ATT&CK, CAPEC, CERT-In, malware intel via ChromaDB + BAAI/bge-small |
| **Multi-Agent AI** | 5 specialist Ollama agents + central analyst for explainable findings |
| **Fraud Intent Reconstruction** | Predicts attacker objective, builds Cytoscape fraud journey graph |
| **Explainable Risk Scoring** | XGBoost model with SHAP feature importance, 4-tier classification |
| **Investigation Reports** | Executive summary, MITRE mappings, recommendations, fraud journey |

---

## Tech Stack

### Backend & API
- **Python 3.11** · **FastAPI** · **Uvicorn**
- **PostgreSQL** · **SQLAlchemy**
- **MinIO** (APK object storage) · **boto3**

### APK Analysis
- **Androguard** — decompilation, permissions, API detection
- **YARA** — malware signature matching
- **ADB** · **Frida** · **Tcpdump** — dynamic sandbox (Linux)

### AI & ML
- **Ollama** — local LLM hosting
- **llama3.2:3b** — threat summarization, fraud intent, bank action recommendations
- **XGBoost** — risk score classification
- **SHAP** — model explainability
- **scikit-learn** — feature pipeline

### RAG Layer
- **ChromaDB** — vector store
- **BAAI/bge-small-en-v1.5** — sentence embeddings
- **LlamaIndex** — knowledge ingestion

### Frontend
- **React 18** · **Vite** · **Tailwind CSS**
- **Recharts** — risk distribution charts
- **Cytoscape.js** — fraud journey attack chain visualization
- **Lucide React** — icons

### Infrastructure
- **Docker** · **Docker Compose**
- **PostgreSQL 15** · **MinIO** · **ChromaDB**

---

## Project Structure

```
BOI/
├── apps/
│   ├── backend/                  # FastAPI main application
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── models/apk.py         # SQLAlchemy ORM + Pydantic schemas
│   │   ├── services/
│   │   │   ├── db.py             # Database session factory
│   │   │   ├── storage.py        # MinIO client
│   │   │   └── pipeline.py       # Async microservice orchestrator
│   │   └── routers/
│   │       ├── upload.py         # POST /api/upload/
│   │       ├── analysis.py       # GET /api/analysis/{id}
│   │       ├── reports.py        # GET /api/reports/{id}
│   │       └── dashboard.py      # GET /api/dashboard/stats
│   └── frontend/                 # React + Vite + Tailwind SPA
│       └── src/
│           ├── pages/            # Dashboard, Upload, Analysis, History
│           └── components/       # Sidebar, RiskScoreCard, AttackChainGraph, ...
│
├── services/
│   ├── static-analysis/          # Port 8010 — Androguard + YARA
│   ├── dynamic-analysis/         # Port 8011 — ADB + Frida sandbox
│   ├── threat-intel/             # Port 8012 — IOC lookup + MITRE mapping
│   ├── rag-engine/               # Port 8013 — ChromaDB + embeddings
│   ├── ai-investigation-engine/  # Port 8014 — 5-agent Ollama system
│   │   └── agents/
│   │       ├── static_agent.py
│   │       ├── dynamic_agent.py
│   │       ├── threat_intel_agent.py
│   │       ├── knowledge_agent.py
│   │       └── central_analyst.py
│   ├── fraud-intent-engine/      # Port 8015 — intent prediction + journey builder
│   └── risk-scoring/             # Port 8016 — XGBoost + SHAP
│
├── infra/
│   ├── docker-compose.yml        # Full stack orchestration
│   ├── postgres/init.sql         # DB schema
│   └── .env.example              # Environment variable template
│
├── datasets/                     # Training data (AndroZoo, Drebin, etc.)
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── DEMO.md
├── infra/
│   └── setup_ollama.ps1          # Pull required AI model (llama3.2:3b)
├── scripts/
│   └── run_pipeline.py           # End-to-end test runner
└── tests/
    ├── test_backend.py
    └── test_static_analysis.py
```

---

## Quick Start

### Prerequisites

- Docker Desktop (or Docker Engine + Compose)
- 8 GB RAM minimum (16 GB recommended for Ollama)
- GPU optional but recommended for Ollama inference

### 1. Clone and configure

```bash
git clone https://github.com/TheVantaDev/BOI-Hackathon.git
cd BOI-Hackathon

cp infra/.env.example infra/.env
# Edit infra/.env to set any API keys (AbuseIPDB, MalwareBazaar)
```

### 2. Pull the AI model

Agents and the action recommender expect **`llama3.2:3b`**. Inside Docker Compose they call `http://ollama:11434`.

```powershell
# Windows (recommended)
powershell -File infra/setup_ollama.ps1

# Or manually:
cd infra
docker compose up -d ollama
docker compose exec ollama ollama pull llama3.2:3b
docker compose exec ollama ollama list
```

```bash
# Local Ollama (non-Docker services only)
ollama pull llama3.2:3b
```

### 3. Start the full stack

```bash
docker compose -f infra/docker-compose.yml up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/api/docs |
| MinIO Console | http://localhost:9001 |
| ChromaDB | http://localhost:8001 |

### 4. Ingest knowledge base

```bash
# After uploading MITRE/CAPEC/CERT-In .txt files to the knowledge_base folders:
curl -X POST http://localhost:8013/ingest \
  -H "Content-Type: application/json" \
  -d '{"sources": ["mitre", "capec", "cert_in", "malware_intel"]}'
```

### 5. Analyze an APK

Upload via the web UI at **http://localhost:3000/upload**, or via API:

```bash
curl -X POST http://localhost:8000/api/upload/ \
  -F "file=@suspicious.apk"
```

```json
{
  "apk_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "sha256": "a3f8c2d1...",
  "filename": "suspicious.apk"
}
```

Poll status and retrieve the report:

```bash
curl http://localhost:8000/api/analysis/550e8400-e29b.../status
curl http://localhost:8000/api/reports/550e8400-e29b...
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload/` | Upload APK for analysis |
| `GET` | `/api/analysis/{id}` | Full analysis result |
| `GET` | `/api/analysis/{id}/status` | Pipeline status (pending/processing/completed/failed) |
| `GET` | `/api/reports/{id}` | Complete investigation report |
| `GET` | `/api/dashboard/stats` | Aggregate statistics |
| `GET` | `/api/dashboard/recent` | Recent uploads with risk data |
| `GET` | `/health` | Backend health check |

Full Swagger UI available at `/api/docs` when the backend is running.

---

## Risk Classification

| Score | Severity | Classification | Action |
|---|---|---|---|
| 0–29 | 🟢 Safe | Benign Application | No action required |
| 30–54 | 🟡 Low Risk | Potentially Unwanted | Monitor, review permissions |
| 55–74 | 🟠 Suspicious | Suspicious Application | Block distribution, manual review |
| 75–100 | 🔴 Highly Malicious | Confirmed Malware | Block IOCs, alert customers immediately |

---

## MITRE ATT&CK Coverage

The platform maps findings to MITRE ATT&CK for Mobile techniques including:

- **T1412** — Capture SMS Messages
- **T1417** — Input Capture (Overlay Attack)
- **T1544** — Ingress Tool Transfer (Dynamic Code Loading)
- **T1426** — System Information Discovery
- **T1430** — Location Tracking
- **T1582** — SMS Control

---

## Knowledge Base Setup

Populate the RAG knowledge base by adding `.txt` files to:

```
services/rag-engine/knowledge_base/
├── mitre/          ← MITRE ATT&CK Mobile technique descriptions
├── capec/          ← CAPEC attack pattern summaries
├── cert_in/        ← CERT-In security advisories
└── malware_intel/  ← Malware analysis reports
```

Then trigger ingestion via `POST /ingest` on the RAG engine service.

---

## Development

### Running services individually

```bash
# Backend only
cd apps/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend only
cd apps/frontend
npm install
npm run dev

# Any microservice
cd services/static-analysis
pip install -r requirements.txt
uvicorn main:app --reload --port 8010
```

### Running tests

```bash
pip install pytest httpx
pytest tests/ -v
```

---

## Threat Intel API Keys (Optional)

Add these to `infra/.env` to enable live IOC lookups:

| Variable | Source |
|---|---|
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/register |
| `MALWAREBAZAAR_API_KEY` | https://bazaar.abuse.ch/ |

Without keys, the platform uses its built-in blocklist and MITRE mappings.

---

## Datasets

Training data sources for the ML model:

| Dataset | Description |
|---|---|
| [AndroZoo](https://androzoo.uni.lu/) | Large-scale Android APK repository |
| [Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/) | Android malware classification |
| [CICMalDroid 2024](https://www.unb.ca/cic/datasets/) | Android malware behavioral data |
| [AMD](http://amd.arguslab.org/) | Android malware family identification |

---

## Team

**BOI Hackathon — PS-1 Submission**
Bank of India · Generative AI-Based APK Fraud Detection

---

## License

This project is developed for the Bank of India Hackathon. All rights reserved.
