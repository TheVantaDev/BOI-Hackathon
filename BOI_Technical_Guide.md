# BOI Sentinel AI — Complete Technical Deep-Dive
### Judge Preparation Guide (Zero Fumble Edition)

> Every claim in this document is extracted directly from the source code. Nothing is made up.

---

# TABLE OF CONTENTS
1. [Project Overview & Problem Statement](#1-project-overview--problem-statement)
2. [System Architecture — The 7-Microservice Pipeline](#2-system-architecture--the-7-microservice-pipeline)
3. [Pipeline Execution Order — How Services Are Orchestrated](#3-pipeline-execution-order--how-services-are-orchestrated)
4. [Static Analysis Service (Port 8010)](#4-static-analysis-service-port-8010)
5. [Dynamic Analysis Service (Port 8011)](#5-dynamic-analysis-service-port-8011)
6. [Threat Intelligence Service (Port 8012)](#6-threat-intelligence-service-port-8012)
7. [RAG Knowledge Engine (Port 8013)](#7-rag-knowledge-engine-port-8013)
8. [AI Investigation Engine — Multi-Agent System (Port 8014)](#8-ai-investigation-engine--multi-agent-system-port-8014)
9. [Fraud Intent Engine (Port 8015)](#9-fraud-intent-engine-port-8015)
10. [Risk Scoring Engine — XGBoost (Port 8016)](#10-risk-scoring-engine--xgboost-port-8016)
11. [ML Datasets — What We Trained On](#11-ml-datasets--what-we-trained-on)
12. [Feature Extraction — Connecting Static Analysis to ML](#12-feature-extraction--connecting-static-analysis-to-ml)
13. [The Mathematics Behind Every ML Component](#13-the-mathematics-behind-every-ml-component)
14. [Infrastructure & Storage](#14-infrastructure--storage)
15. [Potential Judge Questions & Answers (FAQ)](#15-potential-judge-questions--answers-faq)

---

# 1. Project Overview & Problem Statement

**Hackathon:** Bank of India Hackathon — Problem Statement 1
**Problem:** *Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs*

**What BOI Sentinel AI does:** It automates the end-to-end investigation of suspicious Android APK files targeting banking customers. A bank security analyst uploads an APK → the platform automatically reverse-engineers it, runs it in a sandbox, checks threat intelligence feeds, uses AI to explain findings, predicts the attacker's intent, and produces an explainable 0-100 risk score with a full investigation report — all without any manual intervention.

---

# 2. System Architecture — The 7-Microservice Pipeline

The platform is built as **7 independent FastAPI microservices**, each in its own Docker container, orchestrated by a central backend.

| # | Service | Port | Responsibility |
|---|---------|------|----------------|
| 1 | **Static Analysis** | 8010 | Androguard + YARA + QuarkEngine APK reverse engineering |
| 2 | **Dynamic Analysis** | 8011 | MobSF + Frida sandbox runtime analysis (ADB+Frida fallback) |
| 3 | **Threat Intelligence** | 8012 | IOC lookup against URLHaus, OpenPhish, AbuseIPDB, MalwareBazaar |
| 4 | **RAG Engine** | 8013 | ChromaDB + BAAI/bge-small vector retrieval |
| 5 | **AI Investigation Engine** | 8014 | 5-agent Ollama (llama3.2:3b) orchestration |
| 6 | **Fraud Intent Engine** | 8015 | Attack intent prediction + Cytoscape journey graph |
| 7 | **Risk Scoring** | 8016 | XGBoost with SHAP explainability |

**Supporting Infrastructure:**
- **PostgreSQL 15** — Stores APK metadata, analysis results, risk reports (SQLAlchemy ORM)
- **MinIO** — S3-compatible object store for APK binaries and decompiled zips
- **ChromaDB** — Vector database for RAG knowledge documents
- **Ollama** — Local LLM server running `llama3.2:3b`

---

# 3. Pipeline Execution Order — How Services Are Orchestrated

The backend's `pipeline.py` orchestrates all 7 services in a carefully staged async pipeline:

```
Stage 1 (PARALLEL):  Static Analysis  ─┬─▶  JSON results
                     Dynamic Analysis  ─┘

Stage 2 (SEQUENTIAL): Threat Intel ──▶ (needs static IOCs as input)

Stage 3 (PARALLEL):  AI Investigation ─┬─▶  Combined context
                     Fraud Intent      ─┘

Stage 4 (SEQUENTIAL): Risk Scoring ──▶ (needs everything above)
```

**Why this order?**
- Static and Dynamic are independent → run in parallel to save time.
- Threat Intel needs the hardcoded URLs/IPs extracted by Static Analysis → must wait.
- AI Investigation and Fraud Intent both need static + dynamic + threat intel → run in parallel after Stage 2.
- Risk Scoring needs AI confidence + all features → runs last.

---

# 4. Static Analysis Service (Port 8010)

### What It Does
Reverse-engineers the APK binary to extract all static indicators without running the app.

### Tools Used (Actual Code)
| Tool | Version | Purpose |
|------|---------|---------|
| **Androguard** | 3.4.0a1 | APK parsing via `AnalyzeAPK()`: extracts permissions, manifest metadata, bytecode method/class references, strings |
| **YARA** | yara-python 4.5.0 | Signature-based malware detection using custom `.yar` rule files (e.g., `banking_trojan.yar`) |
| **QuarkEngine** | ≥23.9.1 | Behavioral crime scoring using Order Theory on Dalvik bytecode API call sequences |
| **APKTool** | v2.9.3 | Resource & manifest decompilation (runs in background thread to avoid blocking) |
| **JADX** | v1.5.0 | Java source code decompilation (runs in background thread, output uploaded to MinIO as zip) |

### Tools NOT Used
- **MobSF** is NOT used for static analysis.
- No cloud-based static analysis APIs are used.

### How It Extracts Data

**1. Permission Extraction:**
- Calls `a.get_permissions()` from Androguard
- Each permission is checked against a hardcoded `DANGEROUS_PERMISSIONS` set (19 permissions: `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `CAMERA`, `BIND_ACCESSIBILITY_SERVICE`, `BIND_DEVICE_ADMIN`, `REQUEST_INSTALL_PACKAGES`, etc.)
- **Important:** `SYSTEM_ALERT_WINDOW` is intentionally EXCLUDED from dangerous permissions because many legitimate apps (calculators, floating widgets) use it. Real overlay attacks are caught by the dynamic sandbox and YARA rules instead.

**2. Suspicious API Detection:**
- Scans ALL bytecode methods in the DEX for 18 specific suspicious API calls:
  `getDeviceId`, `getSubscriberId`, `getImei`, `getSimSerialNumber`, `sendTextMessage`, `sendMultipartTextMessage`, `execCommand`, `Runtime.getRuntime`, `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader`, `AccessibilityService`, `performGlobalAction`, `getInstalledPackages`, `getInstalledApplications`, `Cipher.getInstance`, `SecretKeySpec`, `Base64.decode`, `getDeclaredMethod`

**3. Full API Class/Method Extraction (for DREBIN ML model):**
- Walks every class definition in DEX bytecode
- Normalizes Dalvik format (`Landroid/telephony/SmsManager;`) → Java dotted format (`android.telephony.SmsManager`)
- Extracts method-level signatures (`TelephonyManager.getDeviceId`, `Runtime.exec`)
- This is critical because it provides the exact feature set the DREBIN-215 XGBoost model was trained on

**4. Obfuscation Detection:**
- Checks if >30% of class names are ≤2 characters (e.g., `a`, `b`, `ab`)
- This indicates ProGuard/R8 or deliberate obfuscation

**5. String Extraction (URLs & IPs):**
- Regex-scans all DEX strings for `https?://` URLs and dotted-quad IPs
- **URL Filtering:** Excludes ~50 known safe domains (Google, Facebook, Unity, ad SDKs like AppLovin, MoPub, Chartboost) to prevent false positives from games and ad-supported apps
- **IP Filtering:** Uses `ipaddress.ip_address()` to exclude private (192.168.x), loopback (127.x), link-local, multicast, and reserved IPs

**6. QuarkEngine Behavioral Crime Scoring:**
- QuarkEngine uses **Order Theory** — it traces specific API call sequences at the Dalvik bytecode level to detect "criminal behaviours" (e.g., `getDeviceId` → `sendTextMessage` = device ID exfiltration via SMS)
- Only runs banking/SMS/overlay/accessibility-relevant rules (filtered by keywords) to keep analysis fast
- Outputs: `quark_crime_count`, `quark_max_confidence` (0.0–1.0), `quark_banking_crime`, `quark_sms_crime`
- **Why this matters:** A calculator app may have `SEND_SMS` permission but no QuarkEngine crimes because it never sequences those API calls in a malicious way

**7. YARA Signature Scanning:**
- Compiles and runs all `.yar` rule files in the `rules/` directory against the raw APK binary
- Includes `banking_trojan.yar` with rules for known banking trojan families

### Static Risk Indicator Formula
```
risk_indicator_count = dangerous_perms + suspicious_apis + (yara_matches × 3) 
                     + (5 if obfuscated) + (4 if dynamic_code_loading)
```

---

# 5. Dynamic Analysis Service (Port 8011)

### What It Does
Executes the APK inside a sandboxed Android environment and monitors runtime behavior using Frida instrumentation.

### Architecture: Two-Tier Fallback System
1. **Primary:** MobSF (Mobile Security Framework) — full sandbox with Frida injection via MobSF's API
2. **Fallback:** Direct ADB + Frida CLI — when MobSF is unavailable

### MobSF Flow (Primary)
1. Download APK from MinIO (verifies SHA-256 integrity)
2. Upload to MobSF via `POST /api/v1/upload`
3. Run MobSF static scan via `POST /api/v1/scan` (populates MobSF's internal DB)
4. Start dynamic analysis via `POST /api/v1/dynamic/start_analysis`
5. Inject **7 custom Frida scripts** via `POST /api/v1/frida/instrument`
6. Wait for `ANALYSIS_TIMEOUT` (default: 300 seconds)
7. Stop analysis and retrieve dynamic report via `POST /api/v1/dynamic/report_json`
8. Fetch Frida logs via `POST /api/v1/frida/logs`
9. Merge MobSF report + Frida events into structured output

### ADB + Frida Fallback Flow
1. Connect to host emulator via `adb connect host.docker.internal:5555`
2. Record package list before/after to identify the installed package
3. Install APK via `adb install -r`
4. Launch via `adb shell monkey -p <package> -c android.intent.category.LAUNCHER 1`
5. Write combined Frida script to temp file, inject via `frida -U -l <script> -f <pkg> --no-pause --runtime=v8`
6. Capture `adb logcat -d -t 500` and parse for specific malware patterns

### The 7 Custom Frida Scripts (Executed In Order)
| # | Script | What It Hooks |
|---|--------|---------------|
| 1 | `anti_emulation_bypass.js` | Hooks `Build` properties (MODEL, HARDWARE, FINGERPRINT), `TelephonyManager` (fakes IMEI, IMSI, Indian phone number, Airtel operator), `SystemProperties` (ro.kernel.qemu), sensors, procfs. **Must run FIRST** so malware doesn't detect the sandbox |
| 2 | `ssl_bypass.js` | Bypasses TrustManager, HostnameVerifier, OkHttp CertificatePinner, Conscrypt TLS. Captures OkHttp/URLConnection traffic |
| 3 | `crypto_monitor.js` | Intercepts `Cipher.doFinal` (captures pre-encryption plaintext), `SecretKeySpec` (extracts AES/DES keys), `Base64.decode`, XOR decoding, `MessageDigest` hashes |
| 4 | `sms_monitor.js` | Hooks `SmsManager.sendTextMessage` & `sendMultipartTextMessage`, `SmsMessage` parsing, OTP regex matching, notification suppression |
| 5 | `overlay_detector.js` | Hooks `WindowManager.addView` for overlay windows (TYPE_APPLICATION_OVERLAY=2038, TYPE_PHONE=2002), monitors for **24 specific Indian banking app packages** (SBI, Paytm, PhonePe, HDFC, Axis, BoI, etc.) |
| 6 | `dex_loader_monitor.js` | Hooks `DexClassLoader`, `InMemoryDexClassLoader` (fileless in-memory execution), `PathClassLoader`, `Class.forName` reflection, file writes to `.dex/.apk/.jar/.so`, `Runtime.exec` shell commands |
| 7 | `accessibility_monitor.js` | Hooks `performGlobalAction` (screenshot, home, back), `dispatchGesture` injection, `findAccessibilityNodeInfosByText` for credential scraping (searches for banking keywords: password, pin, otp, aadhaar, pan, cvv) |

### What Runtime Behaviors Are Captured
- **Network/C2:** HTTP/HTTPS requests, decrypted C2 endpoints, suspicious domains
- **SMS/OTP:** Incoming SMS interception, outgoing SMS sends, OTP regex matches, forwarding detection
- **Accessibility Abuse (ATS):** performGlobalAction, gesture injection, UI text scraping
- **Overlay Attacks:** Banking app monitoring (24 Indian banks), overlay window creation
- **Dynamic Code Loading:** DexClassLoader, in-memory DEX, reflection
- **Crypto Extraction:** AES/DES keys, pre-encryption plaintext, Base64 decoding
- **Anti-Emulation Bypass:** How many emulator checks the malware attempted (and were bypassed)

---

# 6. Threat Intelligence Service (Port 8012)

### What It Does
Correlates IOCs (Indicators of Compromise) extracted by static analysis against live threat intelligence feeds and maps findings to MITRE ATT&CK.

### Threat Intelligence Sources (All Actually Used)
| Source | API Endpoint | What It Checks |
|--------|-------------|----------------|
| **URLHaus** (abuse.ch) | `POST https://urlhaus-api.abuse.ch/v1/url/` | URLs against known malware distribution |
| **URLHaus** (abuse.ch) | `POST https://urlhaus-api.abuse.ch/v1/host/` | Domains and IPs against known C2 infrastructure |
| **OpenPhish** | `GET https://openphish.com/feed.txt` | Domains against live phishing feed (cached in-memory with 6-hour TTL) |
| **AbuseIPDB** | `GET https://api.abuseipdb.com/api/v2/check` | IPs against abuse confidence score (flagged if ≥50). Requires API key. Private IPs automatically skipped |
| **MalwareBazaar** (abuse.ch) | `POST https://mb-api.abuse.ch/api/v1/` | SHA-256 hash lookup (no API key required). Domain tag lookup (requires API key) |
| **Local Blocklists** | In-memory sets | 8 known malicious domains (e.g., `malware-c2.xyz`, `bankingphish.ru`, `sbi-reward.com`) + 7 known malicious IPs |

### MITRE ATT&CK Mapping (Two Mechanisms)

**Mechanism 1 — IOC-Based Mapping (`_mitre_from_ioc_findings`):**
| Finding | MITRE Technique |
|---------|----------------|
| Malicious Domains/URLs | T1583.001 (Acquire Infrastructure: Domains), T1071.001 (Application Layer Protocol: Web) |
| Malicious URLs | T1566.002 (Phishing: Spearphishing Link) |
| Malicious IPs | T1071.001 + T1095 (Non-Application Layer Protocol) |
| Malicious Hashes | T1436 (Commonly Used Port) |

**Mechanism 2 — Android Permission/API Mapping (`map_to_mitre`):**
| Permission/API | MITRE Technique |
|---------------|----------------|
| READ_SMS, RECEIVE_SMS | T1412 (Capture SMS Messages) |
| BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW | T1417 (Input Capture) |
| DexClassLoader | T1544 (Ingress Tool Transfer) |
| getDeviceId | T1426 (System Information Discovery) |
| sendTextMessage | T1582 (SMS Control) |
| GET_ACCOUNTS | T1516 (Input Injection) |
| RECORD_AUDIO | T1429 (Capture Audio) |
| ACCESS_FINE_LOCATION | T1430 (Location Tracking) |

---

# 7. RAG Knowledge Engine (Port 8013)

### What It Does
Provides the LLM with real-time, grounded cybersecurity context from curated knowledge documents — without needing to retrain the model.

### RAG Architecture
```
Knowledge Base (.txt files)
    │
    ▼ (ingestion.py)
Sentence Transformer: BAAI/bge-small-en-v1.5
    │  ↓ encodes text → 384-dim vectors
    ▼
ChromaDB (vector database)
    │  collection: "sentinel_knowledge"
    │
    ▼ (retrieval.py)
Query embedding → Cosine Similarity → Top-K results
    │
    ▼
Injected into LLM prompts as grounding context
```

### Knowledge Base Contents (23 Actual Text Files)

**MITRE ATT&CK Mobile (8 files):**
- `mobile_attack_full.txt`, `t1412_capture_sms.txt`, `t1417_input_capture_accessibility.txt`, `t1461_lockscreen_bypass.txt`, `t1476_malicious_app_delivery.txt`, `t1638_adversary_in_the_middle.txt`, `india_banking_threat_context.txt`

**CAPEC Attack Patterns (5 files):**
- `capec_151_identity_spoofing.txt`, `capec_98_164_phishing.txt`, `fraud_lifecycle_patterns.txt`, `mobile_banking_attack_patterns.txt`

**CERT-In Advisories (4 files):**
- `advisory_android_banking_malware_general.txt`, `advisory_india_banking_campaigns.txt`, `incident_response_procedures.txt`

**Malware Intelligence (6 files):**
- `banking_trojan_overview.txt`, `dynamic_analysis_behavioral_indicators.txt`, `malware_family_profiles.txt`, `overlay_attack_technical.txt`, `static_analysis_indicators.txt`

### Ingestion Process (How Documents Enter ChromaDB)
1. On service startup, `startup_ingest.py` runs as a daemon thread
2. Waits for ChromaDB to become ready (polls heartbeat endpoint, up to 30 retries)
3. Checks if collection already has documents (skips re-ingestion on restart)
4. For each `.txt` file: splits into chunks of **512 words with 64-word overlap**
5. Each chunk is encoded into a **384-dimensional dense vector** using `BAAI/bge-small-en-v1.5`
6. Upserted into ChromaDB collection `sentinel_knowledge` with metadata: `{source, file, chunk_index}`

### Retrieval Process (How Context Is Fetched)
1. A query string (e.g., "Android malware SMS interception OTP theft") is encoded into a 384-dim vector
2. ChromaDB computes **Cosine Similarity** between query vector and all document vectors
3. Top-K most similar documents are returned (default K=5)
4. Relevance score = `1 - distance` (ChromaDB returns L2 distances)

### Fallback (When ChromaDB Is Down)
The `_fallback_context()` function returns hardcoded MITRE technique descriptions based on keyword matching (SMS/OTP → T1412, overlay/accessibility → T1417).

---

# 8. AI Investigation Engine — Multi-Agent System (Port 8014)

### What It Does
Runs 5 specialist AI agents + 1 action recommender using `llama3.2:3b` via Ollama to produce an explainable investigation report.

### LLM Configuration
- **Model:** `llama3.2:3b` (Meta's Llama 3.2, 3 billion parameters)
- **Hosting:** Ollama (local, self-hosted — zero data leaves the bank's network)
- **Temperature:** 0.1–0.3 (low temperature for factual, deterministic outputs)
- **Max tokens:** 200–400 per agent call
- **Timeout:** 120 seconds per call (accommodates CPU-only inference)

### The 6 Agents

**Agent 1: Static Agent**
- **Input:** Dangerous permissions, suspicious APIs, YARA matches, obfuscation, dynamic code loading, hardcoded URLs
- **Prompt:** "You are a malware analyst reviewing static analysis results... Provide a concise technical summary in 3-4 sentences. If no dangerous signals are present, say the app appears benign."
- **Fallback:** If Ollama fails, generates a template-based summary from feature counts

**Agent 2: Dynamic Agent**
- **Input:** Suspicious network requests, SMS interception, accessibility abuse, background services, file writes, runtime downloads
- **Prompt:** "You are a malware analyst reviewing dynamic sandbox results... If no suspicious behavior was detected, clearly state the app showed no malicious runtime activity."
- **Fallback:** Lists detected behaviors (SMS, overlay, C2) or states "no significant behavioral indicators"

**Agent 3: Threat Intel Agent**
- **Input:** Malicious domains, malicious IPs, MITRE techniques, total malicious indicator count
- **Prompt:** "You are a threat intelligence analyst... Include the significance of identified C2 infrastructure and MITRE technique coverage."
- **Fallback:** States "no malicious indicators found" or lists IOC counts + MITRE technique IDs

**Agent 4: Knowledge Agent (RAG-Connected)**
- **Input:** Combined static + dynamic data
- **How it works:**
  1. Builds a dynamic search query based on ACTUAL malicious signals found (SMS → "SMS interception OTP theft", overlay → "overlay attack phishing", etc.)
  2. **Critical design decision:** If no signals are found, it does NOT query the RAG database — this prevents clean apps from being falsely associated with malware intelligence
  3. Calls RAG Engine `POST /retrieve` to get Top-3 relevant knowledge documents
  4. Passes retrieved context + APK characteristics to Ollama for enrichment

**Agent 5: Central Analyst (The Synthesizer)**
- **Input:** All 4 agent summaries + raw analysis data
- **Makes 2 separate LLM calls:**
  1. **Executive Summary** (300 tokens): Consolidates all findings into a 4-5 sentence paragraph. Explicitly instructed: "Do NOT invent threats that are not present in the data."
  2. **Classification** (20 tokens): Picks one label from: `Benign Application | Potentially Unwanted Application | Android Adware | Android Spyware | OTP Stealer / Banking Trojan | Banking Trojan with Overlay Attack | Dropper / Loader Malware | Confirmed Malware`
- **Confidence Scoring:** Starts at 0.0, only increases with CONFIRMED signals:
  - YARA matches: +0.35
  - SMS interception: +0.20
  - Accessibility abuse: +0.15
  - Overlay attack: +0.15
  - Malicious IOCs: +0.15
  - **Obfuscation and dynamic code loading contribute ZERO confidence** (because ProGuard/R8 and Unity/game SDKs use these legitimately)

**Agent 6: Action Recommender**
- **Input:** Severity, classification, fraud intent, risk score, all analysis data
- **How it works:** Queries RAG Engine for incident response context, then asks Ollama to generate 3 concrete bank actions as structured JSON with: `priority` (P1-P4), `owner` (SOC/Fraud/IT/Legal), `SLA`, `title`, `steps[]`, `rationale`
- **Robust parsing:** Handles truncated LLM JSON output via brace-depth extraction and regex-based partial field parsing

### Orchestration (How Agents Run)
```python
# Run 4 agents IN PARALLEL (asyncio.gather + asyncio.to_thread)
static_summary, dynamic_summary, ti_summary, knowledge_summary = await asyncio.gather(
    asyncio.to_thread(static_agent.analyze, static_data),
    asyncio.to_thread(dynamic_agent.analyze, dynamic_data),
    asyncio.to_thread(threat_intel_agent.analyze, ti_data),
    asyncio.to_thread(knowledge_agent.analyze, data),
)
# Then Central Analyst consolidates all 4 summaries
result = await asyncio.to_thread(central_analyst.consolidate, ...)
```
This is ~3-4x faster than sequential execution.

---

# 9. Fraud Intent Engine (Port 8015)

### What It Does
Predicts the attacker's objective and builds a visual attack chain (fraud journey graph).

### Intent Prediction (`intent_predictor.py`)
1. Extracts feature map: `sms_interception`, `accessibility_abuse`, `overlay_attack`, `obfuscation`, `dangerous_permissions`, `yara_matches`, `c2_connections`
2. **Signal filter:** Only predicts intent if CONFIRMED signals exist. Obfuscation alone is intentionally excluded (ProGuard/R8 is standard on production apps)
3. **LLM Prediction:** If signals exist, asks Ollama to select a primary intent from: `[credential_theft, otp_interception, account_takeover, data_exfiltration, overlay_attack, device_takeover, fraud_transaction, benign]`
4. **Rule-Based Fallback** (when Ollama fails):
   - SMS + Accessibility → `account_takeover`
   - SMS only → `otp_interception`
   - Overlay or Accessibility → `overlay_attack`
   - C2 connections → `data_exfiltration`
   - YARA match → `credential_theft`
   - No signals → `benign`

### Journey Graph Builder (`journey_builder.py`)
- Maps predicted intent to pre-defined **attack lifecycle templates**
- Each template defines ordered milestones with: node ID, label, type (`infection` → `persistence` → `collection` → `exfiltration` → `impact`)
- Formats nodes with visual styles (colors, shapes, x/y coordinates) for **Cytoscape.js** rendering in the frontend
- Links consecutive nodes into directed edge pairs

---

# 10. Risk Scoring Engine — XGBoost (Port 8016)

### What It Does
Produces the final 0-100 risk score using an XGBoost ML model + SHAP explainability.

### The Model: XGBoost (Gradient Boosted Trees)
- **Trained on:** DREBIN-215 feature schema (215 binary features)
- **Objective:** `binary:logistic` (outputs probability of maliciousness)
- **Input:** 215-dimensional binary feature vector (`[1.0, 0.0, 0.0, 1.0, ...]`)
- **Output:** `p(malicious)` ∈ [0, 1]
- **Final Risk Score:** `p_malicious × 100` (clamped to 0-100)

### Confidence-Aware Safety Caps (Preventing False Positives)
When NO confirmed runtime/IOC signals exist (no YARA, no SMS interception, no overlay, no malicious IOCs):
- **p ≥ 0.8:** Trust the ML prediction (model is highly confident)
- **0.5 ≤ p < 0.8:** Cap score at 55 (allow "Suspicious" but not "Highly Malicious")
- **p < 0.5:** Cap score at 35 (cap at "Low Risk")

This prevents benign apps with many permissions from being falsely scored as malware.

### SHAP Explainability
- Uses `shap.TreeExplainer` for XGBoost
- Computes per-feature Shapley values across all 215 features
- Each feature gets: `{feature_name, value, shap_value, direction: "increases_risk" | "decreases_risk" | "neutral"}`

### Risk Classification Tiers
| Score | Severity | Classification | Action |
|-------|----------|---------------|--------|
| 0–29 | 🟢 Safe | Benign Application | No action required |
| 30–54 | 🟡 Low Risk | Potentially Unwanted | Monitor, review permissions |
| 55–74 | 🟠 Suspicious | Suspicious Application | Block distribution, manual review |
| 75–100 | 🔴 Highly Malicious | Confirmed Malware | Block IOCs, alert customers immediately |

### Heuristic Fallback (When No Model File Exists)
If the XGBoost model file is missing, a weighted heuristic scorer runs using 16 manually weighted features:
```
Features: dangerous_perm_count (w=4), suspicious_api_count (w=3), yara_match_count (w=8),
          obfuscation (w=10), dynamic_code_loading (w=8), hardcoded_urls (w=2),
          malicious_ioc_count (w=12), sms_intercepted (w=15), accessibility_abuse (w=15),
          c2_connections (w=6), runtime_downloads (w=5), ai_confidence (w=10),
          quark_crime_count (w=10), quark_max_confidence (w=20),
          quark_banking_crime (w=8), quark_sms_crime (w=8)
```
Score = normalized weighted sum, capped at 35 if no dynamic/runtime signals.

---

# 11. ML Datasets — What We Trained On

| Dataset | Description | Used For |
|---------|-------------|----------|
| **DREBIN** | ~5,500 malware + benign samples. Provides the 215-feature binary feature schema (permissions, API calls, intents, shell commands) | XGBoost model training (primary) |
| **CICMalDroid 2024** | Behavioral Android malware data (banking trojans, ransomware, SMS stealers) | Model validation against modern malware |
| **AMD** | Android Malware Dataset with family identification | Additional malicious samples to prevent overfitting to older DREBIN data |

### Training Notebooks (4 iterations in the codebase)
1. `BOI(1).ipynb` — Initial exploration
2. `BOI_Sentinel_DREBIN_RawFeatures_v3.ipynb` — DREBIN raw feature extraction
3. `BOI_Sentinel_Retrain_DREBIN215_AutoDownload_v2.ipynb` — Automated DREBIN dataset download + retrain
4. `BOI_Sentinel_Train_v4.ipynb` — Final production training pipeline

---

# 12. Feature Extraction — Connecting Static Analysis to ML

This is the most critical pipeline in the entire system. It bridges the unstructured JSON output from the Static/Dynamic Analysis services to the structured 215-dimensional feature vector the XGBoost model expects.

### Step-by-Step Process (`feature_extractor.py`)

**Step 1: Load the exact 215 feature names**
```python
# Loads from models/drebin_feature_names.json
# Contains the exact 215 strings the model was trained on
feature_names = ["SEND_SMS", "READ_SMS", "Runtime.exec", "DexClassLoader", 
                 "android.intent.action.BOOT_COMPLETED", "/system/bin", ...]
```

**Step 2: Build APK signal sets from analysis output**
The `_build_apk_signals()` function extracts 5 signal sets from the JSON:
1. **`perm_short`**: Short permission names (`SEND_SMS`, `CAMERA`) — uppercase
2. **`perm_full`**: Full permission strings (`android.permission.send_sms`) — lowercase
3. **`api_strings`**: From `suspicious_apis` list (18 APIs)
4. **`intents`**: From manifest receivers, services, and intent_actions
5. **`shell`**: From hardcoded URLs, IPs, and shell command patterns

**Step 3: Dynamic analysis feedback injection**
If the dynamic sandbox detected actual runtime abuse, we forcefully inject the corresponding static markers:
```python
if dynamic.get("sms_intercepted"):
    perm_short.update({"SEND_SMS", "RECEIVE_SMS", "READ_SMS"})
    api_strings.add("sendTextMessage")
if dynamic.get("accessibility_abuse"):
    perm_short.add("BIND_ACCESSIBILITY_SERVICE")
if dynamic.get("overlay_attack_detected"):
    perm_short.add("SYSTEM_ALERT_WINDOW")
```
This ensures the ML model heavily penalizes proven runtime abuse, even if the static analysis missed the permission.

**Step 4: Match each of 215 DREBIN features against signals**
```python
vector = np.zeros(215, dtype=np.float32)
for i, fname in enumerate(feature_names):
    vector[i] = 1.0 if _feature_hit(fname, signals) else 0.0
```

The `_feature_hit()` function uses a multi-strategy matching approach:
- **ALL-CAPS words** (e.g., `SEND_SMS`) → check `perm_short` set
- **`intent.action.*`** patterns → check `intents` set (substring match)
- **`/system/bin`, `chmod`, `mount`** → check `shell` set
- **`.permission.`** patterns → split to short name, check `perm_short`
- **Method names** (`TelephonyManager.getDeviceId`) → check `api_strings` with bidirectional substring matching

**Step 5: Output**
A sparse binary array of length 215 (e.g., `[1.0, 0.0, 0.0, 1.0, 0.0, ...]`) fed directly into an XGBoost `DMatrix`.

---

# 13. The Mathematics Behind Every ML Component

### A. XGBoost — Gradient Boosted Decision Trees

**Objective Function:**
```
Obj(θ) = L(θ) + Ω(θ)
```
- `L(θ)` = **Binary Cross-Entropy (Log Loss)**:
  `L = -[y·log(p) + (1-y)·log(1-p)]`
  where y ∈ {0,1} (benign/malicious), p = predicted probability

- `Ω(θ)` = **Regularization**:
  `Ω = γ·T + ½·λ·Σ(w²) + α·Σ|w|`
  where T = number of leaves, w = leaf weights, γ/λ/α are hyperparameters
  (L1 + L2 regularization prevents overfitting)

**Newton Boosting (2nd-Order Taylor Expansion):**
Unlike standard Gradient Boosting that uses only the gradient (1st derivative), XGBoost uses both:
- **Gradient (gi):** `∂L/∂ŷ = p - y`
- **Hessian (hi):** `∂²L/∂ŷ² = p·(1-p)`

This 2nd-order approximation allows XGBoost to find optimal tree splits in fewer iterations.

**Tree Structure Optimization:**
For each potential split, XGBoost computes the gain:
```
Gain = ½ · [GL²/(HL+λ) + GR²/(HR+λ) - (GL+GR)²/(HL+HR+λ)] - γ
```
where GL, GR = sum of gradients in left/right child, HL, HR = sum of hessians.

### B. SHAP — Shapley Additive exPlanations

Rooted in **Cooperative Game Theory**:
- **Game:** The prediction score
- **Players:** The 215 features
- **Shapley Value** for feature i:
  ```
  φᵢ = Σ [|S|!·(|N|-|S|-1)! / |N|!] · [f(S∪{i}) - f(S)]
  ```
  where S = subset of features, N = all features, f = model prediction

For tree-based models, **TreeSHAP** computes this in O(TL·D) time (T = trees, L = leaves, D = depth) instead of the exponential brute-force.

**Guarantee:** The sum of all SHAP values = model prediction - base prediction. This means the explanation is mathematically complete.

### C. Cosine Similarity (RAG Retrieval)

```
Similarity(A, B) = (A · B) / (||A|| × ||B||)
```
- A = query embedding (384-dim vector)
- B = document embedding (384-dim vector)
- Dot product measures alignment; magnitude normalization makes it scale-invariant
- Result ∈ [-1, 1]; closer to 1 = more semantically similar

### D. Sentence Embedding (BAAI/bge-small-en-v1.5)

- **Architecture:** 33M parameter BERT-based encoder
- **Output:** 384-dimensional dense vector per text chunk
- **Training:** Pre-trained on massive text corpora, fine-tuned for semantic similarity tasks
- Text is tokenized → fed through 12 transformer layers → [CLS] token output = embedding vector

---

# 14. Infrastructure & Storage

### Docker Compose Stack
| Container | Image | Purpose |
|-----------|-------|---------|
| `backend` | Custom Python 3.11 | FastAPI orchestrator, PostgreSQL ORM |
| `static-analysis` | Custom Python 3.11 + Java | Androguard + YARA + APKTool + JADX |
| `dynamic-analysis` | Custom Python 3.11 | MobSF client + ADB + Frida |
| `threat-intel` | Custom Python 3.11 | httpx-based IOC lookup |
| `rag-engine` | Custom Python 3.11 | ChromaDB client + sentence-transformers |
| `ai-investigation-engine` | Custom Python 3.11 | Ollama client (multi-agent) |
| `fraud-intent-engine` | Custom Python 3.11 | Ollama client + journey builder |
| `risk-scoring` | Custom Python 3.11 | XGBoost + SHAP |
| `postgres` | PostgreSQL 15 | Relational database |
| `minio` | MinIO | S3-compatible APK object storage |
| `chromadb` | ChromaDB | Vector database for RAG |
| `ollama` | Ollama | Local LLM hosting (llama3.2:3b) |

### Database Schema (PostgreSQL)
```
apk_uploads:     id (UUID PK), filename, sha256 (unique), file_size, upload_time, status, minio_path
analysis_results: id (UUID PK), apk_id (FK), static_analysis (JSONB), dynamic_analysis (JSONB), 
                  threat_intel (JSONB), ai_summary (TEXT), recommended_actions (JSONB)
risk_reports:    id (UUID PK), apk_id (FK), risk_score (FLOAT), severity, classification, 
                  fraud_intent, fraud_journey (JSONB), executive_summary (TEXT), 
                  recommendations (JSONB), mitre_mappings (JSONB), shap_explanations (JSONB)
threat_indicators: id (UUID PK), apk_id (FK), indicator_type, indicator_value, source, severity, mitre_technique
```

### APK Deduplication
SHA-256 hash is computed on upload. If an APK with the same hash already exists:
- If previous analysis `failed` → re-runs the pipeline
- Otherwise → returns the existing analysis (no re-processing)

### Report Generation
- HTML templates rendered via **Jinja2** (`templates/report.html`, `templates/actions.html`)
- HTML → PDF conversion via **WeasyPrint**
- Downloadable at `GET /api/reports/{id}/pdf` and `GET /api/actions/{id}/pdf`

---

# 15. Potential Judge Questions & Answers (FAQ)

**Q: Why XGBoost over a deep learning model for risk scoring?**
A: Malware features are highly structured, tabular, and sparse (215 binary features). XGBoost consistently outperforms neural networks on structured tabular data. More importantly, XGBoost integrates with TreeSHAP for mathematically complete explainability — critical for banking compliance. Deep learning models are black boxes.

**Q: Why use a 3B parameter model locally instead of GPT-4?**
A: **Data privacy and regulatory compliance.** Banking malware analysis involves highly sensitive data. By running `llama3.2:3b` locally via Ollama, zero data leaves the bank's secure perimeter. This ensures compliance with RBI data localization requirements and CERT-In guidelines.

**Q: What happens if the AI hallucinates?**
A: We mitigate hallucination through three mechanisms:
1. **Grounding via RAG:** The LLM answers based on facts retrieved from ChromaDB.
2. **Deterministic scoring:** The 0-100 risk score is from the XGBoost math model, NOT the LLM.
3. **Signal-based gating:** The Knowledge Agent only queries RAG if actual malicious signals exist. Clean apps get NO malware context injected → LLM can't hallucinate threats.

**Q: How do you handle zero-day malware not in your training data?**
A: This is why we use a hybrid approach. While XGBoost catches variations of known malware signatures, our dynamic sandbox (Frida instrumentation) captures actual runtime behavior. Even if the static signature is entirely new, the malicious runtime behavior (SMS interception, overlay attacks, C2 communication) will trigger high-severity signals that both the heuristic scorer and the confidence-aware safety caps account for.

**Q: How do you prevent false positives? Games and legitimate apps have many permissions too.**
A: Five mechanisms work together:
1. **URL safe-list:** 50+ known safe domains (Google, Unity, ad SDKs) excluded from hardcoded URL counts
2. **Private IP filtering:** 127.x, 192.168.x, 0.0.0.0 automatically excluded
3. **QuarkEngine:** Only scores when malicious API SEQUENCES are found (not just individual permissions)
4. **SYSTEM_ALERT_WINDOW exclusion:** Not counted as dangerous (many legit apps use it)
5. **Confidence-aware score capping:** Without confirmed dynamic signals, scores are capped at 35 or 55 regardless of what the ML model predicts

**Q: What happens when the analysis pipeline crashes mid-way?**
A: Every service returns safe/neutral defaults on failure (stub results with `_stub: true`). The pipeline never fabricates malware signals. If MobSF fails → falls back to ADB+Frida. If ADB fails → returns `source: "unavailable"`. If Ollama fails → agents return template-based summaries. If ChromaDB fails → RAG returns hardcoded MITRE fallback context.

**Q: How does QuarkEngine differ from just checking permissions?**
A: Permissions alone are misleading — a legitimate SMS app has `SEND_SMS` permission. QuarkEngine uses **Order Theory** to trace API call SEQUENCES at the bytecode level. It detects that `getDeviceId()` is called BEFORE `sendTextMessage()` — meaning the app is reading the device ID and then sending it via SMS (data exfiltration). A legitimate app would never have this sequence. This is why QuarkEngine gives near-zero scores to benign apps even if they have dangerous permissions.

**Q: What is the DREBIN-215 feature schema exactly?**
A: The DREBIN dataset defines 215 binary features that are the most discriminative for Android malware classification. They fall into 5 categories:
1. **Permission names** (short): `SEND_SMS`, `READ_SMS`, `CAMERA`, `BIND_ACCESSIBILITY_SERVICE`
2. **API method/class names**: `Runtime.exec`, `DexClassLoader`, `TelephonyManager.getDeviceId`
3. **Intent actions**: `android.intent.action.BOOT_COMPLETED`
4. **Shell paths/commands**: `/system/bin`, `chmod`, `mount`
5. **Full class paths**: `android.telephony.SmsManager`, `Ljavax.crypto.Cipher`

Our `feature_extractor.py` maps the live APK analysis output to these exact 215 features using multi-strategy matching (permission lookup, substring matching, regex).
