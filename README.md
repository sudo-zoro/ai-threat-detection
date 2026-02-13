# AI Threat Detector (ML + Local LLM + RAG)

An end-to-end local AI security project that detects suspicious login behavior using Machine Learning and explains the threat using a local LLM enhanced with RAG (Retrieval Augmented Generation) over OWASP-style security knowledge.

This project demonstrates how modern AI-assisted SOC (Security Operations Center) tooling can be built using:

* Unsupervised anomaly detection
* Vector databases
* Embeddings
* Local LLM reasoning
* Security knowledge grounding

Everything runs locally — no external APIs required.

---

## 📌 Project Overview

This system simulates login activity, detects anomalies using ML, and explains potential attacks using a locally hosted LLM with RAG.

### Pipeline

```
Login Logs (CSV)
      ↓
Feature Engineering
      ↓
Isolation Forest (ML)
      ↓
Anomaly Detection
      ↓
Vector Search (ChromaDB)
      ↓
Retrieve OWASP Knowledge
      ↓
Ollama (Local LLM)
      ↓
Attack Explanation + Severity + Fix
```

---

## 📂 Project Structure

```
ai-threat-detector/
│
├── data/
│   └── login_logs.csv
│
├── ml/
│   └── train_anomaly.py
│
├── models/
│   └── anomaly_model.pkl
│
├── llm/
│   └── explain_anomaly.py
│
├── rag/
│   ├── chroma_db/
│   ├── docs/
│   │   ├── login_rate_limiting.txt
│   │   ├── mfa_security.txt
│   │   ├── owasp_account_takeover.txt
│   │   ├── owasp_bruteforce.txt
│   │   ├── owasp_credential_stuffing.txt
│   │   ├── owasp_password_spraying.txt
│   │   └── suspicious_login_patterns.txt
│   │
│   ├── rag_ingest.py
│   └── rag_explainer.py
```

---

## 🧠 What This Project Demonstrates

* Behavioral anomaly detection using Isolation Forest
* Local AI inference using Ollama (Llama 3)
* RAG pipeline using ChromaDB + Sentence Transformers
* Security knowledge grounding using OWASP-like documents
* End-to-end AI-assisted threat analysis

---

## ⚙️ Installation Guide

### 1️⃣ Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 2️⃣ Install Core Dependencies

Because `/tmp` may be small on some systems, use a custom temp directory:

```bash
mkdir -p /home/zoro/tmp
TMPDIR=/home/zoro/tmp pip install pandas scikit-learn joblib
TMPDIR=/home/zoro/tmp pip install sentence-transformers chromadb
```

---

### 3️⃣ Install Ollama (Local LLM)

Linux / Mac:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Pull a model:

```bash
ollama pull llama3
```

Test:

```bash
ollama run llama3
```

---

## 🧪 Step-by-Step Usage

### Phase 1 — Train ML Anomaly Model

```bash
python ml/train_anomaly.py
```

This will:

* Generate login behavior patterns
* Train Isolation Forest
* Save model to:

```
models/anomaly_model.pkl
```

---

### Phase 2 — Ingest Security Knowledge into Vector DB

```bash
cd rag
python rag_ingest.py
```

This will:

* Read OWASP-style text files
* Convert them into embeddings
* Store them in ChromaDB:

```
rag/chroma_db/
```

---

### Phase 3 — Run RAG + LLM Threat Explainer

```bash
python rag/rag_explainer.py
```

This will:

1. Load trained ML model
2. Detect anomalies from login logs
3. Search vector DB for relevant OWASP content
4. Send context + login event to local LLM
5. Generate explanation

---

## 🧾 Example Output

```
🚨 Suspicious Login
User: bob
Country: Russia
Failed Attempts: 42

🤖 RAG + LLM Analysis:

Attack Type: Brute Force Attack
Severity: High

Reason:
Multiple failed login attempts from a foreign location at unusual hours.

Recommended Fix:
- Enable MFA
- Rate-limit login attempts
- Monitor IP activity
```

---

## 🧩 Technologies Used

* Python
* Pandas
* Scikit-learn
* Isolation Forest
* Sentence Transformers
* ChromaDB (Vector Database)
* Ollama (Local LLM hosting)
* Llama 3

---

## 🧠 Key Concepts Implemented

* Unsupervised anomaly detection
* Feature engineering
* Embeddings & semantic search
* Vector similarity retrieval
* Retrieval Augmented Generation (RAG)
* Local AI inference

---