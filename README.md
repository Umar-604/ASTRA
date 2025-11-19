# ASTRA – AI-Driven Cyber Threat Detection & Response System  
### _Next-Generation Intelligent EDR with Blockchain-Based Forensics_

---

## 🚀 Overview

**ASTRA** is an AI-powered cyber-threat detection and automated response system.  
It combines **machine learning**, **behavior monitoring**, **automated mitigation**, and **blockchain-backed audit logging** to deliver a complete Endpoint Detection & Response (EDR) solution.

ASTRA collects endpoint logs (Sysmon, Zeek, Suricata), processes them through AI/ML pipelines, generates alerts, and executes automated response actions — all while storing immutable audit records on a blockchain layer.

---

## 🧩 Key Features

### 🔍 Real-Time Threat Detection
- ML-based anomaly detection  
- Event correlation and behavior analytics  
- MITRE ATT&CK tactic classification  

### 🛡 Automated Response
- Process termination  
- Host isolation  
- Policy-based response automation  
- Alert escalation  

### 📊 Security Analyst Dashboard
- Real-time alert monitoring  
- Agent health visualization  
- ELK-based threat analytics  

### 🔗 Blockchain-Powered Audit Logging
- Immutable storage for:
  - Alerts  
  - True/False Positive decisions  
  - Configuration changes  
  - Response actions  
- Ensures tamper-proof forensics  

### 🗃 Centralized Log Management
- **Logstash** for log ingestion  
- **Elasticsearch** for indexing + fast search  
- **Kibana** for visualization  
- **PostgreSQL** for system metadata  

### 🧠 AI/ML Detection Engine
- Python FastAPI microservice  
- Deep learning + ML classifiers  
- Event enrichment and feature extraction  

---

## 🏗 System Architecture

ASTRA uses a **microservices-based architecture** composed of:

- **Go Log Collector** (receives agent logs)  
- **NATS Message Queue** (asynchronous event streaming)  
- **Python ML Engine** (threat scoring)  
- **Processing Worker** (feature extraction + enrichment)  
- **Elasticsearch + Logstash + Kibana** (centralized monitoring)  
- **PostgreSQL** (system storage)  
- **React Admin Dashboard** (UI)  
- **Blockchain Layer** (tamper-proof audit logs)  

---

## 🖥 Tech Stack

### Frontend
- React.js  
- TailwindCSS  

### Backend
- Go (Collector + Workers)  
- Python (FastAPI ML Service)  
- Node.js/Express (Authentication API)  

### Databases
- PostgreSQL  
- Elasticsearch  

### AI / ML
- Scikit-learn  
- TensorFlow / PyTorch  
- NumPy / Pandas  

### Security & Blockchain
- Solidity  
- Web3 Integration  
- Hash-based verification  

---

## 📁 Project Structure (Suggested)

