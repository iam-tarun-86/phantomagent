# 🛡️ PhantomAgent

> **Autonomous Cyber Security — For Everyone**

[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Overview

**PhantomAgent** is a fully offline, AI-powered Security Operations Center (SOC) dashboard designed for small businesses and startups. Unlike enterprise SIEM tools that cost **₹1.4 Cr/year** (Splunk) or **₹95L/year** (Darktrace), PhantomAgent runs on a **standard gaming laptop** with zero cloud dependency.

> *"Every Fortune 500 company has ₹1.9 Cr security tools. We give that power to everyone — open source, local, and built for trust."*

---

## 🎯 The Problem

| Challenge | Statistic |
|-----------|-----------|
| Enterprise SIEM Cost | ₹1.4 Cr/year (Splunk) |
| SMB Target Rate | **43%** of all cyberattacks |
| Ransomware Hit Rate | **88%** of SMB breaches |
| Cloud Data Leaks | Sending logs to AWS = compliance nightmare |
| Mean Time To Detect | **Days** for most organizations |

**Small businesses are the new primary target** — and they have zero defense.

---

## ✨ Key Features

### 🔴 Human-in-the-Loop (HiTL)
The only autonomous security tool that **asks before acting**. High-impact actions (Severity 9-10) enter a **pending approval** state — enterprise-ready by design.

### 🧠 Local LLM Analysis
- **Gemma 4 E4B** via llama.cpp (GGUF quantized)
- **42 tok/sec** inference speed
- **8GB RAM friendly** — runs on a gaming laptop
- **Zero internet** — complete air-gapped operation

### 📡 Real-Time Threat Detection
- **Network Watcher**: Live packet inspection, port scan detection
- **File Watcher**: Monitor `/tmp`, `/var/log` for anomalies
- **Log Watcher**: Tail `auth.log`, `syslog`, `nginx` in real-time

### ⚡ Autonomous Response
- IP blocking via `iptables`
- Process termination (`kill -9`)
- Service isolation (network namespaces)
- System snapshot + forensic report generation

### 🖥️ Professional SOC Dashboard
- Live threat feed with severity classification
- World attack map with real-time ripples
- Kill chain visualizer (5-layer pipeline)
- Hardware telemetry (CPU/RAM/VRAM monitoring)
- Terminal stream (color-coded system logs)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  [Network Watcher] → [Pre-Filter] → [Qwen 3.5] → [Decision]│
│         ↓                    ↓           ↓          ↓     │
│    Event Stream         Noise Kill    AI Analysis   Action  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Severity 1-3 │  │  Severity 4-6 │  │  Severity 7-10   │  │
│  │     LOG       │  │    ALERT      │  │  AUTO-CONTAIN    │  │
│  │               │  │               │  │  or PENDING      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**5-Layer Pipeline:**
1. **Watcher Layer** — Log + Network + File watchers (parallel, event-triggered)
2. **Pre-Filter** — Rule engine kills 99% noise instantly
3. **Gemma 4 E4B** — Always-warm local LLM classifies threats
4. **Decision Engine** — Severity-based action routing
5. **Responder** — Executes containment + forensic snapshot

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **AI Core** | Gemma 4 E4B (llama.cpp) | Threat classification |
| **Watchers** | Python + Watchdog/Scapy/psutil | Event detection |
| **Pre-Filter** | Python rule engine | Noise reduction |
| **Backend** | FastAPI | REST API + async queue |
| **Frontend** | React 19 + Vite + Tailwind CSS | Dashboard |
| **Animation** | Framer Motion | UI transitions |
| **Icons** | Lucide React | Professional iconography |
| **Response** | Python subprocess + iptables | Auto-containment |

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+ (for backend)
- 8GB+ RAM (for local LLM)

### Frontend Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/phantomagent.git
cd phantomagent/phantomagent-dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```

Open `http://localhost:5173` in your browser.

### Demo Mode

Press **`D`** on your keyboard to instantly trigger a **Severity 10 RED ALERT** — the hero feature of PhantomAgent.

### Backend Setup (For Full Integration)

```bash
cd ../backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start FastAPI server
uvicorn main:app --reload
```

### Local LLM Setup

Configure **llama.cpp** and download the Gemma 4 E4B GGUF model:
```bash
# Start your llama.cpp server with the Gemma 4 E4B model
./llama-server -m gemma-4-e4b-it.Q4_K_M.gguf -c 4096 --port 8085
```

---

## 📊 Dashboard Zones

| Zone | Feature | Update Rate |
|------|---------|-------------|
| **Authority Bar** | Telemetry, Qwen status, Auto/Manual toggle | 2s |
| **Live Threat Feed** | Scrolling threat cards with severity | 4s |
| **Attack Map** | World map with attack ripples + arc lines | 3.5s |
| **Kill Chain** | 5-node pipeline with data packet animation | 8s |
| **Terminal Stream** | Color-coded system logs (6 types) | 600ms |
| **RED ALERT** | Full-screen modal with approval flow | On trigger (`D`) |

---

## 🎮 Demo Flow (For Judges)

```
[0:00]  "Let me show you an attack happening right now."
        → Dashboard is calm, telemetry shows low usage

[0:05]  Press D → RED ALERT modal slams open
        → "SSH brute force from a Tor exit node."

[0:10]  Point to Kill Chain → nodes light up sequentially
        → "Watcher → Pre-filter → Qwen → Decision Engine"

[0:20]  "Severity 9. But PhantomAgent doesn't act alone."
        → Hover over APPROVE CONTAINMENT button

[0:23]  Click APPROVE → containment sequence plays
        → "One click. IP blocked. Process killed."

[0:30]  Point to terminal → logs scrolling in real-time
        → "Mean Time To Detect? 12 seconds. MTTR? One click."

[0:40]  Point to telemetry bar → "5.8GB VRAM. Gaming laptop."
        → "No cloud. No subscription. No data leaks."

[0:50]  "Splunk costs ₹1.4 Cr. We cost ₹0."
        → Click DOWNLOAD FORENSIC REPORT

[1:00]  "Built for the 400 million businesses Splunk will never reach."
        → Stop. Smile.
```

---

## 🎯 Unique Selling Proposition

| Feature | Splunk | Darktrace | Cloud SIEM | **PhantomAgent** |
|---------|--------|-----------|------------|------------------|
| Cost | ₹1.4 Cr/yr | ₹95L/yr | ₹47L+/yr | **₹0 (Open Source)** |
| Offline | ❌ | ❌ | ❌ | **✅ 100%** |
| No Data Leaks | ❌ | ❌ | ❌ | **✅** |
| Autonomous Response | Partial | Partial | ❌ | **✅ (Optional)** |
| Setup Time | Weeks | Weeks | Days | **✅ Minutes** |
| Human-in-the-Loop | ❌ | ❌ | ❌ | **✅** |

---

## 📈 Impact & Market

| Metric | Value |
|--------|-------|
| **TAM** | 400M+ SMBs worldwide |
| **SAM** | 60M+ On-prem/dev infra SMBs |
| **SOM** | 2M+ Tech-forward startups (3 years) |
| **Cybercrime Cost** | ₹99.2T projected (2025) |
| **Target MTTD** | Days → Seconds |

---

## 🔮 Future Scope

- **Multi-Agent Defense**: Specialized agents for network, endpoint, cloud
- **Ransomware Prediction**: Early-stage file activity pattern detection
- **Edge Deployment**: Raspberry Pi / IoT device protection
- **Federated Threat Intel**: Peer-to-peer anonymized signature sharing

---

## 👥 Team

**Logic Horizon** — *Confluence 2.0 · Beyond The Edge of Possibility*

| Name | Role |
|------|------|
| Tarun R | AI/ML & Backend |
| Vishnu Varthan M | System Architecture |
| Vishnuvarthan S | Frontend & UI/UX |
| Sanjay RV | DevOps & Integration |

**Track:** Cyber Security · Open Innovation

**Skillset:** Local LLMs (llama.cpp), Python, FastAPI, React, Tailwind CSS

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Gemma 4 E4B** by Google for the model weights
- **llama.cpp** by Georgi Gerganov for efficient local inference
- **Confluence 2.0** for the platform to showcase this vision

---

> *"We didn't build a security tool that alerts humans. We built an AI agent that investigates, decides, and acts — faster than any human can."*

**⭐ Star this repo if you believe small businesses deserve enterprise-grade security.**
