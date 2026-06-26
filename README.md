# 🛡️ PhantomAgent

> Autonomous AI-Powered Cybersecurity Dashboard with Real-Time Threat Detection, Kill Chain Visualization, and Autonomous Containment.

![PhantomAgent Dashboard](https://img.shields.io/badge/Dashboard-Real--Time-green?style=flat-square)
![React](https://img.shields.io/badge/Frontend-React%2018-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-teal?style=flat-square)
![Tailwind](https://img.shields.io/badge/Styling-Tailwind%20CSS-cyan?style=flat-square)

---

## 📖 Overview

PhantomAgent is an autonomous security operations center (SOC) dashboard. It integrates real-time network and file system monitoring with an AI-driven decision engine to detect, classify, and mitigate threats dynamically. Built with a high-performance FastAPI backend and a responsive, cyber-themed React frontend, it visualizes the entire threat lifecycle from detection to containment.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔴 **Real-Time Threat Feed** | Live WebSocket streaming of detected threats with severity indicators |
| 🗺️ **Attack Map** | Geolocation visualization of threat sources with animated connection lines |
| ⚡ **Kill Chain** | MITRE ATT&CK-style pipeline visualization (Watcher → Pre-Filter → AI → Decision → Response) |
| 🚨 **Red Alert Modal** | Glitch text effects, auto-escalation countdown, particle burst on containment for critical threats |
| 🖥️ **Terminal Stream** | Typewriter-style system logs with color-coded severity levels |
| 🔊 **Audio Alerts** | Critical alert sounds for severity 9+ threats |
| 📄 **Forensic Reports** | Auto-generated downloadable incident reports with IOCs and timeline |
| 🔐 **Terminal Login** | CRT-style authentication with Matrix rain background and boot sequence |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FRONTEND (React 18)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Threat   │  │ Attack   │  │ Kill     │  │ Terminal │    │
│  │ Feed     │  │ Map      │  │ Chain    │  │ Stream   │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Red Alert Modal (Framer Motion)         │   │
│  └─────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │ WebSocket + HTTP
┌──────────────────────────┴──────────────────────────────────┐
│                     BACKEND (FastAPI)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Network  │  │ File     │  │ Qwen 3.5 │  │ Decision │    │
│  │ Watcher  │  │ Watcher  │  │ AI       │  │ Engine   │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Auto-Containment Responder              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn
- Ollama (optional, for local AI classification)

### 1. Clone & Setup

```bash
git clone https://github.com/yourusername/phantomagent-dashboard.git
cd phantomagent-dashboard
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Optional: Install Qwen for AI classification**
```bash
ollama pull qwen3:8b
```

**Start the backend:**
```bash
cd ..
python run.py
```

Backend runs on `http://0.0.0.0:8000`

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:5173`

### 4. Open Dashboard

Navigate to `http://localhost:5173` in your browser.

**Default Login:**
- Username: `admin`
- Password: `phantom`

---

## 🧪 Testing the Pipeline

You can simulate threats to test the dashboard's response capabilities using the built-in injection endpoints.

```bash
# Simulate a critical threat requiring human approval (Severity 9)
curl -X POST http://localhost:8000/api/test/inject

# Simulate a moderate threat that auto-contains (Severity 7)
curl -X POST http://localhost:8000/api/test/inject-auto
```

---

## 🎨 UI Components

### Cyber Effects

| Effect | File | Description |
|--------|------|-------------|
| Glitch Text | `index.css` | RGB-split animation on "THREAT DETECTED" |
| Radar Pulse | `index.css` | Pulsing red dot on LIVE indicator |
| Flicker Text | `index.css` | Random opacity flicker on labels |
| Particle Burst | `ParticleBurst.jsx` | Cyan/green/white particles on containment |
| Typewriter Logs | `TerminalStream.jsx` | Character-by-character log typing |
| Matrix Rain | `LoginPage.jsx` | Falling hex characters background |
| CRT Scanlines | `LoginPage.jsx` | Retro monitor scanline effect |

### Tailwind v4 Theme

```css
@import "tailwindcss";

@theme {
  --color-deep-space: #050508;
  --color-panel-base: #0a0a12;
  --color-panel-border: #1a1a2e;
  --color-neon-cyan: #00f0ff;
  --color-alert-red: #ff2a2a;
  --color-contain-green: #00ff88;
  --color-warning-amber: #ffaa00;
  --color-data-white: #e0e0e0;
  --font-mono: 'JetBrains Mono', monospace;
  --font-sans: 'Inter', sans-serif;
}
```

---

## 📁 Project Structure

```
phantomagent-dashboard/
├── backend/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Configuration (API_HOST, ports, paths)
│   ├── watchers/
│   │   ├── network_watcher.py  # Packet capture & analysis
│   │   ├── file_watcher.py     # File system anomaly detection
│   │   └── log_watcher.py      # System log monitoring
│   ├── ai/
│   │   └── classifier.py       # Qwen 3.5 threat classification
│   ├── responder.py            # Auto-containment engine
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main layout
│   │   ├── index.css           # Tailwind theme + cyber effects
│   │   ├── context/
│   │   │   └── DashboardContext.jsx  # WebSocket + state management
│   │   ├── components/
│   │   │   ├── AuthorityBar.jsx    # Top status bar
│   │   │   ├── ThreatFeed.jsx      # Live threat list
│   │   │   ├── AttackMap.jsx       # Geolocation map
│   │   │   ├── KillChain.jsx       # Pipeline visualization
│   │   │   ├── TerminalStream.jsx  # System logs
│   │   │   ├── RedAlertModal.jsx   # Critical threat modal
│   │   │   ├── ParticleBurst.jsx   # Containment particles
│   │   │   └── LoginPage.jsx       # CRT terminal login
│   │   ├── hooks/
│   │   │   └── useTypewriter.js    # Typing effect hook
│   │   └── services/
│   │       └── geoService.js       # IP geolocation API
│   ├── package.json
│   └── vite.config.js
└── run.py                      # Backend runner script
```

---

## 🔧 Configuration

Edit `backend/config.py` to customize the monitoring scope:

```python
API_HOST = "0.0.0.0"      # Listen on all interfaces
API_PORT = 8000
WATCHED_LOGS = ["/var/log/auth.log", "/var/log/syslog"]
WATCHED_PATHS = ["/tmp", "/var/tmp"]
NETWORK_INTERFACE = "eth0"
```

---

## 🐛 Troubleshooting

| Issue | Fix |
|-------|-----|
| `405 Method Not Allowed` | Ensure you are using `POST`, not `GET` for the `/api/test/inject` endpoints. |
| White autofill on login | Addressed by the `WebkitBoxShadow` styling hack in `LoginPage.jsx`. |
| Focus jumps between fields | Addressed by programmatic focus management in `LoginPage.jsx`. |
| Qwen model not found | Run `ollama pull qwen3:8b` or disable the AI fallback in configuration. |

---

## 📜 License

MIT License — Free to use, modify, and distribute.

---

## 🙏 Acknowledgments

- [Tailwind CSS](https://tailwindcss.com) v4 for styling
- [Framer Motion](https://www.framer.com/motion/) for animations
- [FastAPI](https://fastapi.tiangolo.com) for backend framework
- [Qwen](https://qwenlm.github.io) for AI threat classification

---

> *"In cyberspace, the best defense is an autonomous offense."* — PhantomAgent
