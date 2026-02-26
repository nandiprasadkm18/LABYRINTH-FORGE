# 🛡️ LABYRINTH FORGE

**AI-Powered Active Defense & Security Platform**

A hackathon-ready cybersecurity platform featuring generative AI honeypots, real-time attacker profiling, polymorphic deception, and automated vulnerability scanning.

> No paid API keys required — all AI is mocked for demo.

---

## Quick Start

### Prerequisites
- **Node.js** 18+ and npm
- **Python** 3.10+

### 1. Start the Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```

### 3. Open in Browser
Navigate to **http://localhost:5173**

---

## Project Structure

```
Labyrinth/
├── backend/
│   ├── main.py              # FastAPI app + WebSocket endpoints
│   ├── honeypot.py           # Generative honeypot engine (fake filesystems, command processing)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.jsx            # App shell with tab navigation
    │   ├── main.jsx           # Entry point
    │   ├── index.css          # Global cyber theme (grid, glassmorphism, neon, matrix)
    │   ├── pages/
    │   │   ├── LandingPage.jsx   # Hero + features + architecture + pricing
    │   │   └── WarRoom.jsx       # Blue team dashboard (orchestrator)
    │   └── components/
    │       ├── CyberGrid.jsx         # Animated background grid
    │       ├── AttackerTerminal.jsx   # Xterm.js live terminal
    │       ├── NetworkTopology.jsx    # React Flow network graph
    │       ├── HackerProfile.jsx      # Recharts threat gauges
    │       ├── DeceptionStatus.jsx    # AI engine status log
    │       ├── SystemCapture.jsx      # Isolation/capture panel
    │       ├── DecoyFiles.jsx         # Multi-modal decoy display
    │       └── HydraMode.jsx          # Ubuntu/Windows/IoT toggle
    └── vite.config.js
```

---

## Features

| Module | Description |
|---|---|
| **Landing Page** | Hero with matrix rain, problem stats, solution features, architecture diagram, pricing |
| **War Room Dashboard** | Live attacker terminal, network topology, hacker profiling, AI deception status, capture panel |
| **Honeypot Engine** | Mock AI generates realistic Ubuntu/Windows/IoT terminal responses with fake filesystems |
| **Reverse Turing Agent** | "Dave from IT" sends messages to psychologically profile the attacker |
| **Multi-Modal Decoys** | Fake PDFs, spreadsheets, AWS keys, config files displayed in UI |
| **Hydra Mode** | Toggle between Ubuntu, Windows Server, and IoT device simulations |
| **Demo Mode** | One-click full attack simulation from intrusion to isolation |

---

## Tech Stack

- **Frontend:** React + Vite, Tailwind CSS, Xterm.js, React Flow, Recharts, Lucide Icons
- **Backend:** Python FastAPI, WebSocket
- **AI:** Mocked Gemini responses (no API key needed)
- **Theme:** Dark mode, neon cyber aesthetics, glassmorphism, matrix effects
