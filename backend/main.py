"""Labyrinth Forge — FastAPI Backend with WebSocket streaming."""
import asyncio
import json
import random
import time
from typing import List, Dict, Any, Optional
from google import genai
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from honeypot import HoneypotSession, DEMO_COMMANDS, DAVE_MESSAGE, KILL_CHAIN_PHASES
from scanner import scan_code

app = FastAPI(title="Labyrinth Forge API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ─────────────────────────────────────
sessions: dict[str, HoneypotSession] = {}
monitors: List[WebSocket] = []

async def broadcast_to_monitors(message: dict):
    """Send a message to all connected monitor UIs."""
    disconnected = []
    for ws in monitors:
        try:
            await ws.send_json(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in monitors:
            monitors.remove(ws)

# ── REST Endpoints ───────────────────────────────────

class ScanRequest(BaseModel):
    code: str

class CommandRequest(BaseModel):
    session_id: str
    command: str

class ModeRequest(BaseModel):
    session_id: str
    mode: str  # "ubuntu" | "windows" | "iot"

@app.get("/")
def root():
    return {"status": "online", "service": "Labyrinth Forge API"}

@app.post("/api/session")
def create_session():
    sid = f"sess-{random.randint(10000,99999)}"
    sessions[sid] = HoneypotSession()
    ip = f"{random.randint(60,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return {"session_id": sid, "attacker_ip": ip, "prompt": sessions[sid].prompt}

@app.post("/api/command")
def run_command(req: CommandRequest):
    session = sessions.get(req.session_id)
    if not session:
        return {"error": "Session not found"}
    output = session.process_command(req.command)
    return {
        "output": output,
        "prompt": session.prompt,
        "profile": session.get_profile(),
    }

@app.post("/api/hydra")
def switch_mode(req: ModeRequest):
    session = sessions.get(req.session_id)
    if not session:
        return {"error": "Session not found"}
    session.mode = req.mode
    session.cwd = "/" if req.mode != "windows" else "C:\\"
    return {"mode": req.mode, "prompt": session.prompt}

@app.post("/api/scan")
def scan_endpoint(req: ScanRequest):
    return scan_code(req.code)

@app.get("/api/report/{session_id}")
def get_report(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    # Try to find the attacker IP from session metadata
    return session.generate_report()

@app.get("/api/decoys")
def get_decoys():
    return {
        "files": [
            {"name": "Q3_Financials.pdf", "type": "pdf", "size": "2.4 MB", "status": "deployed", "icon": "file-text"},
            {"name": "passwords.xlsx", "type": "excel", "size": "156 KB", "status": "deployed", "icon": "table"},
            {"name": "network_diagram.png", "type": "image", "size": "890 KB", "status": "deployed", "icon": "image"},
            {"name": "aws_credentials.bak", "type": "config", "size": "512 B", "status": "active-lure", "icon": "key"},
            {"name": "prod.env", "type": "config", "size": "1.1 KB", "status": "active-lure", "icon": "shield"},
            {"name": "db_dump_2024.sql.gz", "type": "database", "size": "234 MB", "status": "deployed", "icon": "database"},
        ]
    }

# ── WebSocket — Attacker CLI Bridge ──────────────────
@app.websocket("/ws/attacker")
async def attacker_ws(websocket: WebSocket):
    await websocket.accept()
    sid = f"live-{random.randint(1000,9999)}"
    session = HoneypotSession()
    sessions[sid] = session
    ip = "127.0.0.1" # Local CLI connection

    # Notify monitors of a new connection
    init_payload = {
        "type": "init",
        "session_id": sid,
        "attacker_ip": ip,
        "prompt": session.prompt,
        "message": f"🔥 LIVE INTRUSION — Attacker connected from {ip} (Local CLI)"
    }
    await broadcast_to_monitors(init_payload)
    await websocket.send_json(init_payload)

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "command":
                cmd = msg["command"]
                output = session.process_command(cmd)
                profile = session.get_profile()
                
                # 1. Send response back to Attacker CLI
                await websocket.send_json({
                    "type": "output",
                    "output": output,
                    "prompt": session.prompt
                })

                # 2. Mirror to all Monitor UIs
                await broadcast_to_monitors({
                    "type": "command",
                    "command": cmd,
                    "output": output,
                    "prompt": session.prompt,
                    "profile": profile,
                    "attack_intel": session.get_attack_intel(),
                    "prediction": session.predict_next_move(),
                    "risk_event": session.calculate_command_risk(cmd) > 15
                })
    except WebSocketDisconnect:
        sessions.pop(sid, None)
        await broadcast_to_monitors({
            "type": "isolated",
            "message": "🔌 ATTACKER DISCONNECTED — Session Terminated"
        })

@app.websocket("/ws/monitor")
async def monitor_ws(websocket: WebSocket):
    await websocket.accept()
    monitors.append(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        if websocket in monitors:
            monitors.remove(websocket)

# ── WebSocket — demo mode auto simulation ────────────
@app.websocket("/ws/demo")
async def demo_ws(websocket: WebSocket):
    await websocket.accept()
    session = HoneypotSession()
    sid = f"demo-{random.randint(10000,99999)}"
    sessions[sid] = session
    ip = f"{random.randint(60,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    await websocket.send_json({
        "type": "init",
        "session_id": sid,
        "attacker_ip": ip,
        "prompt": session.prompt,
        "message": "⚠️  INTRUSION DETECTED — Attacker connected from " + ip,
    })
    await asyncio.sleep(1.5)

    deception_phases = [
        "🔍 Analyzing typing speed...",
        "🧪 Fingerprinting attacker tools...",
        "🍯 Deploying honey-token...",
        "📂 Generating decoy files...",
        "🔒 Locking decoys with tripwire...",
        "🧠 Profiling psychological pattern...",
        "🕸️ Expanding deception surface...",
    ]

    try:
        for i, (cmd, delay) in enumerate(DEMO_COMMANDS):
            # Send deception status update
            if i < len(deception_phases):
                await websocket.send_json({
                    "type": "deception",
                    "message": deception_phases[i],
                    "phase": i + 1,
                    "total_phases": len(deception_phases),
                })

            # Simulate typing delay
            await asyncio.sleep(delay)

            output = session.process_command(cmd)
            await websocket.send_json({
                "type": "command",
                "command": cmd,
                "output": output,
                "prompt": session.prompt,
                "profile": session.get_profile(),
                "attack_intel": session.get_attack_intel(),
                "prediction": session.predict_next_move(),
            })

            # Dave from IT appears after 8 commands
            if i == 8 and not session.dave_triggered:
                session.dave_triggered = True
                session.frustration = min(100, session.frustration + 20)
                await asyncio.sleep(1.0)
                await websocket.send_json({
                    "type": "dave",
                    "message": DAVE_MESSAGE,
                    "profile": session.get_profile(),
                })

        # Final isolation
        await asyncio.sleep(2.0)
        session.isolated = True
        await websocket.send_json({
            "type": "isolated",
            "message": "🛑 HACKER ISOLATED — Threat Neutralized",
            "profile": session.get_profile(),
            "attack_intel": session.get_attack_intel(),
            "report": session.generate_report(ip),
            "session_log": {
                "total_commands": session.commands_run,
                "duration": round(time.time() - session.start_time, 1),
                "honey_tokens_accessed": sum(1 for c in session.history if any(k in c["cmd"] for k in ["aws_credentials", "prod.env", "deploy_keys", ".env", "shadow"])),
                "data_exfiltrated": "0 bytes (all decoy)",
            },
        })
    except WebSocketDisconnect:
        pass
    finally:
        sessions.pop(sid, None)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
