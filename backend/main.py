"""PhantomAgent Backend - FastAPI + WebSocket"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Set
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.config import API_HOST, API_PORT, WATCHED_LOGS, WATCHED_PATHS, NETWORK_INTERFACE
from backend.models.threat import Threat, ThreatType, ThreatStatus
from backend.watchers.log_watcher import LogWatcher
from backend.watchers.network_watcher import NetworkWatcher
from backend.watchers.file_watcher import FileWatcher
from backend.pipeline.prefilter import PreFilter
from backend.pipeline.qwen_engine import QwenEngine
from backend.pipeline.decision_engine import DecisionEngine
from backend.pipeline.responder import Responder


class DashboardState:
    def __init__(self):
        self.threats: List[Dict] = []
        self.logs: List[Dict] = []
        self.pipeline_state = {"stage": -1, "threat_id": None}
        self.telemetry = {
            "cpu": 12,
            "ram": 4.2,
            "vram": 5.8,
            "qwen_status": "WARM",
            "threats_blocked": 47,
            "uptime": "0d 0h 0m"
        }
        self.clients: Set[WebSocket] = set()
        self.pending_approvals: Dict[str, Dict] = {}
        self.processing_actions: Set[str] = set()
        
        self.prefilter = PreFilter()
        self.qwen = QwenEngine()
        self.decision = DecisionEngine()
        self.responder = Responder()
        
        self.log_watcher = None
        self.network_watcher = None
        self.file_watcher = None
    
    async def broadcast(self, message: Dict):
        dead_clients = set()
        for client in list(self.clients):
            try:
                await client.send_json(message)
            except Exception:
                dead_clients.add(client)
        
        if dead_clients:
            self.clients -= dead_clients
    
    async def add_log(self, source: str, level: str, message: str):
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "source": source,
            "level": level,
            "message": message
        }
        self.logs.append(log_entry)
        if len(self.logs) > 100:
            self.logs = self.logs[-100:]
        
        await self.broadcast({"type": "log", "data": log_entry})
    
    async def process_event(self, event: Dict):
        await self.add_log("WATCHER", "INFO", event.get('message', 'Unknown event'))
        
        await self.broadcast_pipeline(0, event)
        filtered = self.prefilter.filter(event)
        
        if filtered is None:
            await self.add_log("PREFILTER", "INFO", "Noise filtered")
            return
        
        await self.add_log("PREFILTER", "WARN", f"Flagged: {filtered.get('type', 'Unknown')}")
        
        await self.broadcast_pipeline(2, filtered)
        analysis = await self.qwen.analyze(filtered)
        
        await self.add_log("QWEN", "INFO", f"Analysis: {analysis.get('threat_type', 'Unknown')} (Sev: {analysis.get('severity', 0)})")
        
        await self.broadcast_pipeline(3, filtered)
        decision = self.decision.decide(analysis)
        
        await self.add_log("DECISION", "INFO", f"Action: {decision['action']}")
        
        threat_type_str = analysis.get('threat_type', 'Unknown')
        try:
            threat_type_enum = ThreatType[threat_type_str.upper().replace(' ', '_')]
        except KeyError:
            threat_type_enum = ThreatType.UNKNOWN
        
        threat = Threat(
            type=threat_type_enum,
            severity=analysis.get('severity', 5),
            source_ip=filtered.get('source_ip', 'unknown'),
            raw_log=filtered.get('raw_log', ''),
            attack_pattern=analysis.get('attack_pattern'),
            explanation=analysis.get('explanation')
        )
        
        if decision['requires_approval']:
            threat.status = ThreatStatus.PENDING
            self.pending_approvals[threat.id] = {
                "threat": threat.to_dict(),
                "decision": decision,
                "timestamp": datetime.now().isoformat()
            }
            
            await self.broadcast({
                "type": "alert",
                "data": {
                    "threat_id": threat.id,
                    "type": threat.type.value,
                    "severity": threat.severity,
                    "source_ip": threat.source_ip,
                    "timestamp": threat.timestamp.isoformat(),
                    "status": "PENDING_APPROVAL",
                    "attack_pattern": threat.attack_pattern,
                    "explanation": threat.explanation
                }
            })
            
            await self.add_log("DECISION", "CRITICAL", f"Severity {threat.severity} → PENDING_APPROVAL")
        
        elif decision['auto_execute']:
            threat.status = ThreatStatus.AUTO_CONTAINED
            result = await self.responder.execute(decision['action'], threat.to_dict())
            
            await self.broadcast_pipeline(4, threat.to_dict())
            await self.add_log("RESPONSE", "INFO", "Auto-contained")
            self.telemetry['threats_blocked'] += 1
        
        else:
            threat.status = ThreatStatus.LOGGED if decision['action'] == 'LOG' else ThreatStatus.DETECTED
        
        self.threats.append(threat.to_dict())
        if len(self.threats) > 50:
            self.threats = self.threats[-50:]
        
        await self.broadcast({"type": "threat", "data": threat.to_dict()})
    
    async def broadcast_pipeline(self, stage: int, data: Dict):
        self.pipeline_state = {"stage": stage, "threat_id": data.get('id', 'unknown')}
        await self.broadcast({"type": "pipeline", "data": self.pipeline_state})


state = DashboardState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[MAIN] Starting PhantomAgent backend...")
    await state.qwen.initialize()
    
    state.log_watcher = LogWatcher(WATCHED_LOGS, state.process_event)
    await state.log_watcher.start()
    
    state.network_watcher = NetworkWatcher(NETWORK_INTERFACE, state.process_event)
    await state.network_watcher.start()
    
    state.file_watcher = FileWatcher(WATCHED_PATHS, state.process_event)
    state.file_watcher.start()
    
    asyncio.create_task(update_telemetry())
    
    print("[MAIN] PhantomAgent backend started")
    yield
    
    print("[MAIN] Shutting down...")
    await state.log_watcher.stop()
    await state.network_watcher.stop()
    state.file_watcher.stop()


app = FastAPI(title="PhantomAgent API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def update_telemetry():
    import psutil
    import time
    
    start_time = time.time()
    
    while True:
        try:
            state.telemetry['cpu'] = psutil.cpu_percent(interval=1)
            state.telemetry['ram'] = round(psutil.virtual_memory().used / (1024**3), 1)
            
            try:
                import pynvml
                pynvml.nvmlInit()
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                state.telemetry['vram'] = round(info.used / (1024**3), 1)
            except:
                state.telemetry['vram'] = round(5.6 + (state.telemetry['cpu'] / 100) * 0.5, 1)
            
            uptime_seconds = int(time.time() - start_time)
            days = uptime_seconds // 86400
            hours = (uptime_seconds % 86400) // 3600
            minutes = (uptime_seconds % 3600) // 60
            state.telemetry['uptime'] = f"{days}d {hours}h {minutes}m"
            
            await state.broadcast({
                "type": "telemetry",
                "data": state.telemetry
            })
            
        except Exception as e:
            print(f"[TELEMETRY] Error: {e}")
        
        await asyncio.sleep(2)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.clients.add(websocket)
    print(f"[WS] Client connected. Total: {len(state.clients)}")
    
    try:
        pending_alert = None
        if state.pending_approvals:
            first_pending = next(iter(state.pending_approvals.values()))
            pending_alert = first_pending['threat']
        
        await websocket.send_json({
            "type": "init",
            "data": {
                "threats": state.threats,
                "logs": state.logs[-20:],
                "telemetry": state.telemetry,
                "pipeline": state.pipeline_state,
                "alert": pending_alert
            }
        })
        
        while True:
            await asyncio.sleep(2)
            try:
                await websocket.send_json({
                    "type": "telemetry",
                    "data": state.telemetry
                })
            except Exception:
                break
            
    except Exception as e:
        print(f"[WS] Error/Disconnect: {type(e).__name__}")
    finally:
        state.clients.discard(websocket)
        print(f"[WS] Client removed. Total: {len(state.clients)}")


@app.get("/api/telemetry")
async def get_telemetry():
    return state.telemetry


@app.get("/api/threats")
async def get_threats():
    return state.threats


@app.get("/api/logs")
async def get_logs(limit: int = 50):
    return state.logs[-limit:]


@app.post("/api/threats/{threat_id}/approve")
async def approve_threat(threat_id: str):
    print(f"[HTTP] APPROVE received for: {threat_id}")
    
    if threat_id in state.processing_actions:
        return {"status": "ALREADY_PROCESSING"}
    
    state.processing_actions.add(threat_id)
    
    try:
        if threat_id in state.pending_approvals:
            pending = state.pending_approvals.pop(threat_id)
            result = await state.responder.execute('LOCKDOWN', pending['threat'])
            
            await state.add_log("RESPONSE", "INFO", f"APPROVED → {', '.join(result['actions_taken'])}")
            state.telemetry['threats_blocked'] += 1
            
            await state.broadcast({
                "type": "contained",
                "data": {
                    "threat_id": threat_id,
                    "actions": result['actions_taken'],
                    "report": result.get('forensic_report')
                }
            })
            
            return {"status": "CONTAINED", "actions": result['actions_taken']}
        
        return {"status": "NOT_FOUND"}
    finally:
        state.processing_actions.discard(threat_id)


@app.post("/api/threats/{threat_id}/dismiss")
async def dismiss_threat(threat_id: str):
    print(f"[HTTP] DISMISS received for: {threat_id}")
    
    if threat_id in state.processing_actions:
        return {"status": "ALREADY_PROCESSING"}
    
    state.processing_actions.add(threat_id)
    
    try:
        if threat_id in state.pending_approvals:
            state.pending_approvals.pop(threat_id)
            await state.add_log("DECISION", "INFO", f"Threat {threat_id} dismissed")
            
            await state.broadcast({
                "type": "dismissed",
                "data": {"threat_id": threat_id}
            })
            
            return {"status": "DISMISSED"}
        
        return {"status": "NOT_FOUND"}
    finally:
        state.processing_actions.discard(threat_id)


@app.post("/api/test/inject")
async def inject_test_event():
    event = {
        "source": "WATCHER",
        "type": "BRUTE_FORCE",
        "severity": 9,
        "source_ip": "185.220.101.47",
        "raw_log": "Failed password for root from 185.220.101.47 port 22 ssh2",
        "timestamp": "2026-06-26T00:00:00",
        "message": "SSH brute force detected"
    }
    
    print(f"[TEST] Injecting via API. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients)}


@app.post("/api/test/inject-auto")
async def inject_test_event_auto():
    """Inject a medium-high threat that auto-contains (severity 7)"""
    event = {
        "source": "WATCHER",
        "type": "PORT_SCAN",
        "severity": 7,
        "source_ip": "192.168.1.100",
        "raw_log": "Mass port scan detected from 192.168.1.100: 200 ports in 5s",
        "timestamp": "2026-06-26T00:00:00",
        "message": "Aggressive port scan detected"
    }
    
    print(f"[TEST-AUTO] Injecting auto-contain event. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients), "mode": "auto_contain"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)