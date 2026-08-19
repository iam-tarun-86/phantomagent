"""PhantomAgent Backend - FastAPI + WebSocket"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Set
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.database import db
from backend.auth import authenticate_operator, require_token, token_is_valid
from backend.config import (
    API_HOST,
    API_PORT,
    API_TOKEN,
    APPROVAL_TIMEOUT_SECONDS,
    AUTH_PASSWORD_HASH,
    CORS_ORIGINS,
    DEMO_MODE,
    NETWORK_INTERFACE,
    TOKEN_IS_EPHEMERAL,
    WATCHED_LOGS,
    WATCHED_PATHS,
)
from backend.models.threat import Threat, ThreatType, ThreatStatus
from backend.watchers.log_watcher import LogWatcher
from backend.watchers.network_watcher import NetworkWatcher
from backend.watchers.file_watcher import FileWatcher
from backend.pipeline.prefilter import PreFilter
from backend.pipeline.gemma_engine import GemmaEngine
from backend.pipeline.decision_engine import DecisionEngine
from backend.pipeline.responder import Responder


class DashboardState:
    def __init__(self):
        # DASHBOARD STARTS FRESH — no old threats/logs on startup
        self.threats: List[Dict] = []
        self.logs: List[Dict] = []
        self.pipeline_state = {"stage": -1, "threat_id": None}
        self.telemetry = {
            "cpu": 12,
            "ram": 4.2,
            "vram": 5.8,
            "gemma_status": "WARM",
            "threats_blocked": 0,
            "uptime": "0d 0h 0m"
        }
        self.clients: Set[WebSocket] = set()
        self.pending_approvals: Dict[str, Dict] = {}
        self.processing_actions: Set[str] = set()
        
        self.prefilter = PreFilter()
        self.gemma = GemmaEngine()
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
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source,
            "level": level,
            "message": message
        }
        self.logs.append(log_entry)
        if len(self.logs) > 100:
            self.logs = self.logs[-100:]
        
        # SAVE TO DATABASE
        db.save_log(log_entry)
        
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
        
        # PHASE 5 PIPELINE WIRING: GNN 'Eyes' + Gemma 'Brain'
        pipeline_res = await self.decision.analyze_and_route(filtered)
        analysis = pipeline_res['analysis']
        decision = pipeline_res['decision']
        gnn_score = pipeline_res['gnn_score']
        
        await self.broadcast_pipeline(3, filtered)
        
        # Preserve test event severity ONLY for explicit API test injections or high-consensus events.
        # If Consensus Gate suppressed a false positive, do NOT allow watcher default severity to override it.
        is_test_injection = event.get('source') in ('TEST_API', 'API', 'SIMULATION') or 'inject' in event.get('message', '').lower()
        if (is_test_injection or analysis.get('has_consensus', False)) and event.get('severity', 0) > analysis.get('severity', 0):
            analysis['severity'] = event['severity']
            if event.get('reason'):
                analysis['reason'] = event['reason']
            if event.get('confidence'):
                analysis['confidence'] = event['confidence']
            if event.get('indicators'):
                analysis['indicators'] = event['indicators']
            decision = self.decision.decide(analysis)
            
        await self.add_log("GNN+GEMMA", "INFO", f"Analysis: {analysis.get('threat_type', 'Unknown')} (GNN: {gnn_score:.4f}, Sev: {analysis.get('severity', 0)}) - {analysis.get('reason', '')}")
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
            explanation=analysis.get('explanation'),
            reason=analysis.get('reason'),
            confidence=analysis.get('confidence')
        )
        
        threat_reason = analysis.get('reason', 'AI analysis in progress...')
        threat_confidence = analysis.get('confidence', 0)
        threat_indicators = analysis.get('indicators', [])
        
        # The responder consumes this structured intent; it is never a shell string.
        defense_action = analysis.get('defense_action') or {"action": "NONE", "target_ip": ""}

        if decision['requires_approval']:
            threat.status = ThreatStatus.PENDING
            pending_threat = threat.to_dict()
            pending_threat['defense_action'] = defense_action
            self.pending_approvals[threat.id] = {
                "threat": pending_threat,
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
                    "explanation": threat.explanation,
                    "reason": threat_reason,
                    "confidence": threat_confidence,
                    "indicators": threat_indicators
                }
            })
            
            await self.add_log("DECISION", "CRITICAL", f"Severity {threat.severity} → PENDING_APPROVAL")
            
            # Start the operator-approval countdown
            asyncio.create_task(self.handle_approval_timeout(threat.id))
        
        elif decision['auto_execute']:
            threat.status = ThreatStatus.AUTO_CONTAINED
            auto_threat = threat.to_dict()
            auto_threat['defense_action'] = defense_action
            result = await self.responder.execute(decision['action'], auto_threat)
            
            await self.broadcast_pipeline(4, threat.to_dict())
            await self.add_log("RESPONSE", "INFO", "Auto-contained")
            self.telemetry['threats_blocked'] += 1
        
        else:
            threat.status = ThreatStatus.LOGGED if decision['action'] == 'LOG' else ThreatStatus.DETECTED
        
        self.threats.append(threat.to_dict())
        if len(self.threats) > 50:
            self.threats = self.threats[-50:]
        
        threat_dict = threat.to_dict()
        threat_dict['reason'] = threat_reason
        threat_dict['confidence'] = threat_confidence
        threat_dict['indicators'] = threat_indicators
        threat_dict['gnn_score'] = round(gnn_score, 4)          # GNN anomaly score for frontend
        threat_dict['attack_pattern'] = analysis.get('attack_pattern', '')  # MITRE pattern label
        threat_dict['consensus_votes'] = analysis.get('consensus_votes', 0)
        threat_dict['has_consensus'] = analysis.get('has_consensus', False)
        threat_dict['severity_breakdown'] = analysis.get('severity_breakdown', {})

        # SAVE TO DATABASE
        db.save_threat(threat_dict)

        await self.broadcast({"type": "threat", "data": threat_dict})
    
    async def broadcast_pipeline(self, stage: int, data: Dict):
        self.pipeline_state = {"stage": stage, "threat_id": data.get('id', 'unknown')}
        await self.broadcast({"type": "pipeline", "data": self.pipeline_state})

    async def handle_approval_timeout(self, threat_id: str):
        """Wait for the operator window to lapse, then auto-contain."""
        await asyncio.sleep(APPROVAL_TIMEOUT_SECONDS)
        
        if threat_id in self.pending_approvals:
            print(f"[TIMEOUT] Threat {threat_id} auto-approved after {APPROVAL_TIMEOUT_SECONDS}s timeout")
            
            # Prevent double-processing
            if threat_id in self.processing_actions:
                return
            self.processing_actions.add(threat_id)
            
            try:
                pending = self.pending_approvals.pop(threat_id)
                result = await self.responder.execute('LOCKDOWN', pending['threat'])
                
                await self.add_log("RESPONSE", "INFO", f"AUTO-TIMEOUT → {', '.join(result['actions_taken'])}")
                self.telemetry['threats_blocked'] += 1
                
                await self.broadcast({
                    "type": "contained",
                    "data": {
                        "threat_id": threat_id,
                        "actions": result['actions_taken'],
                        "report": result.get('forensic_report')
                    }
                })
            finally:
                self.processing_actions.discard(threat_id)


state = DashboardState()


def _print_auth_banner():
    """Surface the credentials needed to reach a now-authenticated API."""
    print("=" * 72)
    if TOKEN_IS_EPHEMERAL:
        print("[AUTH] No PHANTOM_API_TOKEN set — generated an ephemeral token for this run:")
        print(f"[AUTH]   {API_TOKEN}")
        print("[AUTH] It changes on every restart. Set PHANTOM_API_TOKEN to pin it.")
    else:
        print("[AUTH] Using PHANTOM_API_TOKEN from the environment.")
    if not AUTH_PASSWORD_HASH:
        print("[AUTH] WARNING: PHANTOM_PASSWORD_HASH is unset — falling back to the dev")
        print("[AUTH]          password. Set a hash before exposing this beyond loopback.")
    print("=" * 72)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[MAIN] Starting PhantomAgent backend...")

    _print_auth_banner()

    # Install the PHANTOM chain up front so the first containment does not pay for it.
    await state.responder.ensure_chain()

    await state.gemma.initialize()
    
    state.log_watcher = LogWatcher(WATCHED_LOGS, state.process_event)
    await state.log_watcher.start()
    
    loop = asyncio.get_running_loop()
    state.network_watcher = NetworkWatcher(NETWORK_INTERFACE, state.process_event, loop=loop)
    await state.network_watcher.start()
    
    state.file_watcher = FileWatcher(WATCHED_PATHS, state.process_event)
    state.file_watcher.start()
    
    asyncio.create_task(update_telemetry())
    
    print("[MAIN] PhantomAgent backend started")
    yield
    
    print("[MAIN] Shutting down...")

    # Each step is isolated: a watcher that fails to stop (e.g. Scapy raising
    # PermissionError when not running as root) must not prevent the firewall chain from
    # being torn down. Skipping that teardown leaves live DROP rules on the host.
    async def _shutdown_step(label, fn):
        try:
            result = fn()
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:
            print(f"[MAIN] Shutdown step '{label}' failed: {type(e).__name__}: {e}")

    await _shutdown_step("log_watcher", state.log_watcher.stop)
    await _shutdown_step("network_watcher", state.network_watcher.stop)
    await _shutdown_step("file_watcher", state.file_watcher.stop)
    # Leave no live DROP rules behind after Ctrl+C.
    await _shutdown_step("iptables_cleanup", state.responder.cleanup_chain)


app = FastAPI(title="PhantomAgent API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
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
    # Validate before accepting: an unauthenticated socket never joins the broadcast set.
    if not token_is_valid(websocket.query_params.get("token")):
        await websocket.close(code=1008, reason="Invalid or missing API token")
        print("[WS] Rejected unauthenticated connection")
        return

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


class LoginRequest(BaseModel):
    username: str
    password: str


def require_demo_mode():
    """Gate the fabricated-threat injection endpoints behind DEMO_MODE."""
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail="Not found")


@app.post("/api/auth/login")
async def login(payload: LoginRequest):
    """Exchange operator credentials for the API token."""
    if not authenticate_operator(payload.username, payload.password):
        # Deliberately vague: do not reveal which half was wrong.
        raise HTTPException(status_code=401, detail="Access denied")

    print(f"[AUTH] Operator '{payload.username}' authenticated")
    return {"token": API_TOKEN, "user": payload.username}


@app.get("/api/blocks", dependencies=[Depends(require_token)])
async def list_blocks():
    """Currently installed firewall blocks."""
    return {"blocked_ips": state.responder.get_blocked_ips()}


@app.post("/api/blocks/{ip}/release", dependencies=[Depends(require_token)])
async def release_block(ip: str):
    """Remove a block. Containment was previously irreversible without shell access."""
    if not state.responder.is_blockable_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    released = await state.responder.unblock_ip(ip)
    await state.add_log("RESPONSE", "INFO", f"Block released for {ip}")
    return {"status": "RELEASED" if released else "NOT_BLOCKED", "ip": ip}


@app.get("/api/telemetry", dependencies=[Depends(require_token)])
async def get_telemetry():
    return state.telemetry


@app.get("/api/threats", dependencies=[Depends(require_token)])
async def get_threats():
    return state.threats


@app.get("/api/logs", dependencies=[Depends(require_token)])
async def get_logs(limit: int = 50):
    return state.logs[-limit:]


# NEW: Fetch ALL historical logs from database for fullscreen viewer
@app.get("/api/logs/all", dependencies=[Depends(require_token)])
async def get_all_logs():
    return db.load_logs(limit=1000)

@app.delete("/api/logs/all", dependencies=[Depends(require_token)])
async def delete_all_logs():
    db.clear_all_logs()
    state.logs = []
    state.threats = []
    await state.broadcast({"type": "clear_logs"})
    return {"status": "cleared"}


@app.post("/api/threats/approve-all", dependencies=[Depends(require_token)])
async def approve_all_threats():
    print(f"[HTTP] APPROVE ALL received. Pending count: {len(state.pending_approvals)}")
    pending_ids = list(state.pending_approvals.keys())
    results = []
    
    for threat_id in pending_ids:
        if threat_id in state.processing_actions:
            continue
        state.processing_actions.add(threat_id)
        try:
            if threat_id in state.pending_approvals:
                pending = state.pending_approvals.pop(threat_id)
                result = await state.responder.execute('LOCKDOWN', pending['threat'])
                await state.add_log("RESPONSE", "INFO", f"APPROVED ALL → {threat_id} ({', '.join(result['actions_taken'])})")
                state.telemetry['threats_blocked'] += 1
                
                await state.broadcast({
                    "type": "contained",
                    "data": {
                        "threat_id": threat_id,
                        "actions": result['actions_taken'],
                        "report": result.get('forensic_report')
                    }
                })
                results.append({"threat_id": threat_id, "status": "CONTAINED"})
        finally:
            state.processing_actions.discard(threat_id)
            
    return {"status": "ALL_CONTAINED", "count": len(results)}


@app.post("/api/threats/{threat_id}/approve", dependencies=[Depends(require_token)])
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


@app.post("/api/threats/{threat_id}/dismiss", dependencies=[Depends(require_token)])
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


@app.post("/api/test/inject", dependencies=[Depends(require_token), Depends(require_demo_mode)])
async def inject_test_event():
    event = {
        "source": "WATCHER",
        "type": "DNS_TUNNELING",
        "severity": 9,
        "source_ip": "185.220.101.47",
        "raw_log": "DNS query: aHR0cHM6Ly9tYWx3YXJlLmNvbQ==.bad-domain.biz from 185.220.101.47",
        "timestamp": "2026-06-27T00:00:00",
        "message": "Suspicious DNS tunneling detected",
        "reason": "High-volume DNS queries to newly registered domain 'bad-domain.biz' with base64-encoded subdomains. 4,847 queries in 12 minutes averaging 3.2KB per query — consistent with data exfiltration. Domain registered 3 days ago via anonymous registrar. No legitimate business relationship.",
        "confidence": 97.4,
        "indicators": [
            "4,847 DNS queries in 12 minutes",
            "Base64-encoded subdomains (3.2KB payload avg)",
            "Domain age: 3 days (suspiciously new)",
            "Anonymous registrar (privacy-protected)",
            "Off-hours activity (02:00-03:00 local time)",
            "No MX/SPF records — not a mail server",
            "Query pattern: beacon-like intervals"
        ]
    }
    
    print(f"[TEST] Injecting via API. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients)}


@app.post("/api/test/inject-auto", dependencies=[Depends(require_token), Depends(require_demo_mode)])
async def inject_test_event_auto():
    event = {
        "source": "WATCHER",
        "type": "FILE_ANOMALY",
        "severity": 7,
        "source_ip": "192.168.1.105",
        "raw_log": "File created: /tmp/.update.sh (SHA256: 8f3b2c...) by user www-data",
        "timestamp": "2026-06-27T00:00:00",
        "message": "Malicious payload dropped in temp directory",
        "reason": "Executable shell script dropped in /tmp by web server process (www-data). File masquerades as system update but contains obfuscated curl commands to C2 server. SHA256 matches known Cobalt Strike beacon (confidence: 97.4%). File permissions: 777 (world-executable). Parent process: apache2 worker.",
        "confidence": 97.4,
        "indicators": [
            "Executable in /tmp by www-data (unusual)",
            "Masquerades as '.update.sh' (hidden file)",
            "SHA256 matches Cobalt Strike beacon",
            "Contains obfuscated curl to external IP",
            "Permissions: 777 (world-executable)",
            "Parent process: apache2 (web server)",
            "No corresponding package manager activity"
        ]
    }
    
    print(f"[TEST-AUTO] Injecting auto-contain event. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients), "mode": "auto_contain"}


@app.post("/api/test/inject-lateral", dependencies=[Depends(require_token), Depends(require_demo_mode)])
async def inject_lateral_movement():
    """Simulate advanced persistent threat — lateral movement"""
    event = {
        "source": "WATCHER",
        "type": "SUSPICIOUS_LOGIN",
        "severity": 8,
        "source_ip": "10.0.0.45",
        "raw_log": "Successful RDP login from 10.0.0.45 to DC-01 at 03:17 AM using svc_backup account",
        "timestamp": "2026-06-27T00:00:00",
        "message": "Lateral movement detected — privileged account misuse",
        "reason": "Service account 'svc_backup' used for interactive RDP session at 03:17 AM — violates least-privilege policy. Account should only run automated backups. Source IP (10.0.0.45) is workstation WS-12, not backup server. Login followed by PSExec execution on 3 domain controllers within 4 minutes. Pattern matches APT29 (Cozy Bear) lateral movement technique.",
        "confidence": 94.2,
        "indicators": [
            "Service account used interactively (03:17 AM)",
            "RDP from workstation (not backup server)",
            "PSExec executed on 3 DCs post-login",
            "Mimikatz artifacts in memory",
            "Kerberoasting detected 12 minutes later",
            "No change ticket for this activity",
            "Matches APT29 TTP (MITRE ATT&CK T1021.002)"
        ]
    }
    
    print(f"[TEST-LATERAL] Injecting lateral movement. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients), "mode": "lateral"}


@app.post("/api/test/inject-ransomware", dependencies=[Depends(require_token), Depends(require_demo_mode)])
async def inject_ransomware():
    """Simulate ransomware behavior"""
    event = {
        "source": "WATCHER",
        "type": "FILE_ANOMALY",
        "severity": 10,
        "source_ip": "192.168.1.50",
        "raw_log": "Mass file modification: 14,203 files renamed to .locked extension in /srv/shares",
        "timestamp": "2026-06-27T00:00:00",
        "message": "RANSOMWARE DETECTED — Mass encryption in progress",
        "reason": "Rapid mass file encryption detected on network shares. 14,203 files renamed to .locked extension in 47 seconds. Read/write ratio: 1:847 (abnormal). Shadow copies deleted via vssadmin. Ransom note 'RECOVER_INSTRUCTIONS.html' dropped in 23 directories. File entropy analysis: 7.98/8.0 (strongly encrypted). Bitcoin wallet in note: bc1q...xyz.",
        "confidence": 99.1,
        "indicators": [
            "14,203 files encrypted in 47 seconds",
            ".locked extension (LockBit 3.0 signature)",
            "Shadow copies deleted (vssadmin)",
            "Ransom note dropped in 23 directories",
            "File entropy: 7.98/8.0 (encrypted)",
            "Bitcoin wallet in ransom note",
            "SMBv1 exploited (EternalBlue vector)",
            "No backup verification in 72 hours"
        ]
    }
    
    print(f"[TEST-RANSOMWARE] Injecting ransomware event. Clients: {len(state.clients)}")
    await state.process_event(event)
    return {"status": "injected", "clients": len(state.clients), "mode": "ransomware"}
@app.get("/api/connections", dependencies=[Depends(require_token)])
async def get_connections():
    """Get real-time network connections from the system"""
    import psutil
    connections = []
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections.append({
                    "ip": conn.raddr.ip,
                    "port": conn.raddr.port,
                    "status": conn.status,
                    "direction": "outbound" if conn.laddr and conn.laddr.port > 1024 else "inbound"
                })
    except Exception as e:
        print(f"[CONNECTIONS] Error: {e}")
    
    return connections[:20]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)