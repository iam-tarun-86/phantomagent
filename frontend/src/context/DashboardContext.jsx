import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import wsService from '../services/websocket';

const DashboardContext = createContext(null);

// Audio state (module-level for persistence)
let currentAudio = null;

const stopCriticalSound = () => {
    if (currentAudio) {
        currentAudio.pause();
        currentAudio.currentTime = 0;
        currentAudio = null;
    }
};

const playCriticalSound = () => {
    stopCriticalSound();
    try {
        const audio = new Audio('/critical-alarm.mp3');
        audio.volume = 0.6;
        audio.loop = true;
        const playPromise = audio.play();
        if (playPromise !== undefined) {
            playPromise.then(() => {
                currentAudio = audio;
            }).catch(err => {
                console.log('[AUDIO] Play blocked:', err.message);
            });
        }
    } catch (e) {
        console.log('[AUDIO] Error:', e);
    }
};

export const DashboardProvider = ({ children }) => {
    const [threats, setThreats] = useState([]);
    const [logs, setLogs] = useState([]);
    const [telemetry, setTelemetry] = useState({
        cpu: 12,
        ram: 4.2,
        vram: 5.8,
        gemma_status: 'WARM',
        threats_blocked: 47,
        uptime: '0d 0h 0m'
    });
    const [pipeline, setPipeline] = useState({ stage: -1, threat_id: null });
    const [alert, setAlert] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [audioReady, setAudioReady] = useState(false);

    const actionLock = useRef(false);
    const processedThreats = useRef(new Set());
    const pendingAlertRef = useRef(null);

    // Unlock audio on ANY user interaction
    useEffect(() => {
        const unlock = () => {
            if (audioReady) return;
            const silent = new Audio("data:audio/wav;base64,UklGRigAAABXQVZFZm10IBIAAAABAAEARKwAAIhYAQACABAAAABkYXRhAgAAAAEA");
            silent.play().then(() => {
                setAudioReady(true);
                console.log('[AUDIO] Unlocked by user interaction');
            }).catch(() => { });
        };

        document.addEventListener('click', unlock, { once: true });
        document.addEventListener('keydown', unlock, { once: true });
        document.addEventListener('touchstart', unlock, { once: true });

        return () => {
            document.removeEventListener('click', unlock);
            document.removeEventListener('keydown', unlock);
            document.removeEventListener('touchstart', unlock);
        };
    }, [audioReady]);

    // Play pending sound when audio becomes ready
    useEffect(() => {
        if (audioReady && pendingAlertRef.current) {
            console.log('[AUDIO] Playing pending sound');
            playCriticalSound();
            pendingAlertRef.current = null;
        }
    }, [audioReady]);

    useEffect(() => {
        wsService.connect();

        const unsubs = [
            wsService.on('connection', (d) => setIsConnected(d.status === 'connected')),

            wsService.on('init', (d) => {
                setThreats(d.threats || []);
                setLogs(d.logs || []);
                setTelemetry(d.telemetry || telemetry);
                setPipeline(d.pipeline || { stage: -1, threat_id: null });
                setAlert(d.alert || null);
                actionLock.current = false;
                processedThreats.current.clear();
                stopCriticalSound();
            }),

            wsService.on('threat', (d) => setThreats(prev => [{
                id: d.id,
                type: d.type,
                source_ip: d.source_ip,
                severity: d.severity,
                timestamp: d.timestamp,
                status: d.status,
                reason: d.reason,
                confidence: d.confidence,
                indicators: d.indicators,
                gnn_score: d.gnn_score ?? null,       // GNN anomaly score [0.0-1.0]
                attack_pattern: d.attack_pattern ?? null,
            }, ...prev].slice(0, 20))),
            wsService.on('log', (d) => setLogs(prev => [...prev, d].slice(-50))),
            wsService.on('telemetry', (d) => setTelemetry(d)),
            wsService.on('pipeline', (d) => setPipeline(d)),

            wsService.on('clear_logs', () => {
                setLogs([]);
                setThreats([]);
            }),

            wsService.on('alert', (d) => {
                setAlert(null);
                setTimeout(() => {
                    setAlert(d);
                    actionLock.current = false;
                    processedThreats.current.delete(d.threat_id);
                    if (d.severity >= 9) {
                        if (audioReady) {
                            playCriticalSound();
                        } else {
                            console.log('[AUDIO] Queued for unlock');
                            pendingAlertRef.current = d;
                        }
                    }
                }, 50);
            }),

            wsService.on('contained', (d) => {
                console.log('[DASHBOARD] Contained:', d);
                actionLock.current = false;
                stopCriticalSound();
                setPipeline({ stage: 4, threat_id: d.threat_id });
                processedThreats.current.add(d.threat_id);
                setThreats(prev => prev.map(t =>
                    t.id === d.threat_id ? { ...t, status: 'CONTAINED' } : t
                ));
            }),

            wsService.on('dismissed', (d) => {
                console.log('[DASHBOARD] Dismissed:', d);
                setAlert(null);
                actionLock.current = false;
                stopCriticalSound();
                setPipeline({ stage: -1, threat_id: null });
                processedThreats.current.add(d.threat_id);
                setThreats(prev => prev.filter(t => t.id !== d.threat_id));
            }),
        ];

        return () => {
            unsubs.forEach(u => u());
        };
    }, [audioReady]);

    const approveThreat = useCallback(async (id) => {
        if (actionLock.current) {
            console.log('[DASHBOARD] Action locked, ignoring approve')
            return
        }
        if (processedThreats.current.has(id)) {
            console.log('[DASHBOARD] Already processed:', id)
            return
        }
        console.log('[DASHBOARD] Approving:', id)
        actionLock.current = true
        try {
            const result = await wsService.approveThreat(id)
            console.log('[DASHBOARD] Approve result:', result)
        } catch (err) {
            console.error('[DASHBOARD] Approve failed:', err)
        } finally {
            actionLock.current = false
        }
    }, [])

    const dismissThreat = useCallback(async (id) => {
        // ALWAYS clear alert immediately — don't wait for backend
        setAlert(null);
        stopCriticalSound();
        setPipeline({ stage: -1, threat_id: null });

        if (actionLock.current) {
            console.log('[DASHBOARD] Action locked, ignoring dismiss backend call');
            return;
        }
        if (processedThreats.current.has(id)) {
            console.log('[DASHBOARD] Already processed:', id);
            return;
        }
        console.log('[DASHBOARD] Dismissing:', id);
        actionLock.current = true;
        try {
            const result = await wsService.dismissThreat(id);
            console.log('[DASHBOARD] Dismiss result:', result);
        } catch (err) {
            console.error('[DASHBOARD] Dismiss failed:', err);
        } finally {
            actionLock.current = false;
        }
    }, []);

    const clearLogs = useCallback(() => {
        setLogs([]);
    }, []);

    return (
        <DashboardContext.Provider value={{
            threats, logs, telemetry, pipeline, alert, isConnected,
            approveThreat, dismissThreat, clearLogs
        }}>
            {children}
        </DashboardContext.Provider>
    );
};

export const useDashboard = () => {
    const ctx = useContext(DashboardContext);
    if (!ctx) throw new Error('useDashboard must be used within DashboardProvider');
    return ctx;
};