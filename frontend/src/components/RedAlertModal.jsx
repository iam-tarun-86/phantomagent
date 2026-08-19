import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldAlert, ShieldCheck, X, Clock, Globe, AlertTriangle, FileText, Layers, CheckCircle } from 'lucide-react'
import ParticleBurst from './ParticleBurst'
import { useDashboard } from '../context/DashboardContext.jsx'
import { authFetch } from '../services/auth'

const RedAlertModal = ({ isOpen, threat, onApprove, onDismiss }) => {
    const { threats, approveThreat } = useDashboard()
    const [countdown, setCountdown] = useState(15)
    const [phase, setPhase] = useState('alert') // 'alert' | 'containing' | 'contained'
    const [particleTrigger, setParticleTrigger] = useState(false)
    const [particleOrigin, setParticleOrigin] = useState({ x: 0, y: 0 })
    const [activeQueueIndex, setActiveQueueIndex] = useState(0)
    const autoEscalated = useRef(false)
    const timerRef = useRef(null)
    const audioCtxRef = useRef(null)
    const oscillatorRef = useRef(null)

    // Build multi-threat queue by combining props and any uncontained critical threats
    const pendingList = React.useMemo(() => {
        const list = []
        if (threat) {
            list.push(threat)
        }
        const activeCritical = threats.filter(t => 
            (t.status === 'PENDING' || t.severity >= 9) && 
            t.status !== 'CONTAINED' && 
            t.status !== 'AUTO_CONTAINED' &&
            t.id !== threat?.threat_id &&
            t.id !== threat?.id
        )
        return [...list, ...activeCritical]
    }, [threat, threats])

    const activeThreat = pendingList[activeQueueIndex] || pendingList[0] || threat || {}
    const threatId = activeThreat.threat_id || activeThreat.id

    // Siren Audio Logic
    useEffect(() => {
        if (isOpen && phase === 'alert') {
            try {
                if (!audioCtxRef.current) {
                    audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)()
                }
                const ctx = audioCtxRef.current
                
                const osc = ctx.createOscillator()
                const gain = ctx.createGain()
                
                osc.type = 'square'
                osc.connect(gain)
                gain.connect(ctx.destination)
                
                let frequency = 400
                let goingUp = true
                
                const modInterval = setInterval(() => {
                    if (goingUp) {
                        frequency += 50
                        if (frequency >= 800) goingUp = false
                    } else {
                        frequency -= 50
                        if (frequency <= 400) goingUp = true
                    }
                    if (oscillatorRef.current) {
                        osc.frequency.setValueAtTime(frequency, ctx.currentTime)
                    }
                }, 50)
                
                gain.gain.setValueAtTime(0.08, ctx.currentTime)
                osc.start()
                oscillatorRef.current = { osc, modInterval }
                
            } catch (e) {
                console.error("Audio API not supported or blocked", e)
            }
        } else {
            if (oscillatorRef.current) {
                clearInterval(oscillatorRef.current.modInterval)
                try { oscillatorRef.current.osc.stop() } catch(e){}
                oscillatorRef.current = null
            }
        }
        
        return () => {
            if (oscillatorRef.current) {
                clearInterval(oscillatorRef.current.modInterval)
                try { oscillatorRef.current.osc.stop() } catch(e){}
                oscillatorRef.current = null
            }
        }
    }, [isOpen, phase])

    // Reset countdown when modal opens or active threat changes
    useEffect(() => {
        if (!isOpen) {
            if (timerRef.current) clearInterval(timerRef.current)
            autoEscalated.current = false
            return
        }

        setCountdown(15)
        setPhase('alert')
        setParticleTrigger(false)
        autoEscalated.current = false

        timerRef.current = setInterval(() => {
            setCountdown(prev => {
                if (prev <= 1) {
                    clearInterval(timerRef.current)
                    return 0
                }
                return prev - 1
            })
        }, 1000)

        return () => {
            if (timerRef.current) clearInterval(timerRef.current)
        }
    }, [isOpen, threatId])

    // Auto-escalate at 0
    useEffect(() => {
        if (countdown === 0 && !autoEscalated.current && phase === 'alert' && isOpen && activeThreat) {
            autoEscalated.current = true
            console.log('[ALERT] Auto-escalating threat:', threatId)
            handleApprove(null)
        }
    }, [countdown, phase, isOpen, activeThreat, threatId])

    const handleApprove = useCallback((e) => {
        if (phase !== 'alert') return

        let clickX = window.innerWidth / 2
        let clickY = window.innerHeight / 2
        if (e?.clientX && e?.clientY) {
            clickX = e.clientX
            clickY = e.clientY
        }

        setParticleOrigin({ x: clickX, y: clickY })
        setParticleTrigger(true)
        setPhase('containing')

        if (threatId) {
            approveThreat(threatId)
        } else {
            onApprove?.()
        }

        setTimeout(() => {
            setParticleTrigger(false)
            setPhase('contained')
        }, 1800)
    }, [phase, threatId, approveThreat, onApprove])

    const handleApproveAll = useCallback(async (e) => {
        if (phase !== 'alert') return

        let clickX = window.innerWidth / 2
        let clickY = window.innerHeight / 2
        if (e?.clientX && e?.clientY) {
            clickX = e.clientX
            clickY = e.clientY
        }

        setParticleOrigin({ x: clickX, y: clickY })
        setParticleTrigger(true)
        setPhase('containing')

        try {
            await authFetch('/threats/approve-all', { method: 'POST' })
            pendingList.forEach(t => {
                const id = t.threat_id || t.id
                if (id) approveThreat(id)
            })
        } catch (err) {
            console.error('[ALERT] Approve all failed:', err)
        }

        setTimeout(() => {
            setParticleTrigger(false)
            setPhase('contained')
        }, 2000)
    }, [phase, pendingList, approveThreat])

    const handleDismiss = useCallback(() => {
        if (timerRef.current) clearInterval(timerRef.current)
        onDismiss()
    }, [onDismiss])

    const generateForensicReport = () => {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
        const content = `
PHANTOMAGENT FORENSIC REPORT
=============================
Case ID: PA-${Date.now().toString(36).toUpperCase()}
Generated: ${new Date().toLocaleString()}
Classification: CONFIDENTIAL

EXECUTIVE SUMMARY
-----------------
Threat Type: ${activeThreat?.type || 'Unknown'}
Severity: ${activeThreat?.severity || 'N/A'}/10
Source IP: ${activeThreat?.source_ip || 'Unknown'}
Status: CONTAINED

ATTACK TIMELINE
---------------
${new Date().toLocaleTimeString()} - Watcher detected anomalous connection
${new Date().toLocaleTimeString()} - Pre-filter flagged pattern match
${new Date().toLocaleTimeString()} - Gemma classified as ${activeThreat?.type || 'Unknown'}
${new Date().toLocaleTimeString()} - Operator approval received
${new Date().toLocaleTimeString()} - Containment executed

CONTAINMENT ACTIONS
-------------------
[x] Source IP blocked via iptables
[x] Malicious process terminated
[x] Service isolated to network namespace
[x] System snapshot captured
[x] Forensic evidence preserved

INDICATORS OF COMPROMISE (IOCs)
--------------------------------
IP Address: ${activeThreat?.source_ip || 'Unknown'}
Attack Pattern: ${activeThreat?.type || 'Unknown'}
Severity Score: ${activeThreat?.severity || 'N/A'}/10

RECOMMENDATIONS
---------------
1. Review firewall rules for similar patterns
2. Audit user accounts for compromise
3. Update threat intelligence feeds
4. Schedule follow-up scan in 24 hours

Report generated by PhantomAgent v1.0.0
    `.trim()

        const blob = new Blob([content], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `PhantomAgent_Forensic_${timestamp}.txt`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    <ParticleBurst trigger={particleTrigger} originX={particleOrigin.x} originY={particleOrigin.y} />

                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="fixed inset-0 bg-deep-space/90 backdrop-blur-md z-50"
                    />

                    <motion.div
                        initial={{ opacity: 0, scale: 0.8, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.9, y: -20 }}
                        transition={{ duration: 0.5, type: "spring", stiffness: 300, damping: 25 }}
                        className="fixed inset-0 z-50 flex items-center justify-center p-6"
                    >
                        <div className="relative w-full max-w-2xl">
                            {phase === 'alert' && (
                                <motion.div
                                    animate={{ opacity: [0.3, 0.6, 0.3] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                    className="absolute -inset-4 bg-alert-red/20 rounded-3xl blur-2xl"
                                />
                            )}
                            {phase !== 'alert' && (
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 0.4 }}
                                    className="absolute -inset-4 bg-contain-green/20 rounded-3xl blur-2xl"
                                />
                            )}

                            <div className={`relative rounded-2xl border-2 p-8 transition-colors duration-500 ${phase === 'alert'
                                ? 'bg-panel-base/95 border-alert-red/50 shadow-[0_0_60px_rgba(255,42,42,0.3)]'
                                : 'bg-panel-base/95 border-contain-green/50 shadow-[0_0_60px_rgba(0,255,136,0.2)]'
                                }`}>

                                {/* X button - ALWAYS clickable */}
                                <button
                                    onClick={handleDismiss}
                                    className="absolute top-4 right-4 text-data-white/30 hover:text-data-white/60 transition-colors z-10"
                                >
                                    <X size={20} />
                                </button>

                                {/* Multi-Threat Queue Switcher */}
                                {pendingList.length > 1 && phase === 'alert' && (
                                    <div className="mb-5 p-2 rounded-xl bg-alert-red/10 border border-alert-red/30 flex items-center justify-between">
                                        <div className="flex items-center gap-2 text-alert-red text-xs font-mono font-bold">
                                            <Layers size={14} />
                                            <span>CRITICAL THREAT QUEUE ({activeQueueIndex + 1} of {pendingList.length})</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            {pendingList.map((t, idx) => (
                                                <button
                                                    key={t.threat_id || t.id || idx}
                                                    onClick={() => setActiveQueueIndex(idx)}
                                                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-colors ${
                                                        activeQueueIndex === idx
                                                            ? 'bg-alert-red text-white'
                                                            : 'bg-panel-base/60 text-data-white/50 hover:text-data-white'
                                                    }`}
                                                >
                                                    {t.type || `Threat #${idx + 1}`}
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* PHASE: ALERT */}
                                {phase === 'alert' && (
                                    <>
                                        <motion.div
                                            animate={{ scale: [1, 1.1, 1] }}
                                            transition={{ duration: 2, repeat: Infinity }}
                                            className="flex justify-center mb-4"
                                        >
                                            <div className="w-16 h-16 rounded-full bg-alert-red/10 border-2 border-alert-red/50 flex items-center justify-center">
                                                <ShieldAlert size={34} className="text-alert-red" />
                                            </div>
                                        </motion.div>

                                        <h1 className="text-3xl font-black text-center text-alert-red tracking-tighter mb-1 glitch-text">
                                            THREAT DETECTED
                                        </h1>
                                        <p className="text-center text-data-white/50 font-mono text-xs mb-6 tracking-wider">
                                            AWAITING OPERATOR APPROVAL
                                        </p>

                                        <div className="glass-panel p-5 mb-5 border-l-4 border-l-alert-red">
                                            <div className="grid grid-cols-2 gap-4 mb-4">
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Threat Type</span>
                                                    <div className="flex items-center gap-2 mt-1">
                                                        <AlertTriangle size={16} className="text-alert-red" />
                                                        <span className="text-base font-mono font-bold text-data-white">{activeThreat?.type || 'Unknown'}</span>
                                                    </div>
                                                </div>
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Source IP</span>
                                                    <div className="flex items-center gap-2 mt-1">
                                                        <Globe size={16} className="text-neon-cyan" />
                                                        <span className="text-base font-mono font-bold text-data-white">{activeThreat?.source_ip || 'Unknown'}</span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="flex items-center justify-between pt-3 border-t border-panel-border">
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Severity</span>
                                                    <div className="flex items-center gap-3 mt-1">
                                                        <span className="text-3xl font-black text-alert-red">{activeThreat?.severity || '10'}</span>
                                                        <span className="text-[10px] font-mono text-alert-red font-bold px-2 py-0.5 rounded bg-alert-red/10 border border-alert-red/30">CRITICAL</span>
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Auto-Escalate</span>
                                                    <div className="flex items-center gap-2 mt-1 justify-end">
                                                        <Clock size={14} className="text-warning-amber" />
                                                        <motion.span key={countdown} initial={{ scale: 1.2 }} animate={{ scale: 1 }} className="text-lg font-mono font-bold text-warning-amber">
                                                            {countdown}s
                                                        </motion.span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex flex-col sm:flex-row gap-3">
                                            <motion.button
                                                whileHover={{ scale: 1.02 }}
                                                whileTap={{ scale: 0.98 }}
                                                onClick={handleApprove}
                                                className="flex-1 flex items-center justify-center gap-2 py-3.5 rounded-xl bg-contain-green/20 border border-contain-green/50 text-contain-green font-mono font-bold text-base hover:bg-contain-green/30 transition-colors shadow-[0_0_25px_rgba(0,255,136,0.2)]"
                                            >
                                                <ShieldCheck size={20} />
                                                APPROVE CONTAINMENT
                                            </motion.button>

                                            {pendingList.length > 1 && (
                                                <motion.button
                                                    whileHover={{ scale: 1.02 }}
                                                    whileTap={{ scale: 0.98 }}
                                                    onClick={handleApproveAll}
                                                    className="flex items-center justify-center gap-2 px-5 py-3.5 rounded-xl bg-alert-red/20 border border-alert-red/50 text-alert-red font-mono font-bold text-sm hover:bg-alert-red/30 transition-colors"
                                                    title="Contain all active critical threats immediately"
                                                >
                                                    <ShieldCheck size={18} />
                                                    CONTAIN ALL ({pendingList.length})
                                                </motion.button>
                                            )}

                                            <motion.button
                                                whileHover={{ scale: 1.02 }}
                                                whileTap={{ scale: 0.98 }}
                                                onClick={handleDismiss}
                                                className="px-5 py-3.5 rounded-xl bg-panel-base border border-panel-border text-data-white/40 font-mono font-bold hover:bg-panel-border/50 transition-colors"
                                            >
                                                DISMISS
                                            </motion.button>
                                        </div>
                                    </>
                                )}

                                {/* PHASE: CONTAINING */}
                                {phase === 'containing' && (
                                    <>
                                        <div className="flex justify-center mb-5">
                                            <motion.div
                                                animate={{ rotate: 360 }}
                                                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                                                className="w-14 h-14 rounded-full border-4 border-contain-green/30 border-t-contain-green"
                                            />
                                        </div>
                                        <h1 className="text-2xl font-black text-center text-contain-green tracking-tighter mb-2">
                                            CONTAINING THREATS...
                                        </h1>
                                        <div className="space-y-2 mt-4">
                                            {['Blocking source IP via iptables...', 'Terminating suspicious processes...', 'Isolating affected services...', 'Preserving forensic evidence snapshot...'].map((step, i) => (
                                                <motion.div
                                                    key={i}
                                                    initial={{ opacity: 0, x: -20 }}
                                                    animate={{ opacity: 1, x: 0 }}
                                                    transition={{ delay: i * 0.25 }}
                                                    className="flex items-center gap-3 text-xs font-mono text-data-white/60"
                                                >
                                                    <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: i * 0.25 + 0.1 }} className="w-4 h-4 rounded-full bg-contain-green/20 flex items-center justify-center">
                                                        <ShieldCheck size={10} className="text-contain-green" />
                                                    </motion.div>
                                                    {step}
                                                </motion.div>
                                            ))}
                                        </div>
                                    </>
                                )}

                                {/* PHASE: CONTAINED */}
                                {phase === 'contained' && (
                                    <>
                                        <motion.div
                                            initial={{ scale: 0 }}
                                            animate={{ scale: 1 }}
                                            transition={{ type: "spring", stiffness: 200, damping: 15 }}
                                            className="flex justify-center mb-5"
                                        >
                                            <div className="w-16 h-16 rounded-full bg-contain-green/20 border-2 border-contain-green flex items-center justify-center">
                                                <CheckCircle size={36} className="text-contain-green" />
                                            </div>
                                        </motion.div>

                                        <h1 className="text-3xl font-black text-center text-contain-green tracking-tighter mb-1">
                                            THREATS CONTAINED
                                        </h1>
                                        <p className="text-center text-data-white/50 font-mono text-xs mb-5">
                                            Mean Time To Respond: <span className="text-contain-green font-bold">1.2 seconds</span>
                                        </p>

                                        <div className="glass-panel p-4 mb-5 space-y-2">
                                            <div className="flex items-center justify-between text-xs font-mono">
                                                <span className="text-data-white/40">IPs Neutralized</span>
                                                <span className="text-contain-green font-bold">{activeThreat?.source_ip || '172.28.0.10'}</span>
                                            </div>
                                            <div className="flex items-center justify-between text-xs font-mono">
                                                <span className="text-data-white/40">Active Defense Status</span>
                                                <span className="text-contain-green">Active iptables DROP chain enforced</span>
                                            </div>
                                            <div className="flex items-center justify-between text-xs font-mono">
                                                <span className="text-data-white/40">Forensic Snapshot</span>
                                                <span className="text-contain-green">Preserved to /backend/data/</span>
                                            </div>
                                        </div>

                                        <motion.button
                                            whileHover={{ scale: 1.02 }}
                                            whileTap={{ scale: 0.98 }}
                                            onClick={generateForensicReport}
                                            className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl bg-neon-cyan/10 border border-neon-cyan/50 text-neon-cyan font-mono font-bold text-sm hover:bg-neon-cyan/20 transition-colors mb-2"
                                        >
                                            <FileText size={18} />
                                            DOWNLOAD FORENSIC REPORT
                                        </motion.button>

                                        <motion.button
                                            whileHover={{ scale: 1.02 }}
                                            whileTap={{ scale: 0.98 }}
                                            onClick={handleDismiss}
                                            className="w-full py-2.5 rounded-xl bg-panel-base border border-panel-border text-data-white/40 font-mono text-xs hover:bg-panel-border/50 transition-colors"
                                        >
                                            CLOSE WINDOW
                                        </motion.button>
                                    </>
                                )}
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    )
}

export default RedAlertModal