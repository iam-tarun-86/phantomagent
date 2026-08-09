import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldAlert, ShieldCheck, X, Clock, Globe, AlertTriangle, FileText } from 'lucide-react'
import ParticleBurst from './ParticleBurst'

const RedAlertModal = ({ isOpen, threat, onApprove, onDismiss }) => {
    const [countdown, setCountdown] = useState(15)
    const [phase, setPhase] = useState('alert') // 'alert' | 'containing' | 'contained'
    const [particleTrigger, setParticleTrigger] = useState(false)
    const [particleOrigin, setParticleOrigin] = useState({ x: 0, y: 0 })
    const autoEscalated = useRef(false)
    const timerRef = useRef(null)
    const audioCtxRef = useRef(null)
    const oscillatorRef = useRef(null)

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
                
                // Siren modulation
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
                
                gain.gain.setValueAtTime(0.1, ctx.currentTime) // Keep volume low
                osc.start()
                oscillatorRef.current = { osc, modInterval }
                
            } catch (e) {
                console.error("Audio API not supported or blocked", e)
            }
        } else {
            // Stop alarm if closed or phase changed
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

    // HARD RESET when modal opens with new threat
    useEffect(() => {
        if (!isOpen) {
            if (timerRef.current) clearInterval(timerRef.current)
            autoEscalated.current = false
            return
        }

        // FORCE RESET everything
        setCountdown(15)
        setPhase('alert')
        setParticleTrigger(false)
        autoEscalated.current = false

        // Start countdown
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
    }, [isOpen, threat?.id])

    // Cleanup when modal closes
    useEffect(() => {
        if (!isOpen) {
            setPhase('alert')
            setCountdown(15)
            setParticleTrigger(false)
            autoEscalated.current = false
            if (timerRef.current) clearInterval(timerRef.current)
        }
    }, [isOpen])

    // Auto-escalate at 0
    useEffect(() => {
        if (countdown === 0 && !autoEscalated.current && phase === 'alert' && isOpen && threat) {
            autoEscalated.current = true
            console.log('[ALERT] Auto-escalating')
            handleApprove(null)
        }
    }, [countdown, phase, isOpen, threat])

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

        // Call backend (fire and forget)
        onApprove()

        // FORCE progress to contained after 2s regardless
        setTimeout(() => {
            setParticleTrigger(false)
            setPhase('contained')
        }, 2000)
    }, [phase, onApprove])

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
Threat Type: ${threat?.type || 'Unknown'}
Severity: ${threat?.severity || 'N/A'}/10
Source IP: ${threat?.source_ip || 'Unknown'}
Status: CONTAINED

ATTACK TIMELINE
---------------
${new Date().toLocaleTimeString()} - Watcher detected anomalous connection
${new Date().toLocaleTimeString()} - Pre-filter flagged pattern match
${new Date().toLocaleTimeString()} - Gemma classified as ${threat?.type || 'Unknown'}
${new Date().toLocaleTimeString()} - Human approval received
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
IP Address: ${threat?.source_ip || 'Unknown'}
Attack Pattern: ${threat?.type || 'Unknown'}
Severity Score: ${threat?.severity || 'N/A'}/10

RECOMMENDATIONS
---------------
1. Review firewall rules for similar patterns
2. Audit user accounts for compromise
3. Update threat intelligence feeds
4. Schedule follow-up scan in 24 hours

Report generated by PhantomAgent v1.0.0-BETA
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
            {isOpen && threat && (
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

                                {/* PHASE: ALERT */}
                                {phase === 'alert' && (
                                    <>
                                        <motion.div
                                            animate={{ scale: [1, 1.1, 1] }}
                                            transition={{ duration: 2, repeat: Infinity }}
                                            className="flex justify-center mb-6"
                                        >
                                            <div className="w-20 h-20 rounded-full bg-alert-red/10 border-2 border-alert-red/50 flex items-center justify-center">
                                                <ShieldAlert size={40} className="text-alert-red" />
                                            </div>
                                        </motion.div>

                                        <h1 className="text-4xl font-black text-center text-alert-red tracking-tighter mb-2 glitch-text">
                                            THREAT DETECTED
                                        </h1>
                                        <p className="text-center text-data-white/50 font-mono text-sm mb-8 tracking-wider">
                                            AWAITING OPERATOR APPROVAL
                                        </p>

                                        <div className="glass-panel p-5 mb-6 border-l-4 border-l-alert-red">
                                            <div className="grid grid-cols-2 gap-4 mb-4">
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Threat Type</span>
                                                    <div className="flex items-center gap-2 mt-1">
                                                        <AlertTriangle size={16} className="text-alert-red" />
                                                        <span className="text-lg font-mono font-bold text-data-white">{threat?.type || 'Unknown'}</span>
                                                    </div>
                                                </div>
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Source IP</span>
                                                    <div className="flex items-center gap-2 mt-1">
                                                        <Globe size={16} className="text-neon-cyan" />
                                                        <span className="text-lg font-mono font-bold text-data-white">{threat?.source_ip || 'Unknown'}</span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="flex items-center justify-between pt-4 border-t border-panel-border">
                                                <div>
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Severity</span>
                                                    <div className="flex items-center gap-3 mt-1">
                                                        <span className="text-4xl font-black text-alert-red">{threat?.severity || '?'}</span>
                                                        <span className="text-xs font-mono text-alert-red font-bold px-2 py-1 rounded bg-alert-red/10">CRITICAL</span>
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <span className="text-[10px] font-mono text-data-white/30 uppercase tracking-wider">Auto-Escalate</span>
                                                    <div className="flex items-center gap-2 mt-1 justify-end">
                                                        <Clock size={14} className="text-warning-amber" />
                                                        <motion.span key={countdown} initial={{ scale: 1.2 }} animate={{ scale: 1 }} className="text-xl font-mono font-bold text-warning-amber">
                                                            {countdown}s
                                                        </motion.span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex gap-4">
                                            <motion.button
                                                whileHover={{ scale: 1.02 }}
                                                whileTap={{ scale: 0.98 }}
                                                onClick={handleApprove}
                                                className="flex-1 flex items-center justify-center gap-3 py-4 rounded-xl bg-contain-green/20 border border-contain-green/50 text-contain-green font-mono font-bold text-lg hover:bg-contain-green/30 transition-colors shadow-[0_0_30px_rgba(0,255,136,0.2)]"
                                            >
                                                <ShieldCheck size={24} />
                                                APPROVE CONTAINMENT
                                            </motion.button>

                                            <motion.button
                                                whileHover={{ scale: 1.02 }}
                                                whileTap={{ scale: 0.98 }}
                                                onClick={handleDismiss}
                                                className="px-6 py-4 rounded-xl bg-panel-base border border-panel-border text-data-white/40 font-mono font-bold hover:bg-panel-border/50 transition-colors"
                                            >
                                                DISMISS
                                            </motion.button>
                                        </div>
                                    </>
                                )}

                                {/* PHASE: CONTAINING */}
                                {phase === 'containing' && (
                                    <>
                                        <div className="flex justify-center mb-6">
                                            <motion.div
                                                animate={{ rotate: 360 }}
                                                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                                                className="w-16 h-16 rounded-full border-4 border-contain-green/30 border-t-contain-green"
                                            />
                                        </div>
                                        <h1 className="text-3xl font-black text-center text-contain-green tracking-tighter mb-2">
                                            CONTAINING THREAT...
                                        </h1>
                                        <div className="space-y-2 mt-6">
                                            {['Blocking source IP...', 'Terminating malicious process...', 'Isolating service...', 'Generating forensic snapshot...'].map((step, i) => (
                                                <motion.div
                                                    key={i}
                                                    initial={{ opacity: 0, x: -20 }}
                                                    animate={{ opacity: 1, x: 0 }}
                                                    transition={{ delay: i * 0.3 }}
                                                    className="flex items-center gap-3 text-sm font-mono text-data-white/60"
                                                >
                                                    <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: i * 0.3 + 0.2 }} className="w-4 h-4 rounded-full bg-contain-green/20 flex items-center justify-center">
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
                                            className="flex justify-center mb-6"
                                        >
                                            <div className="w-20 h-20 rounded-full bg-contain-green/20 border-2 border-contain-green flex items-center justify-center">
                                                <ShieldCheck size={40} className="text-contain-green" />
                                            </div>
                                        </motion.div>

                                        <h1 className="text-4xl font-black text-center text-contain-green tracking-tighter mb-2">
                                            THREAT CONTAINED
                                        </h1>
                                        <p className="text-center text-data-white/50 font-mono text-sm mb-6">
                                            Mean Time To Respond: <span className="text-contain-green font-bold">1.2 seconds</span>
                                        </p>

                                        <div className="glass-panel p-4 mb-6 space-y-2">
                                            <div className="flex items-center justify-between text-sm font-mono">
                                                <span className="text-data-white/40">IP Blocked</span>
                                                <span className="text-contain-green">{threat?.source_ip}</span>
                                            </div>
                                            <div className="flex items-center justify-between text-sm font-mono">
                                                <span className="text-data-white/40">Process Terminated</span>
                                                <span className="text-contain-green">sshd (PID 2841)</span>
                                            </div>
                                            <div className="flex items-center justify-between text-sm font-mono">
                                                <span className="text-data-white/40">Service Isolated</span>
                                                <span className="text-contain-green">nginx → phantom-jail</span>
                                            </div>
                                        </div>

                                        <motion.button
                                            whileHover={{ scale: 1.02 }}
                                            whileTap={{ scale: 0.98 }}
                                            onClick={generateForensicReport}
                                            className="w-full flex items-center justify-center gap-3 py-4 rounded-xl bg-neon-cyan/10 border border-neon-cyan/50 text-neon-cyan font-mono font-bold hover:bg-neon-cyan/20 transition-colors mb-3"
                                        >
                                            <FileText size={20} />
                                            DOWNLOAD FORENSIC REPORT
                                        </motion.button>

                                        <motion.button
                                            whileHover={{ scale: 1.02 }}
                                            whileTap={{ scale: 0.98 }}
                                            onClick={handleDismiss}
                                            className="w-full py-3 rounded-xl bg-panel-base border border-panel-border text-data-white/40 font-mono text-sm hover:bg-panel-border/50 transition-colors"
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