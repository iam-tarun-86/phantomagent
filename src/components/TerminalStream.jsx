import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal } from 'lucide-react'

const LOG_TYPES = {
    WATCHER: { color: 'text-data-white/70', prefix: '[WATCHER]' },
    PREFILTER: { color: 'text-warning-amber', prefix: '[PREFILTER]' },
    QWEN: { color: 'text-neon-cyan', prefix: '[QWEN]' },
    DECISION: { color: 'text-purple-400', prefix: '[DECISION]' },
    RESPONSE: { color: 'text-contain-green', prefix: '[RESPONSE]' },
    FORENSIC: { color: 'text-blue-400', prefix: '[FORENSIC]' },
}

const generateLog = () => {
    const types = Object.keys(LOG_TYPES)
    const type = types[Math.floor(Math.random() * types.length)]
    const config = LOG_TYPES[type]
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false })

    const messages = {
        WATCHER: [
            `New connection: 185.220.101.${Math.floor(Math.random() * 255)}:22`,
            `File modified: /tmp/suspicious_${Math.floor(Math.random() * 9999)}.sh`,
            `DNS query: ${Math.random().toString(36).substring(7)}.evil-domain.com`,
            `Port scan detected from 45.142.212.${Math.floor(Math.random() * 255)}`,
        ],
        PREFILTER: [
            'Pattern match: 5x failed SSH (10s window) → FLAG',
            'Entropy check: /tmp/suspicious_*.sh = 7.8/8.0 → FLAG',
            'DNS tunnel signature detected → FLAG',
            'Port scan threshold exceeded (50 ports/5s) → FLAG',
        ],
        QWEN: [
            'Analyzing... threat_type: brute_force, severity: 9',
            'Analyzing... threat_type: ransomware, severity: 10',
            'Analyzing... threat_type: port_scan, severity: 6',
            'Analyzing... threat_type: dns_tunneling, severity: 7',
        ],
        DECISION: [
            'Severity 9 → PENDING_APPROVAL',
            'Severity 10 → PENDING_APPROVAL',
            'Severity 6 → AUTO-LOG',
            'Severity 7 → AUTO-ALERT',
        ],
        RESPONSE: [
            'APPROVED → iptables -A INPUT -s 185.220.101.47 -j DROP',
            'Process sshd (PID 2841) terminated',
            'Service nginx isolated → network namespace phantom-jail',
            'IP 45.142.212.89 blocked → 0 packets received',
        ],
        FORENSIC: [
            'Report generated: /var/phantom/reports/2026-06-25_18-16-45.pdf',
            'Snapshot created: /var/phantom/snapshots/snap_2026-06-25_18-16-45.tar',
            'IOCs extracted: 3 IPs, 2 domains, 1 file hash',
            'Timeline compiled: 14 events, 2.3s duration',
        ],
    }

    const message = messages[type][Math.floor(Math.random() * messages[type].length)]

    return {
        id: Date.now() + Math.random(),
        timestamp,
        type,
        config,
        message
    }
}

const TerminalStream = () => {
    const [logs, setLogs] = useState(() => {
        const initial = []
        for (let i = 0; i < 15; i++) {
            initial.push(generateLog())
        }
        return initial
    })

    const scrollRef = useRef(null)
    const [isPaused, setIsPaused] = useState(false)

    useEffect(() => {
        if (isPaused) return

        const interval = setInterval(() => {
            setLogs(prev => {
                const newLog = generateLog()
                return [...prev, newLog].slice(-50) // Keep last 50
            })
        }, 600)

        return () => clearInterval(interval)
    }, [isPaused])

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current && !isPaused) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
    }, [logs, isPaused])

    return (
        <div className="h-full flex flex-col glass-panel p-3">
            {/* Header */}
            <div className="flex items-center justify-between mb-2 px-1">
                <div className="flex items-center gap-2">
                    <Terminal size={14} className="text-contain-green" />
                    <span className="text-xs font-mono font-bold tracking-wider text-data-white">SYSTEM LOGS</span>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-[10px] font-mono text-data-white/30">
                        {logs.length} ENTRIES
                    </span>
                    <button
                        onClick={() => setIsPaused(!isPaused)}
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${isPaused
                                ? 'border-warning-amber text-warning-amber'
                                : 'border-contain-green text-contain-green'
                            }`}
                    >
                        {isPaused ? 'RESUME' : 'PAUSE'}
                    </button>
                </div>
            </div>

            {/* Terminal */}
            <div
                ref={scrollRef}
                onMouseEnter={() => setIsPaused(true)}
                onMouseLeave={() => setIsPaused(false)}
                className="flex-1 overflow-y-auto terminal-scroll font-mono text-[11px] leading-relaxed"
            >
                <AnimatePresence initial={false}>
                    {logs.map((log) => (
                        <motion.div
                            key={log.id}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0 }}
                            className="flex items-start gap-2 py-0.5 hover:bg-panel-base/50 px-1 rounded"
                        >
                            <span className="text-data-white/20 shrink-0">[{log.timestamp}]</span>
                            <span className={`shrink-0 font-bold ${log.config.color}`}>{log.config.prefix}</span>
                            <span className="text-data-white/60 break-all">{log.message}</span>
                        </motion.div>
                    ))}
                </AnimatePresence>

                {/* Blinking cursor */}
                <motion.span
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ duration: 1, repeat: Infinity }}
                    className="text-contain-green ml-1"
                >
                    ▋
                </motion.span>
            </div>
        </div>
    )
}

export default TerminalStream