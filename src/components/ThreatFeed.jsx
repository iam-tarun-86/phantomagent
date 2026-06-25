import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, ShieldAlert, ShieldCheck, Globe, FileWarning, Terminal } from 'lucide-react'

const THREAT_TYPES = [
    { type: 'Brute Force', icon: Terminal, color: 'text-alert-red' },
    { type: 'Port Scan', icon: Globe, color: 'text-warning-amber' },
    { type: 'File Anomaly', icon: FileWarning, color: 'text-neon-cyan' },
    { type: 'DNS Tunneling', icon: Globe, color: 'text-purple-400' },
    { type: 'Suspicious Login', icon: AlertTriangle, color: 'text-warning-amber' },
]

const SEVERITY_CONFIG = {
    1: { color: 'bg-gray-500', text: 'text-gray-400', label: 'LOW' },
    2: { color: 'bg-gray-500', text: 'text-gray-400', label: 'LOW' },
    3: { color: 'bg-gray-500', text: 'text-gray-400', label: 'LOW' },
    4: { color: 'bg-warning-amber', text: 'text-warning-amber', label: 'MED' },
    5: { color: 'bg-warning-amber', text: 'text-warning-amber', label: 'MED' },
    6: { color: 'bg-warning-amber', text: 'text-warning-amber', label: 'MED' },
    7: { color: 'bg-orange-500', text: 'text-orange-400', label: 'HIGH' },
    8: { color: 'bg-orange-500', text: 'text-orange-400', label: 'HIGH' },
    9: { color: 'bg-alert-red', text: 'text-alert-red', label: 'CRIT' },
    10: { color: 'bg-alert-red', text: 'text-alert-red', label: 'CRIT' },
}

const generateThreat = () => {
    const typeConfig = THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)]
    const severity = Math.random() > 0.7 ? Math.floor(Math.random() * 4) + 7 : Math.floor(Math.random() * 6) + 1
    const ip = `192.168.1.${Math.floor(Math.random() * 255)}`

    return {
        id: Date.now() + Math.random(),
        type: typeConfig.type,
        icon: typeConfig.icon,
        color: typeConfig.color,
        severity,
        sourceIP: ip,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        status: severity >= 7 ? 'PENDING' : 'RESOLVED'
    }
}

const ThreatCard = ({ threat }) => {
    const Icon = threat.icon
    const config = SEVERITY_CONFIG[threat.severity]

    return (
        <motion.div
            initial={{ x: -50, opacity: 0, scale: 0.95 }}
            animate={{ x: 0, opacity: 1, scale: 1 }}
            exit={{ x: 50, opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
            className="glass-panel p-3 mb-2 border-l-2 hover:bg-panel-base/60 transition-colors cursor-pointer group"
            style={{ borderLeftColor: threat.severity >= 7 ? '#ff2a2a' : threat.severity >= 4 ? '#ffaa00' : '#1a1a2e' }}
        >
            <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                    <Icon size={14} className={threat.color} />
                    <span className="text-xs font-mono font-bold text-data-white">{threat.type}</span>
                </div>
                <span className="text-[10px] font-mono text-data-white/30">{threat.timestamp}</span>
            </div>

            <div className="flex items-center justify-between mt-2">
                <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-data-white/40">SRC:</span>
                    <span className="text-[10px] font-mono text-data-white/60">{threat.sourceIP}</span>
                </div>

                <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${config.text} bg-opacity-20`}>
                        {config.label}
                    </span>
                    <span className={`text-xs font-mono font-bold ${config.text}`}>
                        {threat.severity}
                    </span>
                </div>
            </div>

            {threat.status === 'PENDING' && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-2 flex items-center gap-1.5"
                >
                    <motion.div
                        animate={{ scale: [1, 1.3, 1] }}
                        transition={{ duration: 1, repeat: Infinity }}
                        className="w-1.5 h-1.5 rounded-full bg-alert-red"
                    />
                    <span className="text-[10px] font-mono text-alert-red font-bold tracking-wider">AWAITING APPROVAL</span>
                </motion.div>
            )}
        </motion.div>
    )
}

const ThreatFeed = () => {
    const [threats, setThreats] = useState(() => {
        // Generate initial threats
        const initial = []
        for (let i = 0; i < 5; i++) {
            initial.push(generateThreat())
        }
        return initial.reverse()
    })

    const scrollRef = useRef(null)

    useEffect(() => {
        const interval = setInterval(() => {
            setThreats(prev => {
                const newThreat = generateThreat()
                const updated = [newThreat, ...prev].slice(0, 20) // Keep last 20
                return updated
            })
        }, 4000)

        return () => clearInterval(interval)
    }, [])

    // Auto-scroll to top when new threat arrives
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = 0
        }
    }, [threats])

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between mb-3 px-1">
                <div className="flex items-center gap-2">
                    <ShieldAlert size={16} className="text-alert-red" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">LIVE THREATS</span>
                </div>
                <div className="flex items-center gap-1.5">
                    <motion.div
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="w-2 h-2 rounded-full bg-alert-red"
                    />
                    <span className="text-[10px] font-mono text-alert-red font-bold">LIVE</span>
                </div>
            </div>

            {/* Feed */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto terminal-scroll pr-1"
            >
                <AnimatePresence mode="popLayout">
                    {threats.map(threat => (
                        <ThreatCard key={threat.id} threat={threat} />
                    ))}
                </AnimatePresence>
            </div>

            {/* Stats Footer */}
            <div className="mt-3 pt-2 border-t border-panel-border flex items-center justify-between text-[10px] font-mono">
                <span className="text-data-white/30">TOTAL: <span className="text-data-white/60">{threats.length}</span></span>
                <span className="text-data-white/30">CRITICAL: <span className="text-alert-red">{threats.filter(t => t.severity >= 9).length}</span></span>
            </div>
        </div>
    )
}

export default ThreatFeed