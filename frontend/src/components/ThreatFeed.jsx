import React, { useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, ShieldAlert, Terminal, Globe, FileWarning, Brain } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'

const THREAT_ICONS = {
    'Brute Force': Terminal,
    'Port Scan': Globe,
    'File Anomaly': FileWarning,
    'DNS Tunneling': Globe,
    'Suspicious Login': AlertTriangle,
    'Malware': AlertTriangle,
    'Unknown': AlertTriangle,
}

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

const ThreatCard = ({ threat }) => {
    console.log('[THREAT CARD]', threat.id, 'reason:', threat.reason, 'confidence:', threat.confidence);
    const Icon = THREAT_ICONS[threat.type] || AlertTriangle
    const config = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG[5]

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
                    <Icon size={14} className={config.text} />
                    <span className="text-xs font-mono font-bold text-data-white">{threat.type}</span>
                </div>
                <span className="text-[10px] font-mono text-data-white/30">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                </span>
            </div>

            <div className="flex items-center justify-between mt-2">
                <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-data-white/40">SRC:</span>
                    <span className="text-[10px] font-mono text-data-white/60">{threat.source_ip}</span>
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

            {threat.status === 'CONTAINED' && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-2 flex items-center gap-1.5"
                >
                    <div className="w-1.5 h-1.5 rounded-full bg-contain-green" />
                    <span className="text-[10px] font-mono text-contain-green font-bold tracking-wider">CONTAINED</span>
                </motion.div>
            )}
            {/* NEW: AI Reason Badge */}
            {threat.reason && (
                <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    transition={{ duration: 0.3 }}
                    className="mt-2 p-2 rounded bg-neon-cyan/5 border border-neon-cyan/20"
                >
                    <div className="flex items-center gap-1.5 mb-1">
                        <Brain size={10} className="text-neon-cyan" />
                        <span className="text-[9px] font-mono text-neon-cyan uppercase tracking-wider">AI Reason</span>
                    </div>
                    <p className="text-[10px] font-mono text-data-white/70 leading-relaxed">
                        {threat.reason}
                    </p>

                    {/* Confidence Score */}
                    {threat.confidence && (
                        <div className="mt-1.5 flex items-center gap-2">
                            <div className="flex-1 h-1 bg-panel-border rounded-full overflow-hidden">
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${threat.confidence}%` }}
                                    transition={{ duration: 1, delay: 0.3 }}
                                    className={`h-full rounded-full ${threat.confidence > 90 ? 'bg-contain-green' : threat.confidence > 70 ? 'bg-warning-amber' : 'bg-alert-red'}`}
                                />
                            </div>
                            <span className="text-[9px] font-mono text-data-white/40">{threat.confidence}% confidence</span>
                        </div>
                    )}
                </motion.div>
            )}
        </motion.div>
    )
}

const ThreatFeed = () => {
    const { threats } = useDashboard()
    const scrollRef = useRef(null)

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between mb-3 px-1">
                <div className="flex items-center gap-2">
                    <ShieldAlert size={16} className="text-alert-red" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">LIVE THREATS</span>
                </div>
                <div className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full bg-alert-red radar-pulse" />
                    <span className="text-[10px] font-mono text-alert-red font-bold flicker-text">LIVE</span>
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