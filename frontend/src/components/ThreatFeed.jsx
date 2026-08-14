import React, { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, ShieldAlert, Terminal, Globe, FileWarning, Brain, Filter } from 'lucide-react'
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

const ThreatCard = ({ threat, onClick }) => {
    const Icon = THREAT_ICONS[threat.type] || AlertTriangle
    const config = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG[5]

    return (
        <motion.div
            initial={{ x: -50, opacity: 0, scale: 0.95 }}
            animate={{ x: 0, opacity: 1, scale: 1 }}
            exit={{ x: 50, opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.3, ease: "easeOut" }}
            onClick={onClick}
            className="glass-panel p-3 mb-2 border-l-2 hover:bg-panel-base/70 transition-all cursor-pointer group hover:border-neon-cyan/50"
            style={{ borderLeftColor: threat.severity >= 8 ? '#ff2a2a' : threat.severity >= 6 ? '#ffaa00' : '#1a1a2e' }}
        >
            <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                    <Icon size={14} className={config.text} />
                    <span className="text-xs font-mono font-bold text-data-white group-hover:text-neon-cyan transition-colors">{threat.type}</span>
                </div>
                <span className="text-[10px] font-mono text-data-white/40 font-bold">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                </span>
            </div>

            <div className="flex items-center justify-between mt-2">
                <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-data-white/40">SRC:</span>
                    <span className="text-[10px] font-mono font-bold text-data-white/80">{threat.source_ip}</span>
                </div>

                <div className="flex items-center gap-1.5">
                    <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                        threat.severity >= 8 ? 'bg-alert-red/20 border-alert-red/40 text-alert-red' : 'bg-warning-amber/20 border-warning-amber/40 text-warning-amber'
                    }`}>
                        SEV {threat.severity}
                    </span>
                </div>
            </div>

            {threat.status === 'PENDING' && (
                <div className="mt-2 flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-alert-red radar-pulse" />
                    <span className="text-[9px] font-mono text-alert-red font-bold tracking-wider">AWAITING APPROVAL</span>
                </div>
            )}

            {threat.status === 'CONTAINED' && (
                <div className="mt-2 flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-contain-green" />
                    <span className="text-[9px] font-mono text-contain-green font-bold tracking-wider">CONTAINED</span>
                </div>
            )}

            {threat.reason && (
                <div className="mt-2 p-2 rounded bg-neon-cyan/5 border border-neon-cyan/20">
                    <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-1.5">
                            <Brain size={10} className="text-neon-cyan" />
                            <span className="text-[9px] font-mono text-neon-cyan uppercase tracking-wider font-bold">AI Verdict</span>
                        </div>
                        <div className={`px-1.5 py-0.2 rounded text-[8px] font-mono font-bold ${
                            threat.has_consensus !== false
                                ? 'bg-contain-green/20 text-contain-green border border-contain-green/30'
                                : 'bg-warning-amber/20 text-warning-amber border border-warning-amber/30'
                        }`}>
                            {threat.consensus_votes ?? 3}/5 VOTES
                        </div>
                    </div>
                    <p className="text-[10px] font-mono text-data-white/70 leading-relaxed line-clamp-2">
                        {threat.reason}
                    </p>
                </div>
            )}
        </motion.div>
    )
}

const ThreatFeed = ({ onSelectThreat }) => {
    const { threats } = useDashboard()
    const [filter, setFilter] = useState('ALL') // 'ALL' | 'CRITICAL' | 'CONTAINED'
    const scrollRef = useRef(null)

    const filteredThreats = threats.filter(t => {
        if (filter === 'CRITICAL') return t.severity >= 8
        if (filter === 'CONTAINED') return t.status === 'CONTAINED'
        return true
    })

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between mb-2 px-1">
                <div className="flex items-center gap-2">
                    <ShieldAlert size={16} className="text-alert-red" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">LIVE THREATS</span>
                </div>
                <div className="flex items-center gap-1.5">
                    <button onClick={() => fetch('http://localhost:8000/api/test/inject-auto', {method: 'POST'})} className="text-[9px] font-mono px-2 py-0.5 bg-warning-amber/20 text-warning-amber rounded border border-warning-amber/30 hover:bg-warning-amber/40 transition-colors cursor-pointer">AUTO</button>
                    <button onClick={() => fetch('http://localhost:8000/api/test/inject-lateral', {method: 'POST'})} className="text-[9px] font-mono px-2 py-0.5 bg-alert-red/20 text-alert-red rounded border border-alert-red/30 hover:bg-alert-red/40 transition-colors cursor-pointer">APT</button>
                    <div className="flex items-center gap-1 ml-1">
                        <div className="w-2 h-2 rounded-full bg-alert-red radar-pulse" />
                        <span className="text-[10px] font-mono text-alert-red font-bold">LIVE</span>
                    </div>
                </div>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1 mb-3 p-1 rounded bg-panel-base/40 border border-panel-border text-[9px] font-mono">
                <Filter size={10} className="text-data-white/40 ml-1 mr-0.5" />
                {['ALL', 'CRITICAL', 'CONTAINED'].map(f => (
                    <button
                        key={f}
                        onClick={() => setFilter(f)}
                        className={`flex-1 py-1 rounded transition-colors font-bold ${
                            filter === f
                                ? 'bg-neon-cyan/20 text-neon-cyan border border-neon-cyan/30'
                                : 'text-data-white/40 hover:text-data-white hover:bg-data-white/5'
                        }`}
                    >
                        {f} ({
                            f === 'ALL' ? threats.length :
                            f === 'CRITICAL' ? threats.filter(t => t.severity >= 8).length :
                            threats.filter(t => t.status === 'CONTAINED').length
                        })
                    </button>
                ))}
            </div>

            {/* Feed */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto terminal-scroll pr-1"
            >
                <AnimatePresence mode="popLayout">
                    {filteredThreats.map(threat => (
                        <ThreatCard
                            key={threat.id}
                            threat={threat}
                            onClick={() => onSelectThreat && onSelectThreat(threat)}
                        />
                    ))}
                </AnimatePresence>
            </div>

            {/* Stats Footer */}
            <div className="mt-3 pt-2 border-t border-panel-border flex items-center justify-between text-[10px] font-mono">
                <span className="text-data-white/40 font-bold">TOTAL: <span className="text-data-white">{threats.length}</span></span>
                <span className="text-data-white/40 font-bold">CRITICAL: <span className="text-alert-red">{threats.filter(t => t.severity >= 8).length}</span></span>
            </div>
        </div>
    )
}

export default ThreatFeed