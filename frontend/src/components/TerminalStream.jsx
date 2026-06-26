import React, { useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'

const LOG_COLORS = {
    'WATCHER': 'text-data-white/70',
    'PREFILTER': 'text-warning-amber',
    'QWEN': 'text-neon-cyan',
    'DECISION': 'text-purple-400',
    'RESPONSE': 'text-contain-green',
    'FORENSIC': 'text-blue-400',
}

const LOG_LEVELS = {
    'INFO': 'text-data-white/70',
    'WARN': 'text-warning-amber',
    'CRITICAL': 'text-alert-red',
}

const TerminalStream = () => {
    const { logs } = useDashboard()
    const scrollRef = useRef(null)

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
                </div>
            </div>

            {/* Terminal */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto terminal-scroll font-mono text-[11px] leading-relaxed"
            >
                <AnimatePresence initial={false}>
                    {logs.map((log, index) => (
                        <motion.div
                            key={index}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0 }}
                            className="flex items-start gap-2 py-0.5 hover:bg-panel-base/50 px-1 rounded"
                        >
                            <span className="text-data-white/20 shrink-0">[{log.timestamp}]</span>
                            <span className={`shrink-0 font-bold ${LOG_LEVELS[log.level] || 'text-data-white/70'}`}>
                                [{log.source}]
                            </span>
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