import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Terminal, Maximize2 } from 'lucide-react'
import FullscreenLogViewer from './FullscreenLogViewer'

const LOG_COLORS = {
    INFO: 'text-neon-cyan',
    WARN: 'text-warning-amber',
    ERROR: 'text-alert-red',
    CRITICAL: 'text-alert-red font-bold',
    DEBUG: 'text-data-white/40'
}

const LogPanel = ({ logs }) => {
    const [showFullscreen, setShowFullscreen] = useState(false)

    const recentLogs = logs.slice(-10).reverse()

    return (
        <>
            <div className="glass-panel p-4 h-[280px] flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                        <Terminal size={14} className="text-neon-cyan" />
                        <span className="text-xs font-mono text-data-white/60 uppercase tracking-wider">System Logs</span>
                        <span className="text-[10px] font-mono text-data-white/30 bg-panel-border px-1.5 py-0.5 rounded">
                            {logs.length}
                        </span>
                    </div>
                    <button
                        onClick={() => setShowFullscreen(true)}
                        className="p-1.5 rounded hover:bg-panel-border text-data-white/40 hover:text-neon-cyan transition-colors"
                        title="View Fullscreen Logs"
                    >
                        <Maximize2 size={14} />
                    </button>
                </div>

                {/* Small Log List */}
                <div className="flex-1 overflow-hidden space-y-1">
                    {recentLogs.map((log, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.03 }}
                            className="flex items-center gap-2 text-[10px] font-mono py-1 px-2 rounded hover:bg-panel-border/30 transition-colors"
                        >
                            <span className="text-data-white/30 w-[50px] shrink-0">{log.timestamp}</span>
                            <span className={`${LOG_COLORS[log.level] || 'text-data-white/60'} w-[50px] shrink-0`}>
                                {log.level}
                            </span>
                            <span className="text-data-white/70 truncate">{log.message}</span>
                        </motion.div>
                    ))}
                    {logs.length === 0 && (
                        <div className="text-center py-8 text-data-white/20 text-xs font-mono">
                            No logs yet...
                        </div>
                    )}
                </div>
            </div>

            <FullscreenLogViewer
                isOpen={showFullscreen}
                logs={logs}
                onClose={() => setShowFullscreen(false)}
            />
        </>
    )
}

export default LogPanel