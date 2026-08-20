import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal, Clock, AlertTriangle, Info, AlertCircle, Minimize2, Trash2 } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { authFetch } from '../services/auth'
const LOG_COLORS = {
    INFO: 'text-neon-cyan',
    WARN: 'text-warning-amber',
    ERROR: 'text-alert-red',
    CRITICAL: 'text-alert-red font-bold',
    DEBUG: 'text-data-white/40'
}

const LOG_ICONS = {
    INFO: Info,
    WARN: AlertTriangle,
    ERROR: AlertCircle,
    CRITICAL: AlertTriangle,
    DEBUG: Terminal
}

const FullscreenLogViewer = ({ isOpen, onClose }) => {
    const [logs, setLogs] = useState([])
    const [loading, setLoading] = useState(false)
    const { clearLogs } = useDashboard()

    const handleDeleteLogs = async () => {
        try {
            await authFetch('/logs/all', { method: 'DELETE' })
            setLogs([])
            clearLogs()
        } catch (err) {
            console.error('[LOGS] Failed to delete logs:', err)
        }
    }

    // Global ESC key listener to close fullscreen logs
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                onClose?.()
            }
        }
        if (isOpen) {
            window.addEventListener('keydown', handleKeyDown)
        }
        return () => window.removeEventListener('keydown', handleKeyDown)
    }, [isOpen, onClose])

    // Fetch all historical logs from database when opened
    useEffect(() => {
        if (isOpen) {
            setLoading(true)
            authFetch('/logs/all')
                .then(res => res.json())
                .then(data => {
                    setLogs(data || [])
                    setLoading(false)
                })
                .catch(err => {
                    console.error('[LOGS] Failed to fetch:', err)
                    setLoading(false)
                })
        }
    }, [isOpen])

    const getLogIcon = (level) => {
        const Icon = LOG_ICONS[level] || Terminal
        return <Icon size={14} className={LOG_COLORS[level] || 'text-data-white/60'} />
    }

    return (
        <AnimatePresence>
            {isOpen && (
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.3, ease: "easeOut" }}
                    className="fixed inset-0 z-[100] bg-deep-space/98 backdrop-blur-sm"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-panel-border bg-panel-base/50">
                        <div className="flex items-center gap-3">
                            <Terminal size={20} className="text-neon-cyan" />
                            <h2 className="text-lg font-mono font-bold text-data-white tracking-wider">
                                SYSTEM LOGS
                            </h2>
                            <span className="text-xs font-mono text-data-white/40 bg-panel-border px-2 py-0.5 rounded">
                                {logs.length} ENTRIES
                            </span>
                            {loading && (
                                <span className="text-xs font-mono text-neon-cyan animate-pulse">
                                    Loading...
                                </span>
                            )}
                        </div>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={handleDeleteLogs}
                                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-alert-red/10 hover:bg-alert-red/20 text-alert-red/80 hover:text-alert-red font-mono text-sm transition-colors border border-alert-red/20"
                                title="Delete all logs from database"
                            >
                                <Trash2 size={16} />
                                DELETE ALL
                            </button>
                            <button
                                onClick={onClose}
                                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-panel-border/50 hover:bg-panel-border text-data-white/60 hover:text-data-white font-mono text-sm transition-colors"
                            >
                                <Minimize2 size={16} />
                                CLOSE
                            </button>
                        </div>
                    </div>

                    {/* Log Table */}
                    <div className="overflow-auto h-[calc(100vh-80px)] p-6">
                        <div className="min-w-[800px]">
                            {/* Table Header */}
                            <div className="grid grid-cols-[170px_130px_90px_1fr] gap-4 px-4 py-2 text-[10px] font-mono text-data-white/30 uppercase tracking-wider border-b border-panel-border sticky top-0 bg-deep-space/98 z-10">
                                <span>Date & Time</span>
                                <span>Source</span>
                                <span>Level</span>
                                <span>Message</span>
                            </div>

                            {/* Log Entries */}
                            <div className="space-y-1 mt-2">
                                {logs.map((log, index) => (
                                    <motion.div
                                        key={index}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: index * 0.01 }}
                                        className="grid grid-cols-[170px_130px_90px_1fr] gap-4 px-4 py-2.5 rounded hover:bg-panel-border/20 transition-colors font-mono text-xs border-l-2 border-transparent hover:border-l-neon-cyan/30"
                                    >
                                        <span className="text-data-white/50 flex items-center gap-1.5 whitespace-nowrap">
                                            <Clock size={10} className="shrink-0" />
                                            {log.timestamp}
                                        </span>
                                        <span className="text-data-white/60 truncate">
                                            {log.source}
                                        </span>
                                        <span className={`flex items-center gap-1.5 ${LOG_COLORS[log.level] || 'text-data-white/60'}`}>
                                            {getLogIcon(log.level)}
                                            {log.level}
                                        </span>
                                        <span className="text-data-white/80 break-all">
                                            {log.message}
                                        </span>
                                    </motion.div>
                                ))}
                            </div>

                            {logs.length === 0 && !loading && (
                                <div className="text-center py-20 text-data-white/30 font-mono text-sm">
                                    <Terminal size={32} className="mx-auto mb-3 opacity-30" />
                                    No logs available
                                </div>
                            )}
                        </div>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    )
}

export default FullscreenLogViewer