import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Globe, ArrowUpRight, ArrowDownLeft, Wifi } from 'lucide-react'
import { authFetch } from '../services/auth'

const LiveConnections = () => {
    const [connections, setConnections] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchConnections = async () => {
            try {
                const res = await authFetch('/connections')
                const data = await res.json()
                setConnections(data || [])
                setLoading(false)
            } catch (err) {
                console.error('[CONNECTIONS] Failed:', err)
                setLoading(false)
            }
        }

        fetchConnections()
        const interval = setInterval(fetchConnections, 3000)
        return () => clearInterval(interval)
    }, [])

    // Filter out localhost connections for display
    const externalConnections = connections.filter(c =>
        c.ip !== '127.0.0.1' && !c.ip.startsWith('192.168.') && !c.ip.startsWith('10.')
    )

    const localhostConnections = connections.filter(c => c.ip === '127.0.0.1')

    return (
        <div className="glass-panel p-4 h-[200px] flex flex-col">
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                    <Globe size={14} className="text-neon-cyan" />
                    <span className="text-xs font-mono text-data-white/60 uppercase tracking-wider">
                        Live Connections
                    </span>
                    <span className="text-[10px] font-mono text-data-white/30 bg-panel-border px-1.5 py-0.5 rounded">
                        {connections.length}
                    </span>
                </div>
                <div className="flex items-center gap-1.5">
                    <motion.div
                        animate={{ scale: [1, 1.3, 1] }}
                        transition={{ duration: 1, repeat: Infinity }}
                        className="w-1.5 h-1.5 rounded-full bg-contain-green"
                    />
                    <span className="text-[9px] font-mono text-contain-green">LIVE</span>
                </div>
            </div>

            <div className="flex-1 overflow-hidden space-y-1">
                {/* Show external connections first */}
                {externalConnections.slice(0, 6).map((conn, i) => (
                    <motion.div
                        key={`${conn.ip}-${conn.port}-${i}`}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className="flex items-center justify-between text-[10px] font-mono py-1 px-2 rounded hover:bg-panel-border/30 transition-colors"
                    >
                        <div className="flex items-center gap-2">
                            {conn.direction === 'outbound' ? (
                                <ArrowUpRight size={10} className="text-neon-cyan" />
                            ) : (
                                <ArrowDownLeft size={10} className="text-warning-amber" />
                            )}
                            <span className="text-data-white/70">{conn.ip}</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-data-white/40">:{conn.port}</span>
                            <span className={`text-[9px] px-1.5 py-0.5 rounded ${conn.status === 'ESTABLISHED'
                                ? 'bg-contain-green/10 text-contain-green'
                                : 'bg-warning-amber/10 text-warning-amber'
                                }`}>
                                {conn.status}
                            </span>
                        </div>
                    </motion.div>
                ))}

                {/* If no external connections, show localhost */}
                {externalConnections.length === 0 && localhostConnections.length > 0 && (
                    <div className="text-center py-4">
                        <Wifi size={20} className="mx-auto mb-2 text-data-white/20" />
                        <p className="text-[10px] font-mono text-data-white/30 mb-1">
                            No external connections
                        </p>
                        <p className="text-[9px] font-mono text-data-white/20">
                            {localhostConnections.length} localhost active
                        </p>
                    </div>
                )}

                {connections.length === 0 && !loading && (
                    <div className="text-center py-8 text-data-white/20 text-xs font-mono">
                        No active connections
                    </div>
                )}
            </div>
        </div>
    )
}

export default LiveConnections