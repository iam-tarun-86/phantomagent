import React, { useState, useEffect } from 'react'
import { Shield, Activity, Cpu, HardDrive, Zap, Power } from 'lucide-react'
import { motion } from 'framer-motion'
import { useDashboard } from '../context/DashboardContext.jsx'

const MetricBox = ({ icon: Icon, label, value, unit, color, sparkline }) => (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-panel-base/50 border border-panel-border/50">
        <Icon size={14} className={color} />
        <div className="flex flex-col">
            <span className="text-[10px] text-data-white/40 font-mono uppercase tracking-wider">{label}</span>
            <div className="flex items-baseline gap-1">
                <span className={`text-sm font-mono font-bold ${color}`}>{value}</span>
                <span className="text-[10px] text-data-white/30 font-mono">{unit}</span>
            </div>
        </div>
        {sparkline && (
            <svg width="40" height="20" className="ml-1 opacity-60">
                <polyline
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    className={color}
                    points={sparkline.map((v, i) => `${i * 8},${20 - v}`).join(' ')}
                />
            </svg>
        )}
    </div>
)

const AuthorityBar = () => {
    const { telemetry } = useDashboard()
    const [autoMode, setAutoMode] = useState(true)
    const [history, setHistory] = useState({
        cpu: [12, 14, 11, 15, 10],
        ram: [16, 15, 17, 14, 16],
        vram: [14, 15, 13, 14, 15]
    })

    useEffect(() => {
        setHistory(prev => ({
            cpu: [...prev.cpu.slice(1), Math.min(telemetry.cpu + 10, 20)],
            ram: [...prev.ram.slice(1), Math.min(telemetry.ram * 4, 20)],
            vram: [...prev.vram.slice(1), Math.min(telemetry.vram * 2.5, 18)]
        }))
    }, [telemetry])

    return (
        <motion.div
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="h-16 border-b border-panel-border bg-panel-base/60 backdrop-blur-md flex items-center justify-between px-6 fixed top-0 left-0 right-0 z-40"
        >
            {/* Left: Logo */}
            <div className="flex items-center gap-3">
                <div className="relative">
                    <Shield size={24} className="text-neon-cyan" />
                    <motion.div
                        animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="absolute inset-0 bg-neon-cyan/20 rounded-full blur-sm"
                    />
                </div>
                <div className="flex flex-col">
                    <span className="font-mono text-neon-cyan font-bold tracking-[0.2em] text-sm">
                        PHANTOMAGENT
                    </span>
                    <span className="text-[9px] text-data-white/30 font-mono tracking-wider">
                        AUTONOMOUS CYBER SECURITY
                    </span>
                </div>
                <div className="h-6 w-px bg-panel-border mx-2" />
                <span className="text-[10px] text-data-white/20 font-mono">v1.0.0-BETA</span>

                {/* LIVE MONITORING BADGE */}
                <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-contain-green/10 border border-contain-green/30 ml-3">
                    <motion.div
                        animate={{ scale: [1, 1.3, 1], opacity: [1, 0.7, 1] }}
                        transition={{ duration: 1.5, repeat: Infinity }}
                        className="w-1.5 h-1.5 rounded-full bg-contain-green"
                    />
                    <span className="text-[9px] font-mono text-contain-green font-bold tracking-wider">
                        LIVE
                    </span>
                </div>
            </div>

            {/* Center: Telemetry - REAL DATA */}
            <div className="flex items-center gap-2">
                <MetricBox
                    icon={Cpu}
                    label="CPU"
                    value={telemetry.cpu.toFixed(1)}
                    unit="%"
                    color="text-blue-400"
                    sparkline={history.cpu}
                />
                <MetricBox
                    icon={HardDrive}
                    label="RAM"
                    value={telemetry.ram.toFixed(1)}
                    unit="GB"
                    color="text-purple-400"
                    sparkline={history.ram}
                />
                <MetricBox
                    icon={Zap}
                    label="GPU VRAM"
                    value={`${telemetry.vram.toFixed(1)} / 8GB`}
                    unit=""
                    color="text-contain-green"
                    sparkline={history.vram}
                />
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-panel-base/50 border border-panel-border/50">
                    <Activity size={14} className="text-contain-green" />
                    <div className="flex flex-col">
                        <span className="text-[10px] text-data-white/40 font-mono uppercase tracking-wider">Qwen 3.5</span>
                        <div className="flex items-center gap-1.5">
                            <motion.div
                                animate={{ scale: [1, 1.3, 1] }}
                                transition={{ duration: 1.5, repeat: Infinity }}
                                className="w-1.5 h-1.5 rounded-full bg-contain-green"
                            />
                            <span className="text-sm font-mono font-bold text-contain-green">{telemetry.qwen_status}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Right: Status & Controls */}
            <div className="flex items-center gap-4">
                <div className="flex flex-col items-end">
                    <span className="text-[10px] text-data-white/30 font-mono">THREATS BLOCKED</span>
                    <span className="text-lg font-mono font-bold text-contain-green">{telemetry.threats_blocked}</span>
                </div>

                <div className="h-8 w-px bg-panel-border" />

                <div className="flex flex-col items-end">
                    <span className="text-[10px] text-data-white/30 font-mono">UPTIME</span>
                    <span className="text-xs font-mono text-data-white/60">{telemetry.uptime}</span>
                </div>

                <div className="h-8 w-px bg-panel-border" />

                <button
                    onClick={() => setAutoMode(!autoMode)}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-md border transition-all duration-300 ${autoMode
                        ? 'bg-contain-green/10 border-contain-green/30 text-contain-green'
                        : 'bg-warning-amber/10 border-warning-amber/30 text-warning-amber'
                        }`}
                >
                    <Power size={14} />
                    <span className="text-xs font-mono font-bold tracking-wider">
                        {autoMode ? 'AUTO' : 'MANUAL'}
                    </span>
                    <motion.div
                        animate={{ x: autoMode ? 0 : -2 }}
                        className={`w-5 h-2.5 rounded-full relative ${autoMode ? 'bg-contain-green/30' : 'bg-warning-amber/30'
                            }`}
                    >
                        <motion.div
                            animate={{ x: autoMode ? 10 : 0 }}
                            transition={{ type: "spring", stiffness: 500, damping: 30 }}
                            className={`absolute top-0.5 left-0.5 w-1.5 h-1.5 rounded-full ${autoMode ? 'bg-contain-green' : 'bg-warning-amber'
                                }`}
                        />
                    </motion.div>
                </button>
            </div>
        </motion.div>
    )
}

export default AuthorityBar