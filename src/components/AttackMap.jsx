import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe } from 'lucide-react'
// Simplified world map coordinates (dots for major regions)
const WORLD_DOTS = [
    // North America
    { x: 18, y: 28, region: 'NA' }, { x: 20, y: 30, region: 'NA' }, { x: 22, y: 32, region: 'NA' },
    { x: 16, y: 35, region: 'NA' }, { x: 19, y: 38, region: 'NA' }, { x: 21, y: 40, region: 'NA' },
    // South America
    { x: 28, y: 60, region: 'SA' }, { x: 30, y: 65, region: 'SA' }, { x: 26, y: 70, region: 'SA' },
    // Europe
    { x: 50, y: 25, region: 'EU' }, { x: 52, y: 28, region: 'EU' }, { x: 48, y: 30, region: 'EU' },
    { x: 51, y: 32, region: 'EU' }, { x: 54, y: 26, region: 'EU' },
    // Africa
    { x: 52, y: 50, region: 'AF' }, { x: 50, y: 55, region: 'AF' }, { x: 55, y: 60, region: 'AF' },
    // Asia
    { x: 70, y: 30, region: 'AS' }, { x: 75, y: 35, region: 'AS' }, { x: 72, y: 40, region: 'AS' },
    { x: 78, y: 32, region: 'AS' }, { x: 65, y: 45, region: 'AS' }, { x: 80, y: 50, region: 'AS' },
    // Oceania
    { x: 85, y: 70, region: 'OC' }, { x: 88, y: 75, region: 'OC' },
]

const COUNTRIES = ['Russia', 'China', 'North Korea', 'Iran', 'Brazil', 'Nigeria', 'Vietnam', 'Romania', 'USA', 'India']

const generateAttack = () => ({
    id: Date.now() + Math.random(),
    x: WORLD_DOTS[Math.floor(Math.random() * WORLD_DOTS.length)].x + (Math.random() * 4 - 2),
    y: WORLD_DOTS[Math.floor(Math.random() * WORLD_DOTS.length)].y + (Math.random() * 4 - 2),
    country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)],
    severity: Math.floor(Math.random() * 10) + 1,
    timestamp: Date.now()
})

const AttackRipple = ({ attack }) => {
    const isHigh = attack.severity >= 7
    const color = isHigh ? '#ff2a2a' : attack.severity >= 4 ? '#ffaa00' : '#00f0ff'

    return (
        <motion.g
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
        >
            {/* Center dot */}
            <circle cx={attack.x} cy={attack.y} r="1.5" fill={color} />

            {/* Ripple rings - FIXED: use CSS animation instead of framer motion for SVG r */}
            {[1, 2, 3].map((ring) => (
                <circle
                    key={ring}
                    cx={attack.x}
                    cy={attack.y}
                    r={2 + ring * 0.1}
                    fill="none"
                    stroke={color}
                    strokeWidth="0.5"
                    opacity={0.8 - ring * 0.2}
                >
                    <animate
                        attributeName="r"
                        from="2"
                        to={String(8 + ring * 4)}
                        dur="3s"
                        begin={`${ring * 0.4}s`}
                        repeatCount="indefinite"
                    />
                    <animate
                        attributeName="opacity"
                        from="0.8"
                        to="0"
                        dur="3s"
                        begin={`${ring * 0.4}s`}
                        repeatCount="indefinite"
                    />
                    <animate
                        attributeName="strokeWidth"
                        from="0.5"
                        to="0.1"
                        dur="3s"
                        begin={`${ring * 0.4}s`}
                        repeatCount="indefinite"
                    />
                </circle>
            ))}

            {/* Arc line to center (defended location) */}
            <motion.path
                d={`M ${attack.x} ${attack.y} Q ${(attack.x + 50) / 2} ${(attack.y + 50) / 2 - 10} 50 50`}
                fill="none"
                stroke={color}
                strokeWidth="0.3"
                strokeDasharray="2,2"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: [0, 0.6, 0] }}
                transition={{ duration: 2, ease: "easeInOut" }}
            />
        </motion.g>
    )
}

const AttackMap = () => {
    const [attacks, setAttacks] = useState([])
    const [stats, setStats] = useState({ active: 3, blocked: 47 })

    useEffect(() => {
        // Initial attacks
        const initial = []
        for (let i = 0; i < 3; i++) {
            initial.push(generateAttack())
        }
        setAttacks(initial)

        const interval = setInterval(() => {
            setAttacks(prev => {
                const newAttack = generateAttack()
                const updated = [...prev, newAttack].filter(a => Date.now() - a.timestamp < 8000)
                return updated
            })
            setStats(prev => ({
                active: Math.floor(Math.random() * 3) + 1,
                blocked: prev.blocked + Math.floor(Math.random() * 2)
            }))
        }, 3500)

        return () => clearInterval(interval)
    }, [])

    return (
        <div className="h-full flex flex-col glass-panel p-4 relative overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                    <Globe size={16} className="text-neon-cyan" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">ATTACK MAP</span>
                </div>
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-alert-red animate-pulse" />
                        <span className="text-[10px] font-mono text-data-white/60">ACTIVE: <span className="text-alert-red font-bold">{stats.active}</span></span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-contain-green" />
                        <span className="text-[10px] font-mono text-data-white/60">BLOCKED: <span className="text-contain-green font-bold">{stats.blocked}</span></span>
                    </div>
                </div>
            </div>

            {/* Map SVG */}
            <div className="flex-1 relative">
                <svg viewBox="0 0 100 100" className="w-full h-full" preserveAspectRatio="xMidYMid meet">
                    {/* Grid lines */}
                    <defs>
                        <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
                            <path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(26,26,46,0.3)" strokeWidth="0.2" />
                        </pattern>
                    </defs>
                    <rect width="100" height="100" fill="url(#grid)" />

                    {/* World dots */}
                    {WORLD_DOTS.map((dot, i) => (
                        <circle key={i} cx={dot.x} cy={dot.y} r="0.4" fill="rgba(26,26,46,0.6)" />
                    ))}

                    {/* Center point (defended) */}
                    <circle cx="50" cy="50" r="2" fill="rgba(0,240,255,0.2)" />
                    <circle cx="50" cy="50" r="1" fill="#00f0ff" />
                    <circle cx="50" cy="50" r="3" fill="none" stroke="#00f0ff" strokeWidth="0.3">
                        <animate
                            attributeName="r"
                            values="3;6;3"
                            dur="3s"
                            repeatCount="indefinite"
                        />
                        <animate
                            attributeName="opacity"
                            values="0.5;0.2;0.5"
                            dur="3s"
                            repeatCount="indefinite"
                        />
                    </circle>

                    {/* Attack ripples */}
                    <AnimatePresence>
                        {attacks.map(attack => (
                            <AttackRipple key={attack.id} attack={attack} />
                        ))}
                    </AnimatePresence>
                </svg>

                {/* Scan line effect */}
                <motion.div
                    className="absolute inset-0 bg-gradient-to-b from-transparent via-neon-cyan/5 to-transparent"
                    animate={{ top: ['-100%', '100%'] }}
                    transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
                    style={{ height: '20%' }}
                />
            </div>

            {/* Recent attacks list */}
            <div className="mt-2 pt-2 border-t border-panel-border">
                <div className="flex gap-2 overflow-hidden">
                    {attacks.slice(-3).map((attack, i) => (
                        <div key={attack.id} className="flex items-center gap-1.5 px-2 py-1 rounded bg-panel-base/50 border border-panel-border/30">
                            <span className={`w-1.5 h-1.5 rounded-full ${attack.severity >= 7 ? 'bg-alert-red' : attack.severity >= 4 ? 'bg-warning-amber' : 'bg-neon-cyan'}`} />
                            <span className="text-[10px] font-mono text-data-white/60">{attack.country}</span>
                            <span className="text-[10px] font-mono text-data-white/40">Sev-{attack.severity}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    )
}

export default AttackMap