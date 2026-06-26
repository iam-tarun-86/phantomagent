import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, MapPin, Shield, Crosshair } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { getIPLocation, latLonToXY } from '../services/geoService.js'

const AttackMap = () => {
    const { threats, telemetry } = useDashboard()
    const [attacks, setAttacks] = useState([])
    const mapRef = useRef(null)
    const [mapSize, setMapSize] = useState({ width: 800, height: 400 })

    // Update map size on resize
    useEffect(() => {
        const updateSize = () => {
            if (mapRef.current) {
                setMapSize({
                    width: mapRef.current.clientWidth,
                    height: mapRef.current.clientHeight
                })
            }
        }
        updateSize()
        window.addEventListener('resize', updateSize)
        return () => window.removeEventListener('resize', updateSize)
    }, [])

    // Process new threats and geolocate IPs
    useEffect(() => {
        const processThreats = async () => {
            const newAttacks = await Promise.all(
                threats.slice(0, 5).map(async (threat) => {
                    const location = await getIPLocation(threat.source_ip)
                    const coords = latLonToXY(location.lat, location.lon, mapSize.width, mapSize.height)

                    return {
                        id: threat.id,
                        ip: threat.source_ip,
                        type: threat.type,
                        severity: threat.severity,
                        status: threat.status,
                        ...coords,
                        country: location.country,
                        city: location.city
                    }
                })
            )
            setAttacks(newAttacks)
        }

        processThreats()
    }, [threats, mapSize])

    // Your location (center of map)
    const yourX = mapSize.width / 2
    const yourY = mapSize.height / 2

    return (
        <div className="h-full flex flex-col">
            <div className="flex items-center justify-between mb-3 px-1">
                <div className="flex items-center gap-2">
                    <Globe size={16} className="text-neon-cyan" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">ATTACK MAP</span>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-[10px] font-mono text-alert-red">
                        <span className="inline-block w-2 h-2 rounded-full bg-alert-red mr-1" />
                        ACTIVE: {attacks.filter(a => a.status === 'PENDING_APPROVAL').length}
                    </span>
                    <span className="text-[10px] font-mono text-contain-green">
                        <span className="inline-block w-2 h-2 rounded-full bg-contain-green mr-1" />
                        BLOCKED: {telemetry.threats_blocked}
                    </span>
                </div>
            </div>

            <div
                ref={mapRef}
                className="flex-1 glass-panel relative overflow-hidden"
            >
                {/* World map background - simplified dots */}
                <div className="absolute inset-0 opacity-20">
                    {Array.from({ length: 100 }).map((_, i) => (
                        <div
                            key={i}
                            className="absolute w-1 h-1 bg-neon-cyan/40 rounded-full"
                            style={{
                                left: `${Math.random() * 100}%`,
                                top: `${Math.random() * 100}%`,
                            }}
                        />
                    ))}
                </div>

                {/* Grid lines */}
                <div className="absolute inset-0" style={{
                    backgroundImage: 'linear-gradient(rgba(0,240,255,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(0,240,255,0.05) 1px, transparent 1px)',
                    backgroundSize: '50px 50px'
                }} />

                {/* Your location (center) */}
                <div
                    className="absolute z-20"
                    style={{ left: yourX - 12, top: yourY - 12 }}
                >
                    <motion.div
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="w-6 h-6 rounded-full bg-neon-cyan/20 border-2 border-neon-cyan flex items-center justify-center"
                    >
                        <Shield size={12} className="text-neon-cyan" />
                    </motion.div>
                    <div className="absolute -bottom-5 left-1/2 -translate-x-1/2 text-[8px] font-mono text-neon-cyan whitespace-nowrap">
                        YOU
                    </div>
                </div>

                {/* Radar sweep effect */}
                <motion.div
                    className="absolute rounded-full border border-neon-cyan/20"
                    style={{
                        left: yourX - 100,
                        top: yourY - 100,
                        width: 200,
                        height: 200,
                    }}
                    animate={{ scale: [1, 2], opacity: [0.5, 0] }}
                    transition={{ duration: 3, repeat: Infinity }}
                />

                {/* Attack markers */}
                <AnimatePresence>
                    {attacks.map((attack) => (
                        <AttackMarker
                            key={attack.id}
                            attack={attack}
                            yourX={yourX}
                            yourY={yourY}
                        />
                    ))}
                </AnimatePresence>

                {/* Legend */}
                <div className="absolute bottom-2 left-2 text-[8px] font-mono text-data-white/30">
                    {attacks.length > 0 && (
                        <div>
                            {attacks.map(a => (
                                <div key={a.id} className="flex items-center gap-1 mb-0.5">
                                    <MapPin size={8} className={a.severity >= 9 ? 'text-alert-red' : a.severity >= 7 ? 'text-warning-amber' : 'text-neon-cyan'} />
                                    {a.ip} ({a.country})
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

const AttackMarker = ({ attack, yourX, yourY }) => {
    const isCritical = attack.severity >= 9
    const color = isCritical ? '#ff2a2a' : attack.severity >= 7 ? '#ffaa00' : '#00f0ff'

    return (
        <>
            {/* Attack dot */}
            <motion.div
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0, opacity: 0 }}
                className="absolute z-10"
                style={{
                    left: attack.x - 6,
                    top: attack.y - 6,
                }}
            >
                <motion.div
                    animate={{
                        boxShadow: [`0 0 0 0 ${color}40`, `0 0 0 15px ${color}00`]
                    }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: color }}
                />
            </motion.div>

            {/* Connection line */}
            <svg className="absolute inset-0 pointer-events-none z-0">
                <motion.line
                    initial={{ pathLength: 0, opacity: 0 }}
                    animate={{ pathLength: 1, opacity: 0.6 }}
                    transition={{ duration: 1, ease: "easeInOut" }}
                    x1={attack.x}
                    y1={attack.y}
                    x2={yourX}
                    y2={yourY}
                    stroke={color}
                    strokeWidth="1"
                    strokeDasharray="4 4"
                />

                {/* Animated packet traveling along line */}
                <motion.circle
                    r="3"
                    fill={color}
                    animate={{
                        cx: [attack.x, yourX],
                        cy: [attack.y, yourY],
                    }}
                    transition={{
                        duration: 2,
                        repeat: Infinity,
                        ease: "linear"
                    }}
                />
            </svg>

            {/* IP label */}
            <div
                className="absolute text-[8px] font-mono z-10"
                style={{
                    left: attack.x + 8,
                    top: attack.y - 8,
                    color: color
                }}
            >
                {attack.ip}
            </div>
        </>
    )
}

export default AttackMap