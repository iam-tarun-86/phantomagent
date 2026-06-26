import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const ParticleBurst = ({ trigger, originX, originY }) => {
    const [particles, setParticles] = useState([])

    useEffect(() => {
        if (!trigger) return

        const newParticles = Array.from({ length: 40 }, (_, i) => ({
            id: i,
            angle: (Math.PI * 2 * i) / 40 + (Math.random() - 0.5) * 0.5,
            speed: 2 + Math.random() * 4,
            size: 4 + Math.random() * 8,
            life: 1.5,
            color: ['#00f0ff', '#00ff88', '#ffffff', '#ff2a2a', '#ffaa00'][Math.floor(Math.random() * 5)]
        }))

        setParticles(newParticles)

        setTimeout(() => {
            setParticles([])
        }, 2000)
    }, [trigger, originX, originY])

    if (!trigger || particles.length === 0) return null

    return (
        <div style={{
            position: 'fixed',
            inset: 0,
            pointerEvents: 'none',
            zIndex: 999999,
        }}>
            {particles.map((p) => (
                <motion.div
                    key={p.id}
                    initial={{
                        left: originX,
                        top: originY,
                        opacity: 1,
                        scale: 1,
                    }}
                    animate={{
                        left: originX + Math.cos(p.angle) * p.speed * 60,
                        top: originY + Math.sin(p.angle) * p.speed * 60,
                        opacity: 0,
                        scale: 0,
                    }}
                    transition={{
                        duration: p.life,
                        ease: "easeOut",
                        delay: Math.random() * 0.2
                    }}
                    style={{
                        position: 'absolute',
                        width: p.size,
                        height: p.size,
                        borderRadius: '50%',
                        background: p.color,
                        boxShadow: `0 0 10px ${p.color}, 0 0 20px ${p.color}`,
                    }}
                />
            ))}
        </div>
    )
}

export default ParticleBurst