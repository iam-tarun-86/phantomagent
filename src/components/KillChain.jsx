import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Eye, Filter, Brain, Scale, ShieldCheck, AlertCircle } from 'lucide-react'

const CHAIN_NODES = [
  { id: 'watcher', label: 'Network Watcher', icon: Eye, color: 'text-blue-400' },
  { id: 'prefilter', label: 'Pre-Filter', icon: Filter, color: 'text-purple-400' },
  { id: 'qwen', label: 'Qwen 3.5', icon: Brain, color: 'text-neon-cyan' },
  { id: 'decision', label: 'Decision Engine', icon: Scale, color: 'text-warning-amber' },
  { id: 'response', label: 'Response', icon: ShieldCheck, color: 'text-contain-green' },
]

const KillChain = () => {
  const [activeNode, setActiveNode] = useState(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [lastThreat, setLastThreat] = useState(null)

  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate attack processing
      setIsProcessing(true)
      setActiveNode(0)
      
      const sequence = [0, 1, 2, 3, 4]
      let current = 0
      
      const stepInterval = setInterval(() => {
        current++
        if (current >= sequence.length) {
          clearInterval(stepInterval)
          setIsProcessing(false)
          setLastThreat({
            severity: Math.floor(Math.random() * 4) + 7,
            action: Math.random() > 0.5 ? 'AUTO-CONTAIN' : 'PENDING'
          })
          setTimeout(() => {
            setActiveNode(null)
            setLastThreat(null)
          }, 3000)
          return
        }
        setActiveNode(current)
      }, 800)
      
    }, 8000)
    
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3 px-1">
        <ShieldCheck size={16} className="text-contain-green" />
        <span className="text-sm font-mono font-bold tracking-wider text-data-white">KILL CHAIN</span>
      </div>
      
      {/* Chain */}
      <div className="flex-1 glass-panel p-4 flex flex-col gap-3 relative">
        {CHAIN_NODES.map((node, index) => {
          const Icon = node.icon
          const isActive = activeNode === index
          const isPast = activeNode !== null && index < activeNode
          const isComplete = isPast || (!isProcessing && lastThreat)
          
          return (
            <div key={node.id} className="relative">
              {/* Connector line */}
              {index < CHAIN_NODES.length - 1 && (
                <div className="absolute left-[19px] top-[36px] w-0.5 h-[calc(100%+12px)] bg-panel-border">
                  <motion.div
                    className="w-full bg-contain-green"
                    initial={{ height: '0%' }}
                    animate={{ 
                      height: isPast ? '100%' : isActive ? '50%' : '0%'
                    }}
                    transition={{ duration: 0.4 }}
                  />
                </div>
              )}
              
              {/* Node */}
              <motion.div
                animate={{
                  scale: isActive ? 1.05 : 1,
                  borderColor: isActive ? 'rgba(0,240,255,0.5)' : isComplete ? 'rgba(0,255,136,0.3)' : 'rgba(26,26,46,0.5)'
                }}
                className={`flex items-center gap-3 p-2.5 rounded-lg border transition-colors ${
                  isActive ? 'bg-neon-cyan/5' : isComplete ? 'bg-contain-green/5' : 'bg-panel-base/30'
                }`}
              >
                <div className="relative">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center border ${
                    isActive ? 'border-neon-cyan/50 bg-neon-cyan/10' : 
                    isComplete ? 'border-contain-green/30 bg-contain-green/10' : 
                    'border-panel-border bg-panel-base'
                  }`}>
                    <Icon size={18} className={isActive ? 'text-neon-cyan' : isComplete ? 'text-contain-green' : 'text-data-white/30'} />
                  </div>
                  
                  {isActive && (
                    <motion.div
                      className="absolute inset-0 rounded-lg border border-neon-cyan"
                      animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0, 0.5] }}
                      transition={{ duration: 1.5, repeat: Infinity }}
                    />
                  )}
                </div>
                
                <div className="flex-1">
                  <span className={`text-xs font-mono font-bold ${
                    isActive ? 'text-neon-cyan' : isComplete ? 'text-contain-green' : 'text-data-white/40'
                  }`}>
                    {node.label}
                  </span>
                  {isActive && (
                    <motion.div
                      initial={{ opacity: 0, y: 5 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="text-[10px] font-mono text-data-white/40 mt-0.5"
                    >
                      Processing...
                    </motion.div>
                  )}
                  {isComplete && node.id === 'response' && lastThreat && (
                    <div className="text-[10px] font-mono text-contain-green mt-0.5">
                      {lastThreat.action === 'PENDING' ? 'AWAITING APPROVAL' : 'CONTAINED'}
                    </div>
                  )}
                </div>
                
                {isComplete && (
                  <ShieldCheck size={14} className="text-contain-green" />
                )}
                {isActive && (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-3 h-3 border-2 border-neon-cyan border-t-transparent rounded-full"
                  />
                )}
              </motion.div>
            </div>
          )
        })}
        
        {/* Data packet animation */}
        {isProcessing && activeNode !== null && activeNode < CHAIN_NODES.length - 1 && (
          <motion.div
            className="absolute left-[22px] w-3 h-3 rounded-full bg-neon-cyan shadow-[0_0_10px_rgba(0,240,255,0.5)]"
            initial={{ top: `${activeNode * 68 + 30}px` }}
            animate={{ top: `${(activeNode + 1) * 68 + 30}px` }}
            transition={{ duration: 0.8, ease: "easeInOut" }}
          />
        )}
      </div>
      
      {/* Status */}
      <div className="mt-3 pt-2 border-t border-panel-border">
        <div className="flex items-center justify-between text-[10px] font-mono">
          <span className="text-data-white/30">STATUS</span>
          <span className={isProcessing ? 'text-neon-cyan' : 'text-contain-green'}>
            {isProcessing ? 'PROCESSING...' : 'IDLE'}
          </span>
        </div>
      </div>
    </div>
  )
}

export default KillChain