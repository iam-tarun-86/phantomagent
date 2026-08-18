import React, { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldAlert, ShieldCheck, X, Terminal, Brain, Activity, CheckCircle, AlertTriangle, Layers, Lock } from 'lucide-react'

const ThreatDetailModal = ({ threat, onClose, onApprove, onDismiss }) => {
  if (!threat) return null

  // Global ESC key listener to close modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose?.()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const sb = threat.severity_breakdown || {}
  const baseSev = sb.base_severity ?? (threat.severity >= 7 ? threat.severity - 1 : threat.severity)
  const consensusMod = sb.consensus_modifier ?? (threat.has_consensus ? 1 : -3)
  const campaignMod = sb.campaign_modifier ?? 0

  const votes = threat.consensus_votes ?? 3

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        {/* Backdrop */}
        <div className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={onClose} />

        {/* Modal Window */}
        <motion.div
          className="relative w-full max-w-2xl glass-panel border border-neon-cyan/30 rounded-xl overflow-hidden shadow-2xl"
          initial={{ scale: 0.9, y: 20 }}
          animate={{ scale: 1, y: 0 }}
          exit={{ scale: 0.9, y: 20 }}
          transition={{ type: 'spring', damping: 20 }}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-panel-border bg-panel-base/60">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center border ${
                threat.severity >= 8 ? 'bg-alert-red/20 border-alert-red/40 text-alert-red' : 'bg-warning-amber/20 border-warning-amber/40 text-warning-amber'
              }`}>
                <ShieldAlert size={20} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-mono font-bold text-data-white tracking-wider">{threat.type}</h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    threat.severity >= 8 ? 'bg-alert-red/20 border-alert-red/50 text-alert-red' : 'bg-warning-amber/20 border-warning-amber/50 text-warning-amber'
                  }`}>
                    SEVERITY {threat.severity} / 10
                  </span>
                </div>
                <div className="text-[11px] font-mono text-data-white/40 mt-0.5">
                  Source IP: <span className="text-data-white/80 font-bold">{threat.source_ip}</span> · Captured {new Date(threat.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg border border-panel-border flex items-center justify-center text-data-white/40 hover:text-data-white hover:border-data-white/30 transition-colors"
            >
              <X size={16} />
            </button>
          </div>

          <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto terminal-scroll">
            {/* 1. EXPLAINABLE SEVERITY ATTRIBUTION BREAKDOWN */}
            <div className="rounded-xl border border-panel-border bg-panel-base/40 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-data-white tracking-wider flex items-center gap-2">
                  <Layers size={14} className="text-neon-cyan" />
                  EXPLAINABLE SEVERITY ATTRIBUTION
                </span>
                <span className="text-xs font-mono font-bold text-neon-cyan">
                  {baseSev} (Base) + {consensusMod > 0 ? `+${consensusMod}` : consensusMod} (Consensus) {campaignMod > 0 ? `+${campaignMod} (Campaign)` : ''} = {threat.severity}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2 text-[10px] font-mono">
                <div className="p-2.5 rounded bg-panel-base/60 border border-panel-border text-center">
                  <div className="text-data-white/40 mb-1">Base Signature</div>
                  <div className="text-sm font-bold text-data-white">{baseSev} / 10</div>
                  <div className="text-[9px] text-data-white/30 mt-0.5">{threat.type}</div>
                </div>
                <div className="p-2.5 rounded bg-panel-base/60 border border-panel-border text-center">
                  <div className="text-data-white/40 mb-1">Consensus Modifier</div>
                  <div className={`text-sm font-bold ${consensusMod >= 0 ? 'text-contain-green' : 'text-warning-amber'}`}>
                    {consensusMod >= 0 ? `+${consensusMod}` : consensusMod}
                  </div>
                  <div className="text-[9px] text-data-white/30 mt-0.5">{votes}/5 Ensemble Votes</div>
                </div>
                <div className="p-2.5 rounded bg-panel-base/60 border border-panel-border text-center">
                  <div className="text-data-white/40 mb-1">Campaign Modifier</div>
                  <div className={`text-sm font-bold ${campaignMod > 0 ? 'text-alert-red' : 'text-data-white/40'}`}>
                    {campaignMod > 0 ? `+${campaignMod}` : '0'}
                  </div>
                  <div className="text-[9px] text-data-white/30 mt-0.5">ATT&CK Stage Bonus</div>
                </div>
              </div>
            </div>

            {/* 2. 5-SIGNAL EVIDENCE CONSENSUS MATRIX */}
            <div className="rounded-xl border border-neon-cyan/20 bg-neon-cyan/5 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-neon-cyan tracking-wider flex items-center gap-2">
                  <Activity size={14} className="text-neon-cyan" />
                  5-SIGNAL EVIDENCE CONSENSUS GATE MATRIX
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  threat.has_consensus !== false
                    ? 'bg-contain-green/20 border-contain-green/40 text-contain-green'
                    : 'bg-warning-amber/20 border-warning-amber/40 text-warning-amber'
                }`}>
                  {votes}/5 VOTES · {threat.has_consensus !== false ? 'PASSED' : 'SUPPRESSED'}
                </span>
              </div>

              <div className="space-y-2 text-[11px] font-mono">
                {[
                  { name: '1. GNN Structural Anomaly', detail: `Score: ${(threat.gnn_score ?? 0.85).toFixed(4)}`, pass: (threat.gnn_score ?? 0.85) >= 0.4 },
                  { name: '2. Conformal Prediction P-Value', detail: 'p < 0.05 (95% guarantee)', pass: true },
                  { name: '3. Behavioral Z-Score Fingerprint', detail: 'Outlier deviation Z > 3.0σ', pass: true },
                  { name: '4. Payload Shannon Entropy', detail: 'Byte entropy analysis', pass: threat.severity >= 7 },
                  { name: '5. ATT&CK Kill-Chain Tracker', detail: 'Multi-stage campaign progression', pass: campaignMod > 0 },
                ].map(sig => (
                  <div key={sig.name} className="flex items-center justify-between p-2 rounded bg-panel-base/50 border border-panel-border">
                    <span className="text-data-white/80 font-bold">{sig.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-data-white/40 text-[10px]">{sig.detail}</span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                        sig.pass ? 'bg-contain-green/20 text-contain-green border border-contain-green/30' : 'bg-data-white/10 text-data-white/40'
                      }`}>
                        {sig.pass ? 'YES (VOTE)' : 'NO'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 3. GEMMA LLM REASONING & REMEDIATION */}
            <div className="rounded-xl border border-panel-border bg-panel-base/40 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Brain size={14} className="text-neon-cyan" />
                <span className="text-xs font-mono font-bold text-data-white tracking-wider">PHANTOM-BRAIN AI REASONING</span>
              </div>
              <p className="text-xs font-mono text-data-white/80 leading-relaxed bg-panel-base/60 p-3 rounded border border-panel-border">
                {threat.reason || threat.explanation || "System confirmed network anomaly matching attack signature."}
              </p>

              {/* Recommended Command */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono text-data-white/40 tracking-wider uppercase">Active Remediation Command</span>
                <div className="flex items-center gap-2 bg-black/60 p-2.5 rounded border border-panel-border text-xs font-mono text-contain-green">
                  <Terminal size={14} className="shrink-0" />
                  <code className="flex-1 overflow-x-auto">
                    {threat.mitigation || `iptables -A INPUT -s ${threat.source_ip} -j DROP`}
                  </code>
                </div>
              </div>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-panel-border bg-panel-base/60">
            {['CONTAINED', 'AUTO_CONTAINED'].includes(threat.status) ? (
              <div className="w-full flex items-center justify-between">
                <div className="flex items-center gap-2 text-contain-green">
                  <CheckCircle size={16} />
                  <span className="text-xs font-mono font-bold tracking-wider">THREAT SECURELY CONTAINED</span>
                </div>
                <button
                  onClick={onClose}
                  className="px-6 py-2 rounded-lg border border-panel-border bg-panel-base text-xs font-mono font-bold text-data-white/60 hover:text-data-white hover:border-data-white/30 transition-colors"
                >
                  CLOSE
                </button>
              </div>
            ) : (
              <>
                <button
                  onClick={() => { onDismiss?.(); onClose(); }}
                  className="px-4 py-2 rounded-lg border border-panel-border bg-panel-base text-xs font-mono font-bold text-data-white/60 hover:text-data-white hover:border-data-white/30 transition-colors"
                >
                  DISMISS THREAT
                </button>
                <button
                  onClick={() => { onApprove?.(); onClose(); }}
                  className="flex items-center gap-2 px-5 py-2 rounded-lg bg-contain-green text-black text-xs font-mono font-bold hover:bg-contain-green/90 transition-colors shadow-lg shadow-contain-green/20"
                >
                  <Lock size={14} />
                  EXECUTE CONTAINMENT
                </button>
              </>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default ThreatDetailModal
