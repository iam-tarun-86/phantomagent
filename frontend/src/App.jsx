import React, { useState } from 'react'
import { useDashboard } from './context/DashboardContext.jsx'
import LoginPage from './components/LoginPage'
import AuthorityBar from './components/AuthorityBar'
import ThreatFeed from './components/ThreatFeed'
import AttackMap from './components/AttackMap'
import KillChain from './components/KillChain'
import TerminalStream from './components/TerminalStream'
import LiveConnections from './components/LiveConnections'
import RedAlertModal from './components/RedAlertModal'
import ThreatDetailModal from './components/ThreatDetailModal'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [selectedThreat, setSelectedThreat] = useState(null)
  const { alert, approveThreat, dismissThreat, isConnected } = useDashboard()

  if (!isAuthenticated) {
    return <LoginPage onLogin={() => setIsAuthenticated(true)} />
  }

  return (
    <div className="min-h-screen bg-deep-space text-data-white font-sans grid-bg-animated">
      {!isConnected && (
        <div className="fixed top-20 left-1/2 -translate-x-1/2 z-50 px-4 py-2 bg-warning-amber/20 border border-warning-amber/50 rounded-lg">
          <span className="text-xs font-mono text-warning-amber">⚠ RECONNECTING...</span>
        </div>
      )}

      <div className="scan-line" />
      <AuthorityBar />
      <div className="h-16" />

      <div className="px-4 py-4 h-[calc(100vh-4rem)] flex flex-col gap-4">
        <div className="flex-1 flex gap-4 min-h-0">
          <div className="w-[22%] min-w-[260px]">
            <ThreatFeed onSelectThreat={(threat) => setSelectedThreat(threat)} />
          </div>
          <div className="flex-1 min-w-0"><AttackMap /></div>
          <div className="w-[18%] min-w-[200px] flex flex-col gap-3">
            <KillChain />
            <LiveConnections />
          </div>
        </div>
        <div className="h-[22%] min-h-[180px]"><TerminalStream /></div>
      </div>

      {/* Red Alert Modal for Critical Approval */}
      <RedAlertModal
        isOpen={!!alert}
        threat={alert}
        onApprove={() => alert && approveThreat(alert.threat_id)}
        onDismiss={() => alert && dismissThreat(alert.threat_id)}
      />

      {/* Interactive Threat Detail & Evidence Inspector Modal */}
      {selectedThreat && (
        <ThreatDetailModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onApprove={() => selectedThreat && approveThreat(selectedThreat.id)}
          onDismiss={() => selectedThreat && dismissThreat(selectedThreat.id)}
        />
      )}
    </div>
  )
}

export default App