import React, { useState, useEffect } from 'react'
import AuthorityBar from './components/AuthorityBar'
import ThreatFeed from './components/ThreatFeed'
import AttackMap from './components/AttackMap'
import KillChain from './components/KillChain'
import TerminalStream from './components/TerminalStream'
import RedAlertModal from './components/RedAlertModal'

function App() {
  const [showAlert, setShowAlert] = useState(false)
  const [currentThreat, setCurrentThreat] = useState(null)

  // Demo mode: Press 'D' to instantly trigger RED ALERT
  useEffect(() => {
    const handleKeyPress = (e) => {
      if (e.key === 'd' || e.key === 'D') {
        if (!showAlert) {
          const threat = {
            type: ['Brute Force', 'Port Scan', 'Ransomware', 'DNS Tunneling'][Math.floor(Math.random() * 4)],
            severity: 10,
            sourceIP: `185.220.101.${Math.floor(Math.random() * 255)}`,
            timestamp: new Date().toLocaleTimeString()
          }
          setCurrentThreat(threat)
          setShowAlert(true)
        }
      }
    }

    window.addEventListener('keydown', handleKeyPress)
    return () => window.removeEventListener('keydown', handleKeyPress)
  }, [showAlert])

  const handleApprove = () => {
    setShowAlert(false)
    setCurrentThreat(null)
  }

  const handleDismiss = () => {
    setShowAlert(false)
    setCurrentThreat(null)
  }

  return (
    <div className="min-h-screen bg-deep-space text-data-white font-sans grid-bg-animated">
      {/* Scan line effect */}
      <div className="scan-line" />

      <AuthorityBar />

      {/* Spacer for fixed header */}
      <div className="h-16" />

      {/* Main Dashboard Grid */}
      <div className="px-4 py-4 h-[calc(100vh-4rem)] flex flex-col gap-4">
        {/* Top Row */}
        <div className="flex-1 flex gap-4 min-h-0">
          <div className="w-[25%] min-w-[280px]">
            <ThreatFeed />
          </div>
          <div className="flex-1 min-w-0">
            <AttackMap />
          </div>
          <div className="w-[20%] min-w-[220px]">
            <KillChain />
          </div>
        </div>

        {/* Bottom Row */}
        <div className="h-[22%] min-h-[180px]">
          <TerminalStream />
        </div>
      </div>

      {/* RED ALERT MODAL */}
      <RedAlertModal
        isOpen={showAlert}
        threat={currentThreat}
        onApprove={handleApprove}
        onDismiss={handleDismiss}
      />
    </div>
  )
}

export default App