import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const BOOT_LINES = [
  { text: 'PhantomAgent Kernel v1.0.0 initialized', status: 'OK' },
  { text: 'Security modules loaded', status: 'OK' },
  { text: 'Waiting for operator authentication...', status: 'WAIT' },
]

const MatrixRain = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-10">
    {[...Array(25)].map((_, i) => (
      <motion.div
        key={i}
        className="absolute font-mono text-xs text-contain-green"
        style={{ left: `${i * 4}%`, top: -50 }}
        animate={{ top: ['-10%', '110%'] }}
        transition={{
          duration: 10 + Math.random() * 20,
          repeat: Infinity,
          delay: Math.random() * 10,
          ease: "linear"
        }}
      >
        {Array.from({ length: 30 }, () =>
          Math.random() > 0.5 ? '1' : Math.random() > 0.5 ? '0' : ['A', 'B', 'C', 'D', 'E', 'F'][Math.floor(Math.random() * 6)]
        ).join('')}
      </motion.div>
    ))}
  </div>
)

const CRTScanlines = () => (
  <div className="absolute inset-0 pointer-events-none opacity-20" style={{
    background: 'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%)',
    backgroundSize: '100% 4px'
  }} />
)

const LoginPage = ({ onLogin }) => {
  const [bootComplete, setBootComplete] = useState(false)
  const [bootIndex, setBootIndex] = useState(0)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const usernameRef = useRef(null)
  const passwordRef = useRef(null)
  const [activeField, setActiveField] = useState('username')

  useEffect(() => {
    if (bootIndex < BOOT_LINES.length) {
      const timer = setTimeout(() => {
        setBootIndex(prev => prev + 1)
      }, 200 + Math.random() * 200)
      return () => clearTimeout(timer)
    } else {
      const timer = setTimeout(() => setBootComplete(true), 300)
      return () => clearTimeout(timer)
    }
  }, [bootIndex])

  // Only focus username on boot complete, never auto-focus password
  useEffect(() => {
    if (bootComplete && activeField === 'username' && usernameRef.current) {
      usernameRef.current.focus()
    }
  }, [bootComplete, activeField])

  const handleUsernameKeyDown = (e) => {
    if (e.key === 'Tab' || e.key === 'Enter') {
      e.preventDefault()
      setActiveField('password')
      setTimeout(() => {
        if (passwordRef.current) passwordRef.current.focus()
      }, 10)
    }
  }

  const handlePasswordKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      setActiveField('username')
      setTimeout(() => {
        if (usernameRef.current) usernameRef.current.focus()
      }, 10)
    }
    if (e.key === 'Enter' && username && password) {
      handleSubmit(e)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!username || !password) {
      setError('Credentials required')
      return
    }

    setIsLoading(true)
    await new Promise(resolve => setTimeout(resolve, 1200))

    if (username === 'admin' && password === 'phantom') {
      onLogin()
    } else {
      setError('Access denied')
      setIsLoading(false)
    }
  }

  // Autofill hack: hide browser autofill background
  const autofillHack = {
    WebkitBoxShadow: '0 0 0 1000px #0d0d0d inset !important',
    WebkitTextFillColor: '#33ff33 !important',
    caretColor: '#33ff33',
    transition: 'background-color 5000s ease-in-out 0s',
  }

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-[#0a0f0a] font-mono">
      <MatrixRain />
      <CRTScanlines />

      <div className="absolute inset-0 bg-radial-gradient pointer-events-none" style={{
        background: 'radial-gradient(ellipse at center, rgba(51,255,51,0.03) 0%, transparent 70%)'
      }} />

      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 w-full max-w-2xl px-4"
      >
        {/* Prominent PhantomAgent Logo & Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-[#33ff33]/10 border border-[#33ff33]/30 mb-3 shadow-[0_0_20px_rgba(51,255,51,0.15)]">
            <div className="w-2 h-2 rounded-full bg-[#33ff33] animate-ping" />
            <span className="text-[11px] font-mono text-[#33ff33] font-bold tracking-widest uppercase">AUTONOMOUS CYBER DEFENSE SYSTEM</span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-black tracking-widest flex items-center justify-center gap-3">
            <span className="text-[#33ff33] drop-shadow-[0_0_25px_rgba(51,255,51,0.6)] font-mono">PHANTOM</span>
            <span className="text-data-white font-mono drop-shadow-[0_0_20px_rgba(255,255,255,0.3)]">AGENT</span>
          </h1>
          <p className="text-xs font-mono text-[#33ff33]/50 mt-1.5 tracking-wider">
            GNN EYES + GEMMA LLM BRAIN · ACTIVE THREAT CONTAINMENT
          </p>
        </div>

        <div className="bg-[#1a1a1a] border border-[#33ff33]/20 rounded-t-lg px-4 py-2 flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-[#ff5f56]" />
          <div className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
          <div className="w-3 h-3 rounded-full bg-[#27ca40]" />
          <span className="ml-2 text-[10px] text-[#33ff33]/40 font-mono">phantomagent@secure — bash — 80x24</span>
        </div>

        <div className="bg-[#0d0d0d] border border-t-0 border-[#33ff33]/20 rounded-b-lg p-6 min-h-[320px] shadow-[0_0_40px_rgba(51,255,51,0.05)]">

          <AnimatePresence>
            {!bootComplete && (
              <div className="space-y-1">
                {BOOT_LINES.slice(0, bootIndex).map((line, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="text-xs font-mono"
                  >
                    <span className="text-[#33ff33]/60">[{new Date().toLocaleTimeString()}]</span>
                    {' '}
                    <span className="text-[#33ff33]/80">{line.text}</span>
                    {' '}
                    <span className={line.status === 'OK' ? 'text-contain-green' : 'text-warning-amber'}>
                      [{line.status}]
                    </span>
                  </motion.div>
                ))}
                {bootIndex < BOOT_LINES.length && (
                  <motion.span
                    animate={{ opacity: [1, 0] }}
                    transition={{ duration: 0.5, repeat: Infinity }}
                    className="inline-block w-2 h-4 bg-[#33ff33] ml-1"
                  />
                )}
              </div>
            )}
          </AnimatePresence>

          <AnimatePresence>
            {bootComplete && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
                className="space-y-4"
              >
                <div className="text-[#33ff33]/60 text-xs mb-6">
                  <div>PhantomAgent Security Console v1.0.0-BETA</div>
                  <div>Secure connection established. Waiting for authentication.</div>
                </div>

                <form onSubmit={handleSubmit} className="space-y-3" autoComplete="off">
                  {/* Username line */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[#33ff33] text-sm whitespace-nowrap">phantomagent@secure:~$</span>
                    <span className="text-[#33ff33]/60 text-sm whitespace-nowrap">login</span>
                    <input
                      ref={usernameRef}
                      type="text"
                      name="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      onKeyDown={handleUsernameKeyDown}
                      onFocus={() => setActiveField('username')}
                      className="bg-transparent border-none outline-none text-[#33ff33] text-sm font-mono w-48 focus:ring-0 placeholder-[#33ff33]/20"
                      placeholder="username"
                      disabled={isLoading}
                      autoFocus
                      autoComplete="off"
                      style={autofillHack}
                    />
                  </div>

                  {/* Password line — NO autoFocus, controlled by activeField */}
                  <div className={`flex items-center gap-2 flex-wrap transition-opacity duration-300 ${username.length > 0 ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
                    <span className="text-[#33ff33] text-sm whitespace-nowrap">phantomagent@secure:~$</span>
                    <span className="text-[#33ff33]/60 text-sm whitespace-nowrap">password</span>
                    <input
                      ref={passwordRef}
                      type="password"
                      name="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={handlePasswordKeyDown}
                      onFocus={() => setActiveField('password')}
                      className="bg-transparent border-none outline-none text-[#33ff33] text-sm font-mono w-48 focus:ring-0 placeholder-[#33ff33]/20"
                      placeholder="••••••"
                      disabled={isLoading}
                      autoComplete="off"
                      style={autofillHack}
                    />
                  </div>

                  {/* Submit line */}
                  <div className={`flex items-center gap-2 transition-opacity duration-300 ${username.length > 0 && password.length > 0 ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
                    <span className="text-[#33ff33] text-sm whitespace-nowrap">phantomagent@secure:~$</span>
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="text-[#33ff33] text-sm font-mono hover:text-[#33ff33]/80 transition-colors disabled:opacity-50 bg-transparent border-none cursor-pointer"
                    >
                      {isLoading ? 'AUTHENTICATING...' : 'ACCESS_CONSOLE --auth'}
                    </button>
                    {isLoading && (
                      <motion.span
                        animate={{ opacity: [1, 0] }}
                        transition={{ duration: 0.5, repeat: Infinity }}
                        className="inline-block w-2 h-4 bg-[#33ff33]"
                      />
                    )}
                  </div>

                  {error && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="text-alert-red text-xs font-mono"
                    >
                      Error: {error}
                    </motion.div>
                  )}

                  {isLoading && !error && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="text-contain-green text-xs font-mono mt-2"
                    >
                      [OK] Access granted. Redirecting to dashboard...
                    </motion.div>
                  )}
                </form>

                <div className="mt-8 text-[10px] text-[#33ff33]/30 font-mono">
                  <div>Default credentials: admin / phantom</div>
                  <div>Press Tab to move between fields | Enter to submit</div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  )
}

export default LoginPage