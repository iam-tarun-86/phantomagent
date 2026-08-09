import React, { useRef, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal, Maximize2, Trash2 } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import FullscreenLogViewer from './FullscreenLogViewer'

// Typewriter hook inline (or import from hooks/useTypewriter.js)
const useTypewriter = (text, speed = 25, startTyping = true) => {
    const [displayedText, setDisplayedText] = React.useState('');
    const [isComplete, setIsComplete] = React.useState(false);

    React.useEffect(() => {
        if (!startTyping || !text) {
            setDisplayedText('');
            setIsComplete(false);
            return;
        }

        setDisplayedText('');
        setIsComplete(false);

        let index = 0;
        const timer = setInterval(() => {
            if (index < text.length) {
                setDisplayedText(text.slice(0, index + 1));
                index++;
            } else {
                setIsComplete(true);
                clearInterval(timer);
            }
        }, speed);

        return () => clearInterval(timer);
    }, [text, speed, startTyping]);

    return { displayedText, isComplete };
};

const LogEntry = ({ log, index }) => {
    const fullText = `[${log.timestamp}] [${log.source}] ${log.message}`;
    const { displayedText, isComplete } = useTypewriter(fullText, 20, true);

    const getLevelColor = (level) => {
        switch (level) {
            case 'CRITICAL': return 'text-alert-red';
            case 'WARN': return 'text-warning-amber';
            case 'INFO': return 'text-neon-cyan';
            default: return 'text-data-white/60';
        }
    };

    return (
        <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
            className="font-mono text-xs mb-1"
        >
            <span className={getLevelColor(log.level)}>
                {displayedText}
                {!isComplete && (
                    <span className="inline-block w-2 h-4 bg-neon-cyan ml-0.5 animate-pulse" />
                )}
            </span>
        </motion.div>
    );
};

const TerminalStream = () => {
    const { logs, clearLogs } = useDashboard()
    const scrollRef = useRef(null)
    const [showFullscreen, setShowFullscreen] = useState(false)

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
    }, [logs])

    return (
        <>
            <div className="h-full flex flex-col glass-panel p-3">
                <div className="flex items-center gap-2 mb-3 px-1">
                    <Terminal size={16} className="text-neon-cyan" />
                    <span className="text-sm font-mono font-bold tracking-wider text-data-white">SYSTEM LOGS</span>
                    <div className="flex-1" />
                    <span className="text-[10px] font-mono text-data-white/30 mr-2">{logs.length} ENTRIES</span>
                    <button
                        onClick={clearLogs}
                        className="p-1.5 rounded hover:bg-panel-border text-data-white/40 hover:text-alert-red transition-colors"
                        title="Clear Logs"
                    >
                        <Trash2 size={14} />
                    </button>
                    <button
                        onClick={() => setShowFullscreen(true)}
                        className="p-1.5 rounded hover:bg-panel-border text-data-white/40 hover:text-neon-cyan transition-colors"
                        title="Toggle Fullscreen"
                    >
                        <Maximize2 size={14} />
                    </button>
                </div>

                <div
                    ref={scrollRef}
                    className="flex-1 overflow-y-auto terminal-scroll pr-2"
                >
                    <AnimatePresence>
                        {logs.map((log, index) => (
                            <LogEntry key={`${log.timestamp}-${index}`} log={log} index={index} />
                        ))}
                    </AnimatePresence>
                </div>
            </div>

            <FullscreenLogViewer
                isOpen={showFullscreen}
                onClose={() => setShowFullscreen(false)}
            />
        </>
    )
}

export default TerminalStream