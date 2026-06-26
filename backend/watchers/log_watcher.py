"""Real-time log watcher with SSH brute force detection"""

import asyncio
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List
import aiofiles


class SSHBruteForceDetector:
    """Detects SSH brute force attempts"""
    
    def __init__(self, window_seconds=10, threshold=5):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.attempts: Dict[str, List[datetime]] = {}
    
    def check(self, ip: str, timestamp: datetime) -> bool:
        """Returns True if IP exceeds threshold in window"""
        now = timestamp
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Get attempts in window
        if ip not in self.attempts:
            self.attempts[ip] = []
        
        self.attempts[ip] = [t for t in self.attempts[ip] if t > window_start]
        self.attempts[ip].append(now)
        
        return len(self.attempts[ip]) >= self.threshold
    
    def cleanup(self):
        """Remove old entries"""
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds * 2)
        for ip in list(self.attempts.keys()):
            self.attempts[ip] = [t for t in self.attempts[ip] if t > window_start]
            if not self.attempts[ip]:
                del self.attempts[ip]


class LogWatcher:
    """Watches system logs for security events"""
    
    # Regex patterns for log parsing
    SSH_FAILED_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    SSH_ACCEPTED_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    SUDO_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*user NOT in sudoers'
    )
    
    def __init__(self, log_paths: List[str], callback: Callable):
        self.log_paths = log_paths
        self.callback = callback
        self.brute_detector = SSHBruteForceDetector()
        self.running = False
        self.tasks = []
    
    async def start(self):
        """Start watching all log files"""
        self.running = True
        for path in self.log_paths:
            if Path(path).exists():
                task = asyncio.create_task(self._watch_file(path))
                self.tasks.append(task)
                print(f"[WATCHER] Started watching: {path}")
            else:
                print(f"[WATCHER] Log file not found: {path}")
                # Create fake log for demo
                await self._generate_demo_logs(path)
    
    async def _watch_file(self, path: str):
        """Watch a single log file using tail -f equivalent"""
        try:
            # Open file and seek to end
            async with aiofiles.open(path, 'r') as f:
                await f.seek(0, 2)  # Seek to end
                
                while self.running:
                    line = await f.readline()
                    if line:
                        await self._process_line(path, line.strip())
                    else:
                        await asyncio.sleep(0.1)  # No new data, wait
        except Exception as e:
            print(f"[WATCHER] Error watching {path}: {e}")
    
    async def _process_line(self, path: str, line: str):
        """Process a single log line"""
        # Check SSH failed login
        match = self.SSH_FAILED_PATTERN.match(line)
        if match:
            ip = match.group('ip')
            timestamp = datetime.now()
            
            if self.brute_detector.check(ip, timestamp):
                # Brute force detected!
                await self.callback({
                    "source": "WATCHER",
                    "type": "BRUTE_FORCE",
                    "severity": 9,
                    "source_ip": ip,
                    "raw_log": line,
                    "timestamp": timestamp.isoformat(),
                    "message": f"SSH brute force detected from {ip} ({self.brute_detector.attempts[ip]} attempts)"
                })
            else:
                # Single failed attempt
                await self.callback({
                    "source": "WATCHER",
                    "type": "SUSPICIOUS_LOGIN",
                    "severity": 4,
                    "source_ip": ip,
                    "raw_log": line,
                    "timestamp": datetime.now().isoformat(),
                    "message": f"Failed SSH login from {ip}"
                })
        
        # Check sudo failure
        elif self.SUDO_PATTERN.search(line):
            await self.callback({
                "source": "WATCHER",
                "type": "SUSPICIOUS_LOGIN",
                "severity": 6,
                "source_ip": "local",
                "raw_log": line,
                "timestamp": datetime.now().isoformat(),
                "message": "Unauthorized sudo attempt detected"
            })
    
    async def _generate_demo_logs(self, path: str):
        """Generate fake log entries for demo"""
        print(f"[WATCHER] Demo mode: Generating fake logs for {path}")
        
        # Create fake log file
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        while self.running:
            await asyncio.sleep(5)
            
            # Generate fake SSH brute force every 20-40 seconds
            if asyncio.get_event_loop().time() % 30 < 1:
                ip = f"185.220.101.{asyncio.get_event_loop().time() % 255:.0f}"
                await self.callback({
                    "source": "WATCHER",
                    "type": "BRUTE_FORCE",
                    "severity": 9,
                    "source_ip": ip,
                    "raw_log": f"Failed password for root from {ip} port 22",
                    "timestamp": datetime.now().isoformat(),
                    "message": f"SSH brute force detected from {ip}"
                })
    
    async def stop(self):
        """Stop all watchers"""
        self.running = False
        for task in self.tasks:
            task.cancel()
        self.tasks.clear()
        print("[WATCHER] Stopped all log watchers")