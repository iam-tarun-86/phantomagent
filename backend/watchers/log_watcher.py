"""Real-time log watcher with SSH brute force detection"""

import asyncio
import re
import tempfile
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
        now = timestamp
        window_start = now - timedelta(seconds=self.window_seconds)

        if ip not in self.attempts:
            self.attempts[ip] = []

        self.attempts[ip] = [t for t in self.attempts[ip] if t > window_start]
        self.attempts[ip].append(now)

        return len(self.attempts[ip]) >= self.threshold

    def cleanup(self):
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds * 2)
        for ip in list(self.attempts.keys()):
            self.attempts[ip] = [t for t in self.attempts[ip] if t > window_start]
            if not self.attempts[ip]:
                del self.attempts[ip]


class LogWatcher:
    """Watches system logs for security events"""

    SSH_FAILED_PATTERN = re.compile(
        r'.*Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+).*'
    )
    SSH_ACCEPTED_PATTERN = re.compile(
        r'.*Accepted .* from (?P<ip>\d+\.\d+\.\d+\.\d+).*'
    )
    SUDO_PATTERN = re.compile(
        r'.*sudo:.*user NOT in sudoers.*'
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
        
        # Create test log file if real logs don't exist
        for path in self.log_paths:
            if Path(path).exists():
                task = asyncio.create_task(self._watch_file(path))
                self.tasks.append(task)
                print(f"[WATCHER] Watching real log: {path}")
            else:
                # Create a test log that we can write to
                test_path = Path(tempfile.gettempdir()) / "phantomagent_test.log"
                test_path.parent.mkdir(parents=True, exist_ok=True)
                if not test_path.exists():
                    test_path.write_text("# PhantomAgent test log\n")
                print(f"[WATCHER] Real log not found at {path}, using test log: {test_path}")
                task = asyncio.create_task(self._watch_file(str(test_path)))
                self.tasks.append(task)

    async def _watch_file(self, path: str):
        """Watch a single log file"""
        try:
            async with aiofiles.open(path, 'r') as f:
                await f.seek(0, 2)  # Seek to end

                while self.running:
                    line = await f.readline()
                    if line:
                        await self._process_line(path, line.strip())
                    else:
                        await asyncio.sleep(0.1)
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
                await self.callback({
                    "source": "WATCHER",
                    "type": "BRUTE_FORCE",
                    "severity": 9,
                    "source_ip": ip,
                    "raw_log": line,
                    "timestamp": timestamp.isoformat(),
                    "message": f"SSH brute force detected from {ip}"
                })
            else:
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

    async def stop(self):
        """Stop all watchers"""
        self.running = False
        for task in self.tasks:
            task.cancel()
        self.tasks.clear()
        print("[WATCHER] Stopped all log watchers")