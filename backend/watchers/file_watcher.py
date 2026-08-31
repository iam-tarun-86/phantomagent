"""File system watcher for suspicious file activity"""

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent


class SuspiciousFileHandler(FileSystemEventHandler):
    """Handles file system events"""
    
    SUSPICIOUS_EXTENSIONS = {'.sh', '.py', '.exe', '.bin', '.elf'}
    SUSPICIOUS_PATHS = {tempfile.gettempdir(), '/tmp', '/var/tmp', '/dev/shm'}
    
    def __init__(self, callback: Callable, loop: asyncio.AbstractEventLoop = None):
        self.callback = callback
        self.loop = loop
    
    def _schedule(self, coro):
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, self.loop)
        else:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(coro)
            except RuntimeError:
                pass
    
    def on_created(self, event):
        if event.is_directory:
            return
        self._schedule(self._check_file(event.src_path, "created"))
    
    def on_modified(self, event):
        if event.is_directory:
            return
        self._schedule(self._check_file(event.src_path, "modified"))
    
    async def _check_file(self, path: str, action: str):
        """Check if file is suspicious"""
        file_path = Path(path)
        
        # Check extension
        if file_path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
            # Check if in suspicious path
            resolved_file = file_path.resolve()
            for suspicious in self.SUSPICIOUS_PATHS:
                suspicious_resolved = Path(suspicious).resolve()
                if (
                    str(file_path).lower().startswith(str(suspicious).lower())
                    or str(resolved_file).lower().startswith(str(suspicious_resolved).lower())
                    or (suspicious_resolved.exists() and resolved_file.is_relative_to(suspicious_resolved))
                ):
                    await self.callback({
                        "source": "FILE",
                        "type": "FILE_ANOMALY",
                        "severity": 6,
                        "source_ip": "local",
                        "raw_log": f"Suspicious file {action}: {path}",
                        "timestamp": datetime.now().isoformat(),
                        "message": f"Suspicious executable {action} in {suspicious}: {file_path.name}"
                    })
                    return


class FileWatcher:
    """Watches file system for anomalies"""
    
    def __init__(self, paths: list, callback: Callable):
        self.paths = paths
        self.callback = callback
        self.observer = Observer()
        self.running = False
    
    def start(self):
        """Start file watching"""
        self.running = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        handler = SuspiciousFileHandler(self.callback, loop=loop)
        
        for path in self.paths:
            if Path(path).exists():
                self.observer.schedule(handler, path, recursive=True)
                print(f"[FILE] Watching: {path}")
        
        self.observer.start()
        print("[FILE] File watcher started")
    
    def stop(self):
        """Stop file watching"""
        self.running = False
        self.observer.stop()
        self.observer.join()
        print("[FILE] File watcher stopped")