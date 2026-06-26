"""File system watcher for suspicious file activity"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent


class SuspiciousFileHandler(FileSystemEventHandler):
    """Handles file system events"""
    
    SUSPICIOUS_EXTENSIONS = {'.sh', '.py', '.exe', '.bin', '.elf'}
    SUSPICIOUS_PATHS = {'/tmp', '/var/tmp', '/dev/shm'}
    
    def __init__(self, callback: Callable):
        self.callback = callback
    
    def on_created(self, event):
        if event.is_directory:
            return
        asyncio.create_task(self._check_file(event.src_path, "created"))
    
    def on_modified(self, event):
        if event.is_directory:
            return
        asyncio.create_task(self._check_file(event.src_path, "modified"))
    
    async def _check_file(self, path: str, action: str):
        """Check if file is suspicious"""
        file_path = Path(path)
        
        # Check extension
        if file_path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
            # Check if in suspicious path
            for suspicious in self.SUSPICIOUS_PATHS:
                if str(file_path).startswith(suspicious):
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
        handler = SuspiciousFileHandler(self.callback)
        
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