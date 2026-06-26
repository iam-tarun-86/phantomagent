"""Threat data models"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
import json
import uuid


class ThreatType(Enum):
    BRUTE_FORCE = "Brute Force"
    PORT_SCAN = "Port Scan"
    FILE_ANOMALY = "File Anomaly"
    DNS_TUNNELING = "DNS Tunneling"
    SUSPICIOUS_LOGIN = "Suspicious Login"
    MALWARE = "Malware"
    UNKNOWN = "Unknown"


class ThreatStatus(Enum):
    DETECTED = "DETECTED"
    PREFILTERED = "PREFILTERED"
    ANALYZING = "ANALYZING"
    PENDING = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CONTAINED = "CONTAINED"
    AUTO_CONTAINED = "AUTO_CONTAINED"
    LOGGED = "LOGGED"


@dataclass
class Threat:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    type: ThreatType = ThreatType.UNKNOWN
    severity: int = 1
    source_ip: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.now)
    raw_log: str = ""
    status: ThreatStatus = ThreatStatus.DETECTED
    attack_pattern: Optional[str] = None
    explanation: Optional[str] = None
    action_taken: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "attack_pattern": self.attack_pattern,
            "explanation": self.explanation,
            "action_taken": self.action_taken,
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)