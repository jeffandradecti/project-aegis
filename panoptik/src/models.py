import os
from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class FileArtifact:
    """Represents the raw file being analyzed."""
    name: str
    path: str
    data: bytes
    size: int

    @classmethod
    def from_path(cls, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} not found.")
        with open(file_path, "rb") as f:
            data = f.read()
        return cls(
            name=os.path.basename(file_path),
            path=os.path.abspath(file_path),
            data=data,
            size=len(data)
        )


@dataclass
class AnalysisReport:
    """The central ledger for all analysis results."""
    file_info: Dict[str, Any] = field(default_factory=dict)
    hashes: Dict[str, str] = field(default_factory=dict)
    risk_score: int = 0
    heuristics: List[str] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=lambda: {
        "ips": [],
        "urls": [],
        "emails": [],
        "decoded_payloads": []
    })
    structure_info: Dict[str, Any] = field(default_factory=dict)
    strings: List[str] = field(default_factory=list)

    def add_risk(self, points: int, reason: str):
        """Helper to safely increment risk score."""
        self.risk_score += points
        self.heuristics.append(reason)

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            "file_info": self.file_info,
            "hashes": self.hashes,
            "risk_score": self.risk_score,
            "heuristics": self.heuristics,
            "iocs": self.iocs,
            "structure_info": self.structure_info,
            "strings": self.strings
        }
