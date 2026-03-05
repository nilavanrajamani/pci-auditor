"""Core data models shared across all modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    rule_id: str          # e.g. "3.3.1"
    severity: str         # critical | high | medium | low | info
    file_path: str
    line_number: int
    column: int = 0
    description: str = ""
    recommendation: str = ""
    snippet: str = ""
    source: str = "pattern"   # pattern | ai

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "description": self.description,
            "recommendation": self.recommendation,
            "snippet": self.snippet,
            "source": self.source,
        }


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_lines: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "low")
