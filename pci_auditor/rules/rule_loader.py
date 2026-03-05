"""Load PCI DSS rules from the local JSON cache."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


_BUNDLED_RULES_PATH = Path(__file__).parent / "pci_rules.json"
_USER_CACHE_PATH = Path.home() / ".pci-auditor" / "pci_rules.json"


@dataclass
class PciRule:
    id: str
    requirement: str
    severity: str
    category: str
    code_indicators: List[str] = field(default_factory=list)
    ai_prompt_hint: str = ""

    @staticmethod
    def from_dict(data: dict) -> "PciRule":
        return PciRule(
            id=data["id"],
            requirement=data["requirement"],
            severity=data.get("severity", "Medium"),
            category=data.get("category", ""),
            code_indicators=data.get("code_indicators", []),
            ai_prompt_hint=data.get("ai_prompt_hint", ""),
        )


def load_rules(severity_filter: Optional[List[str]] = None) -> List[PciRule]:
    """Load rules from cache (user override) or bundled file.

    Args:
        severity_filter: Optional list of severities to include (e.g. ['critical','high']).
                         If None all rules are returned.
    """
    rules_path = _USER_CACHE_PATH if _USER_CACHE_PATH.exists() else _BUNDLED_RULES_PATH

    with rules_path.open(encoding="utf-8") as f:
        data = json.load(f)

    rules = [PciRule.from_dict(r) for r in data.get("rules", [])]

    if severity_filter:
        lower_filter = {s.lower() for s in severity_filter}
        rules = [r for r in rules if r.severity.lower() in lower_filter]

    return rules


def get_rules_metadata() -> dict:
    """Return version/source metadata from the active rules file."""
    rules_path = _USER_CACHE_PATH if _USER_CACHE_PATH.exists() else _BUNDLED_RULES_PATH
    with rules_path.open(encoding="utf-8") as f:
        data = json.load(f)
    return {
        "pci_dss_version": data.get("pci_dss_version", "unknown"),
        "last_updated": data.get("last_updated", "unknown"),
        "source": data.get("source", "unknown"),
        "rule_count": len(data.get("rules", [])),
        "path": str(rules_path),
    }
