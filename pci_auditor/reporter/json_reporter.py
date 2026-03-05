"""JSON reporter: outputs findings as a machine-readable JSON file."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from pci_auditor.models import ScanResult


def write_json(
    result: ScanResult,
    output_file: Optional[str] = None,
) -> None:
    """Write scan results as JSON.

    Args:
        result: The scan result to serialise.
        output_file: Path to write to. If None, writes to stdout.
    """
    payload = {
        "summary": {
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "scanned_files": result.scanned_files,
            "scanned_lines": result.scanned_lines,
        },
        "findings": [f.as_dict() for f in result.findings],
        "errors": result.errors,
    }

    json_str = json.dumps(payload, indent=2)

    if output_file:
        Path(output_file).write_text(json_str, encoding="utf-8")
    else:
        print(json_str)
