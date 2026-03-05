"""SARIF 2.1.0 reporter for GitHub Advanced Security / Azure DevOps integration.

GitHub-specific requirements met by this implementation:
- File URIs are relative to the repository root (%SRCROOT%) so GitHub can map
  findings to exact file/line positions and show inline PR annotations.
- ``security-severity`` property (0-10 CVSS-like score) is set so GitHub
  categorises alerts correctly in the Security tab.
- ``helpUri`` links each rule to the relevant PCI DSS documentation.
- Message text is clean prose — no internal prefixes or pipe-delimited fields.
- ``fix`` message field carries the remediation guidance separately.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from pci_auditor.models import Finding, ScanResult
from pci_auditor import __version__

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# SARIF level — GitHub shows 'error' as red, 'warning' as yellow, 'note' as blue
_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

# GitHub Advanced Security uses security-severity (0-10) to triage alerts.
# These values align roughly with CVSS base scores for code-level findings.
_SECURITY_SEVERITY_MAP = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

# PCI DSS 4.0 online reference — used as helpUri in rule metadata
_PCI_HELP_BASE = "https://www.pcisecuritystandards.org/document_library/"


def _resolve_repo_root() -> Optional[Path]:
    """Return the repo root to relativise file URIs against.

    Priority:
    1. GITHUB_WORKSPACE env var (set automatically in GitHub Actions)
    2. Current working directory (works for most local and CI runs)
    """
    gw = os.environ.get("GITHUB_WORKSPACE")
    if gw:
        return Path(gw).resolve()
    return Path.cwd().resolve()


def _relative_uri(file_path: str, repo_root: Optional[Path]) -> str:
    """Return a forward-slash URI relative to *repo_root*.

    GitHub maps SARIF findings to repository files using this relative path.
    If relativisation fails (e.g. different drive on Windows) the absolute
    path is returned as a fallback — findings will still appear but without
    inline PR annotations.
    """
    root = repo_root or _resolve_repo_root()
    try:
        rel = Path(file_path).resolve().relative_to(root)
        return str(rel).replace("\\", "/")
    except ValueError:
        # Fallback: absolute path (annotations won't work but data is preserved)
        return Path(file_path).as_posix()


def _clean_description(description: str, rule_id: str) -> str:
    """Strip internal boilerplate prefix added by the pattern scanner."""
    prefix = f"[Rule {rule_id}]"
    if description.startswith(prefix):
        description = description[len(prefix):].strip()
    return description


def write_sarif(
    result: ScanResult,
    output_file: Optional[str] = None,
    rules_metadata: Optional[dict] = None,
    repo_root: Optional[Path] = None,
) -> None:
    """Write scan results as SARIF 2.1.0.

    Args:
        result: The scan result to serialise.
        output_file: Path to write to.  If None, writes to stdout.
        rules_metadata: Optional dict with pci_dss_version, last_updated, etc.
        repo_root: Absolute path to the repository root used to make file URIs
            relative.  Defaults to GITHUB_WORKSPACE env var or cwd.
    """
    sarif_doc = _build_sarif(result, rules_metadata or {}, repo_root)
    json_str = json.dumps(sarif_doc, indent=2)

    if output_file:
        Path(output_file).write_text(json_str, encoding="utf-8")
    else:
        print(json_str)


def _build_sarif(result: ScanResult, metadata: dict, repo_root: Optional[Path]) -> dict:
    rules = _collect_rules(result.findings)

    tool = {
        "driver": {
            "name": "pci-auditor",
            "version": __version__,
            "informationUri": "https://github.com/pci-auditor/pci-auditor",
            "organization": "PCI Auditor",
            "shortDescription": {
                "text": f"PCI DSS {metadata.get('pci_dss_version', '4.0.1')} Compliance Auditor"
            },
            "rules": rules,
        }
    }

    run = {
        "tool": tool,
        "originalUriBaseIds": {
            "%SRCROOT%": {"uri": "./"}
        },
        "results": [_finding_to_result(f, repo_root) for f in result.findings],
        "properties": {
            "scanned_files": result.scanned_files,
            "scanned_lines": result.scanned_lines,
            "pci_dss_version": metadata.get("pci_dss_version", "4.0.1"),
            "rules_last_updated": metadata.get("last_updated", "unknown"),
        },
    }

    if result.errors:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"message": {"text": err}, "level": "warning"}
                    for err in result.errors
                ],
            }
        ]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }


def _collect_rules(findings: List[Finding]) -> List[dict]:
    """Produce the tool.driver.rules array — one entry per unique rule ID."""
    seen: dict = {}
    for f in findings:
        if f.rule_id not in seen:
            clean_desc = _clean_description(
                f.description or f"PCI DSS 4.0 Rule {f.rule_id}", f.rule_id
            )
            seen[f.rule_id] = {
                "id": f"PCI-DSS-{f.rule_id}",
                "name": f"PciDss{f.rule_id.replace('.', '')}",
                "shortDescription": {"text": f"PCI DSS 4.0 — Rule {f.rule_id}"},
                "fullDescription": {"text": clean_desc},
                "helpUri": _PCI_HELP_BASE,
                "defaultConfiguration": {
                    "level": _LEVEL_MAP.get(f.severity.lower(), "warning")
                },
                "properties": {
                    "tags": ["security", "pci-dss"],
                    "security-severity": str(
                        _SECURITY_SEVERITY_MAP.get(f.severity.lower(), 5.0)
                    ),
                },
            }
    return list(seen.values())


def _finding_to_result(finding: Finding, repo_root: Optional[Path]) -> dict:
    level = _LEVEL_MAP.get(finding.severity.lower(), "warning")
    clean_desc = _clean_description(
        finding.description or f"PCI DSS Rule {finding.rule_id} violation",
        finding.rule_id,
    )

    message: dict = {"text": clean_desc}
    if finding.recommendation:
        message["markdown"] = f"{clean_desc}\n\n**Fix:** {finding.recommendation}"

    rel_uri = _relative_uri(finding.file_path, repo_root)

    result: dict = {
        "ruleId": f"PCI-DSS-{finding.rule_id}",
        "level": level,
        "message": message,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(finding.line_number, 1),
                    },
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "security-severity": str(
                _SECURITY_SEVERITY_MAP.get(finding.severity.lower(), 5.0)
            ),
            "source": finding.source,
            "pci_rule_id": finding.rule_id,
        },
    }

    if finding.column:
        result["locations"][0]["physicalLocation"]["region"]["startColumn"] = finding.column

    if finding.snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.snippet
        }

    if finding.recommendation:
        result["fixes"] = [
            {
                "description": {"text": finding.recommendation},
            }
        ]

    return result
