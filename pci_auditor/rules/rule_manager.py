"""Download and update PCI DSS rules from an authoritative source."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import httpx

from pci_auditor.rules.rule_loader import _BUNDLED_RULES_PATH, _USER_CACHE_PATH


class RuleUpdateError(Exception):
    """Raised when the rules update fails."""


def update_rules(source_url: Optional[str] = None, timeout: int = 30) -> dict:
    """Download the latest PCI DSS rules and save to the user cache.

    Args:
        source_url: URL to fetch rules JSON from. Required — no default URL.
        timeout: HTTP request timeout in seconds.

    Returns:
        Metadata dict from the downloaded rules file.

    Raises:
        RuleUpdateError: If no URL is provided, or the download/validation fails.
    """
    if not source_url:
        raise RuleUpdateError(
            "No source URL provided. "
            "Use --source to specify a URL, e.g.:\n"
            "  pci-auditor rules update --source https://example.com/pci_rules.json"
        )

    url = source_url

    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuleUpdateError(f"Failed to download rules from {url}: {exc}") from exc

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise RuleUpdateError(f"Downloaded rules file is not valid JSON: {exc}") from exc

    _validate_rules_schema(data)

    # Write atomically via temp file
    _USER_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        dir=_USER_CACHE_PATH.parent,
        delete=False,
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = Path(tmp.name)

    shutil.move(str(tmp_path), str(_USER_CACHE_PATH))

    return {
        "pci_dss_version": data.get("pci_dss_version", "unknown"),
        "last_updated": data.get("last_updated", "unknown"),
        "rule_count": len(data.get("rules", [])),
        "saved_to": str(_USER_CACHE_PATH),
    }


def reset_to_bundled() -> None:
    """Remove the user-cached rules so the bundled baseline is used."""
    if _USER_CACHE_PATH.exists():
        _USER_CACHE_PATH.unlink()


def _validate_rules_schema(data: dict) -> None:
    if not isinstance(data, dict):
        raise RuleUpdateError("Rules file must be a JSON object.")
    if "rules" not in data:
        raise RuleUpdateError("Rules file must contain a 'rules' array.")
    if not isinstance(data["rules"], list) or len(data["rules"]) == 0:
        raise RuleUpdateError("Rules file 'rules' array must be non-empty.")
    required_fields = {"id", "requirement", "severity"}
    for i, rule in enumerate(data["rules"]):
        missing = required_fields - set(rule.keys())
        if missing:
            raise RuleUpdateError(
                f"Rule at index {i} is missing required fields: {missing}"
            )
