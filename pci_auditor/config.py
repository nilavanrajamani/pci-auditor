"""Configuration loader for PCI Auditor.

Reads from (in priority order):
1. CLI flags (handled by click in cli.py)
2. Environment variables
3. .env file in the working directory (loaded automatically via python-dotenv)
4. .pci-auditor.yml in the repo root
5. Built-in defaults
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

# Load .env from the current working directory (or any parent) if present.
# This is a no-op when the file doesn't exist, so it's always safe to call.
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)  # env vars already set in the shell take precedence
except ImportError:  # python-dotenv not installed — degrade gracefully
    pass


_DEFAULT_RULES_SOURCE = ""

_DEFAULT_EXCLUDE_PATHS = [
    ".git",
    ".github",
    "node_modules",
    "__pycache__",
    "*.pyc",
    "bin/",
    "obj/",
    "dist/",
    "build/",
    ".venv",
    "venv",
    "*.min.js",
    "*.map",
    "*.lock",
    "*.log",
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class AuditorConfig:
    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-02-01"

    # Scan behaviour
    fail_on: List[str] = field(default_factory=lambda: ["critical", "high"])
    exclude_paths: List[str] = field(default_factory=lambda: list(_DEFAULT_EXCLUDE_PATHS))
    chunk_lines: int = 200
    max_file_size_kb: int = 512

    # Rules
    rules_source: str = _DEFAULT_RULES_SOURCE

    # Output
    output_format: str = "console"  # console | json | sarif
    output_file: Optional[str] = None

    # Embeddings + semantic rule retrieval
    azure_openai_embedding_deployment: str = ""  # e.g. "text-embedding-3-small"
    # Optional overrides — leave blank to share the main endpoint/key above
    azure_openai_embedding_endpoint: str = ""
    azure_openai_embedding_api_key: str = ""
    top_k_rules: int = 8  # number of rules retrieved per code chunk

    # Azure AI Search (optional — omit to use local cosine-similarity index)
    azure_search_endpoint: str = ""
    azure_search_api_key: str = ""
    azure_search_index_name: str = "pci-rules"

    # Feature flags
    use_ai: bool = True


def load_config(repo_path: Path | None = None) -> AuditorConfig:
    """Load configuration merging .pci-auditor.yml with env vars."""
    cfg = AuditorConfig()

    # Load from .pci-auditor.yml if present
    config_file = (repo_path or Path.cwd()) / ".pci-auditor.yml"
    if config_file.exists():
        with config_file.open() as f:
            data: dict = yaml.safe_load(f) or {}
        _apply_yaml(cfg, data)

    # Override with env vars
    _apply_env(cfg)

    return cfg


def _apply_yaml(cfg: AuditorConfig, data: dict) -> None:
    field_map = {
        "fail_on": "fail_on",
        "exclude_paths": "exclude_paths",
        "chunk_lines": "chunk_lines",
        "max_file_size_kb": "max_file_size_kb",
        "rules_source": "rules_source",
        "output_format": "output_format",
        "output_file": "output_file",
        "use_ai": "use_ai",
        "azure_openai_endpoint": "azure_openai_endpoint",
        "azure_openai_deployment": "azure_openai_deployment",
        "azure_openai_api_version": "azure_openai_api_version",
        "azure_openai_embedding_deployment": "azure_openai_embedding_deployment",
        "azure_openai_embedding_endpoint": "azure_openai_embedding_endpoint",
        "azure_openai_embedding_api_key": "azure_openai_embedding_api_key",
        "top_k_rules": "top_k_rules",
        "azure_search_endpoint": "azure_search_endpoint",
        "azure_search_index_name": "azure_search_index_name",
    }
    for yaml_key, attr in field_map.items():
        if yaml_key in data:
            setattr(cfg, attr, data[yaml_key])


def _apply_env(cfg: AuditorConfig) -> None:
    env_map = {
        "AZURE_OPENAI_ENDPOINT": "azure_openai_endpoint",
        "AZURE_OPENAI_API_KEY": "azure_openai_api_key",
        "AZURE_OPENAI_DEPLOYMENT": "azure_openai_deployment",
        "AZURE_OPENAI_API_VERSION": "azure_openai_api_version",
        "AZURE_OPENAI_EMBEDDING_DEPLOYMENT": "azure_openai_embedding_deployment",
        "AZURE_OPENAI_EMBEDDING_ENDPOINT": "azure_openai_embedding_endpoint",
        "AZURE_OPENAI_EMBEDDING_API_KEY": "azure_openai_embedding_api_key",
        "AZURE_SEARCH_ENDPOINT": "azure_search_endpoint",
        "AZURE_SEARCH_API_KEY": "azure_search_api_key",
        "AZURE_SEARCH_INDEX_NAME": "azure_search_index_name",
        "PCI_AUDITOR_TOP_K_RULES": "top_k_rules",
        "PCI_AUDITOR_RULES_SOURCE": "rules_source",
        "PCI_AUDITOR_FAIL_ON": None,  # handled below
        "PCI_AUDITOR_NO_AI": None,  # handled below
    }
    for env_key, attr in env_map.items():
        val = os.environ.get(env_key)
        if val is not None and attr:
            setattr(cfg, attr, val)

    # Coerce numeric fields read from env (env vars are always strings)
    try:
        cfg.top_k_rules = int(cfg.top_k_rules)
    except (ValueError, TypeError):
        cfg.top_k_rules = 8

    fail_on_env = os.environ.get("PCI_AUDITOR_FAIL_ON")
    if fail_on_env:
        cfg.fail_on = [s.strip().lower() for s in fail_on_env.split(",")]

    no_ai_env = os.environ.get("PCI_AUDITOR_NO_AI")
    if no_ai_env and no_ai_env.lower() in ("1", "true", "yes"):
        cfg.use_ai = False


def severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity.lower(), 99)


def should_fail(findings: list, fail_on: List[str]) -> bool:
    """Return True if any finding severity is in the fail_on list."""
    fail_set = {s.lower() for s in fail_on}
    return any(f.severity.lower() in fail_set for f in findings)
