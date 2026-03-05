"""Codebase scanner: recursively walks a directory tree."""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_EXCLUDES = [
    ".git",
    ".github",
    ".vscode",
    "node_modules",
    "__pycache__",
    "*.pyc",
    "bin",
    "obj",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.lock",
    "*.log",
    "*.egg-info",
    "*.dist-info",
    "migrations",
    "vendor",
    ".terraform",
]


def iter_files(
    root: Path,
    exclude_patterns: Optional[List[str]] = None,
    max_file_size_kb: int = 512,
) -> Iterator[Path]:
    """Recursively yield files under *root* that are eligible for scanning.

    Args:
        root: Directory to scan.
        exclude_patterns: Additional glob patterns to exclude (merged with defaults).
        max_file_size_kb: Skip individual files larger than this.

    Yields:
        Path objects for each scannable file.
    """
    patterns = list(_DEFAULT_EXCLUDES)
    if exclude_patterns:
        patterns.extend(exclude_patterns)

    for path in _walk(root, root, patterns):
        try:
            if path.stat().st_size / 1024 <= max_file_size_kb:
                yield path
        except OSError:
            continue


def _walk(current: Path, root: Path, exclude_patterns: List[str]) -> Iterator[Path]:
    try:
        entries = list(current.iterdir())
    except PermissionError:
        logger.debug("Permission denied: %s", current)
        return

    for entry in sorted(entries):
        relative = entry.relative_to(root)

        if _is_excluded(entry, relative, exclude_patterns):
            logger.debug("Excluded: %s", entry)
            continue

        if entry.is_symlink():
            continue

        if entry.is_dir():
            yield from _walk(entry, root, exclude_patterns)
        elif entry.is_file():
            yield entry


def _is_excluded(path: Path, relative: Path, patterns: List[str]) -> bool:
    name = path.name
    relative_str = relative.as_posix()

    for pattern in patterns:
        # Match against just the name
        if fnmatch.fnmatch(name, pattern):
            return True
        # Match against relative path
        if fnmatch.fnmatch(relative_str, pattern):
            return True
        # Match directory name exactly (for things like "bin", "obj")
        if path.is_dir() and name == pattern.rstrip("/"):
            return True

    return False
