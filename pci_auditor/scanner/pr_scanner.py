"""PR scanner: scans only lines changed in a git diff."""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

# Unified diff hunk header: @@ -old_start,old_count +new_start,new_count @@
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")


@dataclass
class DiffFile:
    path: str
    added_line_numbers: Set[int] = field(default_factory=set)
    added_lines: Dict[int, str] = field(default_factory=dict)  # line_no -> content


def get_diff_files(
    repo_path: Path,
    base_branch: str = "main",
    head: str = "HEAD",
) -> List[DiffFile]:
    """Run git diff and return per-file changed lines.

    Args:
        repo_path: Root of the git repository.
        base_branch: Base ref to diff against (e.g. 'main', 'origin/main').
        head: HEAD ref (default: current HEAD).

    Returns:
        List of DiffFile objects, one per changed file.
    """
    cmd = [
        "git",
        "-C",
        str(repo_path),
        "diff",
        "--unified=0",
        f"{base_branch}...{head}",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "git is not installed or not on PATH. "
            "Ensure git is available in the CI environment."
        ) from exc

    if result.returncode not in (0, 1):
        err = result.stderr.strip()
        raise RuntimeError(
            f"git diff failed (exit {result.returncode}): {err}"
        )

    return _parse_diff(result.stdout)


def _parse_diff(diff_text: str) -> List[DiffFile]:
    files: Dict[str, DiffFile] = {}
    current_file: str = ""
    current_new_start = 0
    current_line_no = 0

    for line in diff_text.splitlines():
        # New file in diff
        if line.startswith("+++ b/"):
            file_match = _DIFF_FILE_RE.match(line)
            if file_match:
                current_file = file_match.group(1)
                if current_file not in files:
                    files[current_file] = DiffFile(path=current_file)
            continue

        # Skip header lines
        if line.startswith("--- ") or line.startswith("diff ") or line.startswith("index "):
            if line.startswith("diff "):
                # Reset current file until +++ line is found
                current_file = ""
            continue

        # Hunk header
        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            current_new_start = int(hunk_match.group(1))
            current_line_no = current_new_start
            continue

        if not current_file:
            continue

        diff_file = files[current_file]

        if line.startswith("+"):
            # Added line
            diff_file.added_line_numbers.add(current_line_no)
            diff_file.added_lines[current_line_no] = line[1:]
            current_line_no += 1
        elif line.startswith("-"):
            # Removed line — don't advance new file line counter
            pass
        else:
            # Context line
            current_line_no += 1

    return list(files.values())
