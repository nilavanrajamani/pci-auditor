"""Per-file PCI DSS scanning: pattern matching + optional AI analysis."""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List, Optional

from pci_auditor.models import Finding
from pci_auditor.rules.rule_loader import PciRule

logger = logging.getLogger(__name__)

# Maps file extension -> (single_line_prefix, block_open, block_close)
# Used to skip pattern matches that fall inside comments.
_COMMENT_STYLES: dict[str, tuple[str | None, str | None, str | None]] = {
    ".py":    ("#",  None,  None),
    ".rb":    ("#",  None,  None),
    ".sh":    ("#",  None,  None),
    ".bash":  ("#",  None,  None),
    ".zsh":   ("#",  None,  None),
    ".yml":   ("#",  None,  None),
    ".yaml":  ("#",  None,  None),
    ".toml":  ("#",  None,  None),
    ".r":     ("#",  None,  None),
    ".conf":  ("#",  None,  None),
    ".tf":    ("#",  "/*",  "*/"),
    ".ini":   (";",  None,  None),
    ".js":    ("//", "/*",  "*/"),
    ".ts":    ("//", "/*",  "*/"),
    ".jsx":   ("//", "/*",  "*/"),
    ".tsx":   ("//", "/*",  "*/"),
    ".java":  ("//", "/*",  "*/"),
    ".c":     ("//", "/*",  "*/"),
    ".cpp":   ("//", "/*",  "*/"),
    ".cc":    ("//", "/*",  "*/"),
    ".h":     ("//", "/*",  "*/"),
    ".hpp":   ("//", "/*",  "*/"),
    ".cs":    ("//", "/*",  "*/"),
    ".go":    ("//", "/*",  "*/"),
    ".rs":    ("//", "/*",  "*/"),
    ".php":   ("//", "/*",  "*/"),
    ".swift": ("//", "/*",  "*/"),
    ".kt":    ("//", "/*",  "*/"),
    ".kts":   ("//", "/*",  "*/"),
    ".scala": ("//", "/*",  "*/"),
    ".sql":   ("--", "/*",  "*/"),
    ".html":  (None, "<!--", "-->"),
    ".xml":   (None, "<!--", "-->"),
}


def _comment_start_col(
    line: str,
    single_prefix: str | None,
    block_open: str | None,
    in_block: bool,
) -> tuple[int, bool]:
    """Return (comment_start_col, new_in_block).

    *comment_start_col* is the 0-based column at which a comment begins on
    *line*, or ``len(line)`` when there is no comment region.  Uses a simple
    quote-tracking scan so that ``//`` or ``#`` inside a string literal is
    not mistaken for a comment start.
    """
    if in_block:
        # Whole line is inside a block comment until the closing token.
        if block_open is not None:
            # Derive block_close from convention (always paired with block_open)
            block_close = "*/" if block_open == "/*" else "-->"
            idx = line.find(block_close)
            if idx != -1:
                # Block ends on this line; code may resume after the close token.
                # Conservatively mark the whole line as comment (the re-opened
                # code portion is rare and can still be scanned in next line).
                return 0, False
        return 0, True

    in_single_q = False
    in_double_q = False
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]

        if not in_single_q and not in_double_q:
            # Check block-comment open first (e.g. "/*")
            if block_open and line[i: i + len(block_open)] == block_open:
                return i, True
            # Check single-line comment prefix (e.g. "#", "//", "--")
            if single_prefix and line[i: i + len(single_prefix)] == single_prefix:
                return i, False
            if ch == "'":
                in_single_q = True
            elif ch == '"':
                in_double_q = True
        elif in_single_q:
            if ch == "\\":
                i += 1  # skip escaped character
            elif ch == "'":
                in_single_q = False
        else:  # in_double_q
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_double_q = False
        i += 1

    return n, False  # no comment found on this line


def _build_comment_cols(
    lines: list[str],
    single_prefix: str | None,
    block_open: str | None,
) -> list[int]:
    """Pre-compute the comment-start column for every line in a file.

    Returns a list of length ``len(lines)`` where each element is the
    0-based column at which a comment starts, or ``len(line)`` when there is
    no comment region.  Lines that are entirely inside a block comment have
    column 0.
    """
    cols: list[int] = []
    in_block = False
    for line in lines:
        col, in_block = _comment_start_col(line, single_prefix, block_open, in_block)
        cols.append(col)
    return cols


_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov",
    ".db", ".sqlite", ".bin",
}

# Documentation / plain-text file types that are never executable code.
# Pattern matching against these produces high false-positive rates
# (e.g. README tables containing sample code, changelogs, licence files).
_DOCUMENTATION_EXTENSIONS = {
    ".md", ".rst", ".txt", ".adoc", ".asciidoc",
    ".markdown", ".mdx", ".ipynb",
}


def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    if path.suffix.lower() in _DOCUMENTATION_EXTENSIONS:
        return True  # treat doc files the same as binary — skip pattern scanning
    try:
        with path.open("rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except OSError:
        return True


def scan_file(
    file_path: Path,
    rules: List[PciRule],
    ai_client=None,
    chunk_lines: int = 200,
    max_file_size_kb: int = 512,
    changed_lines: Optional[set] = None,
    rule_retriever=None,
) -> List[Finding]:
    """Scan a single file for PCI DSS violations.

    Args:
        file_path: Path to the file to scan.
        rules: List of PCI rules to check (all rules, used for pattern stage
               and as fallback for AI stage when no retriever is available).
        ai_client: Optional OpenAIClient instance for AI analysis.
        chunk_lines: Number of lines per AI chunk.
        max_file_size_kb: Skip files larger than this (kilobytes).
        changed_lines: If provided, only report findings on these line numbers (PR mode).
        rule_retriever: Optional RuleRetriever for semantic rule selection per
                        chunk.  When provided, only the top-K most relevant
                        rules are sent to the AI for each chunk instead of all
                        rules, reducing token usage and improving precision.

    Returns:
        List of Finding objects.
    """
    if is_binary_file(file_path):
        return []

    try:
        size_kb = file_path.stat().st_size / 1024
    except OSError:
        return []

    if size_kb > max_file_size_kb:
        logger.debug("Skipping %s: file too large (%.1f KB)", file_path, size_kb)
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Could not read %s: %s", file_path, exc)
        return []

    lines = content.splitlines()
    findings: List[Finding] = []

    # Stage 1: Pattern matching
    findings.extend(
        _pattern_scan(str(file_path), lines, rules, changed_lines)
    )

    # Stage 2: AI analysis
    if ai_client is not None:
        ai_findings = _ai_scan(
            str(file_path), lines, rules, ai_client, chunk_lines, changed_lines,
            rule_retriever=rule_retriever,
        )
        findings.extend(ai_findings)

    # Deduplicate (same rule_id + line_number)
    findings = _deduplicate(findings)

    return findings


def _pattern_scan(
    file_path: str,
    lines: List[str],
    rules: List[PciRule],
    changed_lines: Optional[set],
) -> List[Finding]:
    """Run regex-based pattern matching against each line.

    Matches that fall entirely within a comment region are silently skipped
    so that explanatory comments that mention security keywords do not produce
    false-positive findings.  Comment detection is language-aware based on the
    file extension (see ``_COMMENT_STYLES``).
    """
    findings: List[Finding] = []

    # Pre-compute the column at which each line's comment region starts.
    ext = Path(file_path).suffix.lower()
    single_prefix, block_open, _ = _COMMENT_STYLES.get(ext, (None, None, None))
    comment_cols = _build_comment_cols(lines, single_prefix, block_open)

    for rule in rules:
        if not rule.code_indicators:
            continue

        compiled_patterns = []
        for indicator in rule.code_indicators:
            try:
                compiled_patterns.append(re.compile(indicator, re.IGNORECASE))
            except re.error as exc:
                logger.debug(
                    "Invalid regex pattern '%s' for rule %s: %s",
                    indicator,
                    rule.id,
                    exc,
                )

        for line_no, line in enumerate(lines, start=1):
            if changed_lines is not None and line_no not in changed_lines:
                continue

            comment_col = comment_cols[line_no - 1]

            for pattern in compiled_patterns:
                match = pattern.search(line)
                if match:
                    # Skip matches that start inside a comment region.
                    if match.start() >= comment_col:
                        continue
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity.lower(),
                            file_path=file_path,
                            line_number=line_no,
                            column=match.start() + 1,
                            description=(
                                f"[Rule {rule.id}] {rule.requirement}"
                            ),
                            recommendation=(
                                f"Review this line against PCI DSS {rule.id}. "
                                f"Category: {rule.category}."
                            ),
                            snippet=line.strip()[:200],
                            source="pattern",
                        )
                    )
                    break  # One finding per rule per line is enough

    return findings


def _ai_scan(
    file_path: str,
    lines: List[str],
    rules: List[PciRule],
    ai_client,
    chunk_lines: int,
    changed_lines: Optional[set],
    rule_retriever=None,
) -> List[Finding]:
    """Chunk the file and send each chunk to the AI client.

    When *rule_retriever* is provided each chunk is individually queried for
    the most semantically relevant rules, reducing prompt size and cost.
    Falls back to injecting all *rules* when the retriever is unavailable.
    """
    findings: List[Finding] = []
    total_lines = len(lines)

    for start in range(0, total_lines, chunk_lines):
        end = min(start + chunk_lines, total_lines)
        chunk = lines[start:end]

        # In PR mode, skip chunks that have no changed lines
        if changed_lines is not None:
            chunk_line_nos = set(range(start + 1, end + 1))
            if not chunk_line_nos.intersection(changed_lines):
                continue

        snippet = "\n".join(chunk)
        # Select rules: use semantic retriever if available, else all rules
        chunk_rules = (
            rule_retriever.retrieve(snippet) if rule_retriever is not None else rules
        )
        logger.debug(
            "[RAG] %s lines %d-%d -> %d/%d rules selected%s: %s",
            file_path,
            start + 1,
            end,
            len(chunk_rules),
            len(rules),
            " (semantic)" if rule_retriever is not None else " (all -- no retriever)",
            ", ".join(r.id for r in chunk_rules),
        )
        try:
            chunk_findings = ai_client.analyse_chunk(
                file_path=file_path,
                code_snippet=snippet,
                line_offset=start + 1,
                rules=chunk_rules,
            )
            # Adjust absolute line numbers (model returns relative-to-chunk)
            for f in chunk_findings:
                if f.line_number > 0:
                    f.line_number = start + f.line_number
                else:
                    f.line_number = start + 1
                # In PR mode, filter to changed lines only
                if changed_lines is not None and f.line_number not in changed_lines:
                    continue
                findings.append(f)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI scan failed for %s chunk %d-%d: %s", file_path, start, end, exc)

    return findings


def _deduplicate(findings: List[Finding], line_tolerance: int = 3) -> List[Finding]:
    """Remove duplicate findings.

    Two findings are considered duplicates when they share the same rule_id and
    file_path and their line numbers are within *line_tolerance* lines of each
    other.  The first occurrence (pattern findings come before AI findings) wins.
    """
    result: List[Finding] = []
    for f in findings:
        is_dup = any(
            f.rule_id == existing.rule_id
            and f.file_path == existing.file_path
            and abs(f.line_number - existing.line_number) <= line_tolerance
            for existing in result
        )
        if not is_dup:
            result.append(f)
    return result
