"""Per-file PCI DSS scanning: pattern matching + optional AI analysis."""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List, Optional

from pci_auditor.models import Finding
from pci_auditor.rules.rule_loader import PciRule

logger = logging.getLogger(__name__)

_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov",
    ".db", ".sqlite", ".bin",
}


def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
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
    """Run regex-based pattern matching against each line."""
    findings: List[Finding] = []

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

            for pattern in compiled_patterns:
                match = pattern.search(line)
                if match:
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
