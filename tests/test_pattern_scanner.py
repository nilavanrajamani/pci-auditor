"""Tests for pattern-based scanning in pci_auditor.scanner.file_scanner."""

import tempfile
from pathlib import Path

import pytest

from pci_auditor.rules.rule_loader import PciRule, load_rules
from pci_auditor.scanner.file_scanner import scan_file, _pattern_scan


def _rule(id_, severity, indicators):
    return PciRule(
        id=id_,
        requirement=f"Test rule {id_}",
        severity=severity,
        category="Test",
        code_indicators=indicators,
    )


class TestPatternScan:
    def test_detects_raw_pan_in_variable(self):
        rules = [_rule("3.3.1", "Critical", [r"(?<![A-Z0-9])[0-9]{13,19}(?![0-9])"])]
        lines = ['    pan = "4111111111111111"']
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        assert len(findings) == 1
        assert findings[0].rule_id == "3.3.1"
        assert findings[0].severity == "critical"
        assert findings[0].line_number == 1

    def test_detects_cvv_storage(self):
        rules = [_rule("3.3.2", "Critical", ["cvv", "cvc", "security_code"])]
        lines = ['    stored_cvv = request.POST["cvv"]']
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        assert len(findings) == 1
        assert findings[0].rule_id == "3.3.2"

    def test_detects_http_endpoint(self):
        rules = [_rule("4.2.1", "Critical", ["http://"])]
        lines = ['    url = "http://payment-api.example.com/charge"']
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        assert len(findings) >= 1
        assert any(f.rule_id == "4.2.1" for f in findings)

    def test_detects_hardcoded_password(self):
        rules = [_rule("8.6.1", "High", [r"password\s*=\s*['\"][^'\"]{1,8}['\"]"])]
        lines = ['    password = "secret1"']
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        assert len(findings) == 1
        assert findings[0].rule_id == "8.6.1"

    def test_no_false_positive_on_https(self):
        rules = [_rule("4.2.1", "Critical", [r"(?<!\w)http://"])]
        lines = ['    url = "https://payment-api.example.com/charge"']
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        assert len(findings) == 0

    def test_changed_lines_filter(self):
        rules = [_rule("3.3.1", "Critical", [r"(?<![A-Z0-9])[0-9]{13,19}(?![0-9])"])]
        lines = [
            '    safe = "hello"',
            '    pan = "4111111111111111"',
            '    other = "world"',
        ]
        # Only line 3 is changed — should NOT find the PAN on line 2
        findings = _pattern_scan("test.py", lines, rules, changed_lines={3})
        assert all(f.line_number == 3 for f in findings)
        assert not any(f.line_number == 2 for f in findings)

    def test_multiple_rules_multiple_findings(self):
        rules = [
            _rule("3.3.1", "Critical", [r"[0-9]{16}"]),
            _rule("3.3.2", "Critical", ["cvv"]),
        ]
        lines = [
            '    pan = "4111111111111111"',
            '    cvv = "123"',
        ]
        findings = _pattern_scan("test.py", lines, rules, changed_lines=None)
        rule_ids = {f.rule_id for f in findings}
        assert "3.3.1" in rule_ids
        assert "3.3.2" in rule_ids

    def test_scan_file_skips_binary(self):
        """scan_file should return empty list for binary files."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
            tmp_path = Path(tmp.name)
        try:
            findings = scan_file(tmp_path, rules=load_rules(), ai_client=None)
            assert findings == []
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_scan_file_detects_pan_in_temp_file(self):
        """End-to-end: write a file with a PAN and verify finding is raised."""
        code = 'credit_card_number = "4111111111111111"\n'
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)
        try:
            rules = [r for r in load_rules() if r.id == "3.3.1"]
            findings = scan_file(tmp_path, rules=rules, ai_client=None)
            assert any(f.rule_id == "3.3.1" for f in findings)
        finally:
            tmp_path.unlink(missing_ok=True)
