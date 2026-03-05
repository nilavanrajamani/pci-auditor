"""Tests for reporters and exit-code logic."""

import json

import pytest

from pci_auditor.models import Finding, ScanResult
from pci_auditor.config import should_fail
from pci_auditor.reporter.json_reporter import write_json
from pci_auditor.reporter.sarif_reporter import write_sarif, _SARIF_VERSION


def _make_finding(rule_id="3.3.1", severity="critical", line=10):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file_path="payment/processor.py",
        line_number=line,
        description=f"Rule {rule_id} violation",
        recommendation="Fix this immediately.",
        snippet='pan = "4111111111111111"',
        source="pattern",
    )


def _make_result(findings=None):
    r = ScanResult()
    r.findings = findings or []
    r.scanned_files = 3
    r.scanned_lines = 300
    return r


class TestShouldFail:
    def test_critical_finding_fails_on_critical_high(self):
        findings = [_make_finding(severity="critical")]
        assert should_fail(findings, ["critical", "high"]) is True

    def test_high_finding_fails_on_critical_high(self):
        findings = [_make_finding(severity="high")]
        assert should_fail(findings, ["critical", "high"]) is True

    def test_medium_does_not_fail_on_critical_high(self):
        findings = [_make_finding(severity="medium")]
        assert should_fail(findings, ["critical", "high"]) is False

    def test_empty_findings_does_not_fail(self):
        assert should_fail([], ["critical", "high"]) is False

    def test_fail_on_none_never_fails(self):
        findings = [_make_finding(severity="critical")]
        assert should_fail(findings, []) is False


class TestJsonReporter:
    def test_json_output_structure(self, capsys):
        result = _make_result([_make_finding()])
        write_json(result)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["critical"] == 1
        assert data["summary"]["total_findings"] == 1
        assert data["findings"][0]["rule_id"] == "3.3.1"
        assert data["findings"][0]["severity"] == "critical"
        assert data["findings"][0]["line_number"] == 10

    def test_json_to_file(self, tmp_path):
        result = _make_result([_make_finding()])
        out_file = str(tmp_path / "results.json")
        write_json(result, out_file)
        with open(out_file) as f:
            data = json.load(f)
        assert data["summary"]["critical"] == 1

    def test_empty_findings(self, capsys):
        result = _make_result([])
        write_json(result)
        data = json.loads(capsys.readouterr().out)
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []


class TestSarifReporter:
    def test_sarif_version(self, capsys):
        result = _make_result([_make_finding()])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        assert sarif["version"] == _SARIF_VERSION

    def test_sarif_contains_run(self, capsys):
        result = _make_result([_make_finding()])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        assert len(sarif["runs"]) == 1

    def test_sarif_result_rule_id(self, capsys):
        result = _make_result([_make_finding(rule_id="3.3.1")])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        sarif_result = sarif["runs"][0]["results"][0]
        assert sarif_result["ruleId"] == "PCI-DSS-3.3.1"

    def test_sarif_critical_level_is_error(self, capsys):
        result = _make_result([_make_finding(severity="critical")])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_medium_level_is_warning(self, capsys):
        result = _make_result([_make_finding(severity="medium")])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_to_file(self, tmp_path):
        result = _make_result([_make_finding()])
        out_file = str(tmp_path / "results.sarif")
        write_sarif(result, out_file)
        with open(out_file) as f:
            sarif = json.load(f)
        assert sarif["version"] == _SARIF_VERSION

    def test_sarif_empty_findings(self, capsys):
        result = _make_result([])
        write_sarif(result)
        sarif = json.loads(capsys.readouterr().out)
        assert sarif["runs"][0]["results"] == []


class TestScanResultModel:
    def test_severity_counts(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
            _make_finding(severity="low"),
        ]
        result = _make_result(findings)
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
