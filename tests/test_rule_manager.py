"""Tests for pci_auditor.rules.rule_manager."""

import json

import pytest
import responses as responses_lib

from pci_auditor.rules.rule_manager import (
    RuleUpdateError,
    _validate_rules_schema,
    update_rules,
)
from pci_auditor.rules.rule_loader import load_rules, get_rules_metadata


_VALID_RULES = {
    "pci_dss_version": "4.0.1",
    "last_updated": "2025-01-01",
    "source": "Test",
    "rules": [
        {
            "id": "3.3.1",
            "requirement": "Do not store SAD after authorisation.",
            "severity": "Critical",
            "category": "Protect Stored Account Data",
            "code_indicators": ["pan"],
            "ai_prompt_hint": "Look for PAN storage.",
        }
    ],
}


class TestValidateRulesSchema:
    def test_valid_schema_passes(self):
        _validate_rules_schema(_VALID_RULES)  # should not raise

    def test_missing_rules_key_raises(self):
        with pytest.raises(RuleUpdateError, match="'rules' array"):
            _validate_rules_schema({"pci_dss_version": "4.0.1"})

    def test_empty_rules_array_raises(self):
        with pytest.raises(RuleUpdateError, match="non-empty"):
            _validate_rules_schema({"rules": []})

    def test_rule_missing_id_raises(self):
        bad = {
            "rules": [{"requirement": "x", "severity": "High"}]
        }
        with pytest.raises(RuleUpdateError, match="missing required fields"):
            _validate_rules_schema(bad)

    def test_non_dict_raises(self):
        with pytest.raises(RuleUpdateError, match="JSON object"):
            _validate_rules_schema([1, 2, 3])  # type: ignore


class TestLoadRules:
    def test_loads_bundled_rules(self):
        """Without any user cache file, bundled rules should load."""
        rules = load_rules()
        assert len(rules) > 0

    def test_filter_by_severity(self):
        critical_rules = load_rules(severity_filter=["critical"])
        assert all(r.severity.lower() == "critical" for r in critical_rules)

    def test_all_rules_have_required_fields(self):
        for rule in load_rules():
            assert rule.id
            assert rule.requirement
            assert rule.severity

    def test_metadata_returns_expected_keys(self):
        meta = get_rules_metadata()
        assert "pci_dss_version" in meta
        assert "rule_count" in meta
        assert meta["rule_count"] > 0


@responses_lib.activate
class TestUpdateRules:
    def test_successful_update(self, tmp_path, monkeypatch):
        url = "https://example.com/pci_rules.json"
        responses_lib.add(
            responses_lib.GET,
            url,
            json=_VALID_RULES,
            status=200,
        )

        # Redirect the user cache path to tmp_path so we don't pollute home dir
        import pci_auditor.rules.rule_manager as rm
        monkeypatch.setattr(rm, "_USER_CACHE_PATH", tmp_path / "pci_rules.json")

        result = update_rules(source_url=url)

        assert result["pci_dss_version"] == "4.0.1"
        assert result["rule_count"] == 1
        assert (tmp_path / "pci_rules.json").exists()

    def test_http_error_raises(self, monkeypatch):
        url = "https://example.com/bad_rules.json"
        responses_lib.add(
            responses_lib.GET,
            url,
            status=404,
        )
        import pci_auditor.rules.rule_manager as rm
        monkeypatch.setattr(rm, "_USER_CACHE_PATH", __import__("pathlib").Path("/tmp/test_rules.json"))

        with pytest.raises(RuleUpdateError):
            update_rules(source_url=url)

    def test_invalid_json_raises(self, monkeypatch):
        url = "https://example.com/bad_json.json"
        responses_lib.add(
            responses_lib.GET,
            url,
            body="not json at all!!!",
            status=200,
            content_type="application/json",
        )
        import pci_auditor.rules.rule_manager as rm
        monkeypatch.setattr(rm, "_USER_CACHE_PATH", __import__("pathlib").Path("/tmp/test_rules.json"))

        with pytest.raises(RuleUpdateError):
            update_rules(source_url=url)
