"""Tests for pci_auditor.ai.openai_client."""

import json

import pytest

from pci_auditor.ai.openai_client import OpenAIClient, _build_user_prompt
from pci_auditor.rules.rule_loader import PciRule


def _rule(id_="3.3.1", severity="Critical", hint="Look for PAN."):
    return PciRule(
        id=id_,
        requirement="Test requirement.",
        severity=severity,
        category="Test",
        code_indicators=[],
        ai_prompt_hint=hint,
    )


class TestBuildUserPrompt:
    def test_includes_file_path(self):
        prompt = _build_user_prompt("payment/pay.py", "code here", 1, [_rule()])
        assert "payment/pay.py" in prompt

    def test_includes_rule_id(self):
        prompt = _build_user_prompt("file.py", "code", 1, [_rule(id_="3.3.1")])
        assert "3.3.1" in prompt

    def test_includes_code_snippet(self):
        prompt = _build_user_prompt("file.py", 'pan = "4111111111111111"', 1, [_rule()])
        assert '4111111111111111' in prompt

    def test_includes_line_offset(self):
        prompt = _build_user_prompt("file.py", "code", 50, [_rule()])
        assert "50" in prompt


class TestOpenAIClientInit:
    def test_missing_credentials_raises(self):
        with pytest.raises(ValueError, match="endpoint"):
            OpenAIClient(endpoint="", api_key="", deployment="")

    def test_missing_endpoint_raises(self):
        with pytest.raises(ValueError):
            OpenAIClient(endpoint="", api_key="key", deployment="gpt-4o")


class TestParseResponse:
    """Test _parse_response without making real network calls."""

    def _make_client(self):
        """Create a client instance bypassing __init__ for unit testing the parser."""
        client = object.__new__(OpenAIClient)
        client._deployment = "gpt-4o"
        # Attach parser method directly
        return client

    def _parse(self, content, file_path="test.py"):
        client = self._make_client()
        return OpenAIClient._parse_response(client, content, file_path)

    def test_parses_valid_json_array(self):
        payload = json.dumps([
            {
                "rule_id": "3.3.1",
                "severity": "critical",
                "line_number": 5,
                "description": "PAN stored in plain text.",
                "recommendation": "Tokenise the PAN.",
            }
        ])
        findings = self._parse(payload)
        assert len(findings) == 1
        assert findings[0].rule_id == "3.3.1"
        assert findings[0].severity == "critical"
        assert findings[0].line_number == 5
        assert findings[0].source == "ai"

    def test_parses_findings_wrapper(self):
        payload = json.dumps({
            "findings": [
                {
                    "rule_id": "4.2.1",
                    "severity": "high",
                    "line_number": 12,
                    "description": "HTTP used instead of HTTPS.",
                    "recommendation": "Switch to HTTPS.",
                }
            ]
        })
        findings = self._parse(payload)
        assert len(findings) == 1
        assert findings[0].rule_id == "4.2.1"

    def test_returns_empty_on_empty_array(self):
        findings = self._parse("[]")
        assert findings == []

    def test_handles_markdown_fenced_json(self):
        payload = "```json\n[\n{\"rule_id\":\"3.3.2\",\"severity\":\"critical\",\"line_number\":1,\"description\":\"CVV stored.\",\"recommendation\":\"Remove it.\"}\n]\n```"
        findings = self._parse(payload)
        assert len(findings) == 1
        assert findings[0].rule_id == "3.3.2"

    def test_returns_empty_on_invalid_json(self):
        findings = self._parse("this is not json at all")
        assert findings == []

    def test_multiple_findings(self):
        payload = json.dumps([
            {"rule_id": "3.3.1", "severity": "critical", "line_number": 1,
             "description": "PAN stored.", "recommendation": "Tokenise."},
            {"rule_id": "8.6.1", "severity": "high", "line_number": 7,
             "description": "Hardcoded password.", "recommendation": "Use vault."},
        ])
        findings = self._parse(payload)
        assert len(findings) == 2
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"3.3.1", "8.6.1"}
