"""Azure OpenAI client for PCI DSS AI-powered analysis."""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from pci_auditor.models import Finding
from pci_auditor.rules.rule_loader import PciRule

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a PCI DSS 4.0 compliance security auditor specialising in code review.
Your task is to analyse provided source code snippets and identify potential PCI DSS compliance violations.

For each violation you find, return a JSON array of objects with exactly these fields:
- "rule_id": the PCI DSS rule ID (e.g. "3.3.1")
- "severity": one of "critical", "high", "medium", "low", "info"
- "line_number": integer, best-estimate line number within the provided snippet (1-based, relative to the snippet start offset)
- "description": clear description of what the violation is and why it violates PCI DSS
- "recommendation": specific remediation guidance

Return ONLY a valid JSON array. No markdown, no explanation text outside the JSON.
If no violations are found, return an empty array: []
"""


def _build_user_prompt(
    file_path: str,
    code_snippet: str,
    line_offset: int,
    rules: List[PciRule],
) -> str:
    rule_hints = "\n".join(
        f"- Rule {r.id} ({r.severity}): {r.requirement}\n  Hint: {r.ai_prompt_hint}"
        for r in rules
        if r.ai_prompt_hint
    )

    return f"""File: {file_path}
Lines: {line_offset} - {line_offset + code_snippet.count(chr(10))}

Applicable PCI DSS 4.0 rules to check (focus on these):
{rule_hints}

Source code to analyse:
```
{code_snippet}
```

Return JSON array of findings."""


class OpenAIClient:
    """Wrapper around the Azure OpenAI API for PCI analysis."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str = "2024-02-01",
    ) -> None:
        if not endpoint or not api_key or not deployment:
            raise ValueError(
                "Azure OpenAI endpoint, API key, and deployment name are all required. "
                "Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT."
            )
        try:
            from openai import AzureOpenAI  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for AI analysis. "
                "Install it with: pip install openai"
            ) from exc

        self._client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
        self._deployment = deployment

    def analyse_chunk(
        self,
        file_path: str,
        code_snippet: str,
        line_offset: int,
        rules: List[PciRule],
    ) -> List[Finding]:
        """Send a code chunk to Azure OpenAI and return PCI findings.

        Args:
            file_path: Source file path (for context / finding attribution).
            code_snippet: Raw code text to analyse.
            line_offset: Line number of the first line in the snippet.
            rules: List of PCI rules to instruct the model to check against.

        Returns:
            List of Finding objects parsed from the model response.
        """
        if not code_snippet.strip():
            return []

        user_prompt = _build_user_prompt(file_path, code_snippet, line_offset, rules)

        logger.debug(
            "[GPT] Sending prompt to '%s' -- %d rules, %d code lines\n"
            "--- SYSTEM ---\n%s\n"
            "--- USER ---\n%s\n"
            "--- END ---",
            self._deployment,
            len(rules),
            code_snippet.count("\n") + 1,
            _SYSTEM_PROMPT.strip(),
            user_prompt,
        )

        try:
            response = self._client.chat.completions.create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0,
                max_tokens=2048,
                response_format={"type": "json_object"}
                if self._supports_json_mode()
                else None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Azure OpenAI request failed for %s: %s", file_path, exc)
            return []

        content = response.choices[0].message.content or ""
        return self._parse_response(content, file_path)

    def _supports_json_mode(self) -> bool:
        """gpt-4o and gpt-4-turbo support json_object response_format."""
        return any(
            name in self._deployment.lower()
            for name in ("gpt-4o", "gpt-4-turbo", "gpt-4t")
        )

    def _parse_response(self, content: str, file_path: str) -> List[Finding]:
        """Parse the model JSON response into Finding objects."""
        content = content.strip()

        # Strip markdown code fences if present
        if content.startswith("```"):
            lines = content.splitlines()
            content = "\n".join(
                line for line in lines if not line.startswith("```")
            ).strip()

        # Handle {"findings": [...]} wrapper that some models emit
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Could not parse OpenAI response as JSON for %s", file_path)
            return []

        if isinstance(parsed, dict):
            # Unwrap common wrappers
            for key in ("findings", "violations", "results", "issues"):
                if key in parsed and isinstance(parsed[key], list):
                    parsed = parsed[key]
                    break
            else:
                logger.warning(
                    "OpenAI response for %s is a dict without a recognised array key.",
                    file_path,
                )
                return []

        if not isinstance(parsed, list):
            return []

        findings: List[Finding] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule_id", "unknown"))
            severity = str(item.get("severity", "medium")).lower()
            line_number = int(item.get("line_number", 0))
            description = str(item.get("description", ""))
            recommendation = str(item.get("recommendation", ""))

            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_number,
                    description=description,
                    recommendation=recommendation,
                    source="ai",
                )
            )

        return findings
