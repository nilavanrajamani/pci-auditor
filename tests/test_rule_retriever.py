"""Tests for pci_auditor.ai.rule_embedder and pci_auditor.ai.rule_index."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch, call

import pytest

from pci_auditor.ai.rule_embedder import EmbeddingClient, cosine_similarity
from pci_auditor.ai.rule_index import (
    AzureSearchRuleIndex,
    LocalRuleIndex,
    RuleRetriever,
    build_retriever,
)
from pci_auditor.rules.rule_loader import PciRule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(rule_id: str, requirement: str = "Requirement text") -> PciRule:
    return PciRule(
        id=rule_id,
        requirement=requirement,
        severity="HIGH",
        category="Test",
        code_indicators=["indicator"],
        ai_prompt_hint="Hint for " + rule_id,
    )


def _unit_vector(length: int, hot: int) -> List[float]:
    """Return a unit vector of *length* with 1.0 at position *hot*."""
    v = [0.0] * length
    v[hot] = 1.0
    return v


# ---------------------------------------------------------------------------
# cosine_similarity
# ---------------------------------------------------------------------------

class TestCosineSimilarity:
    def test_identical_vectors_return_one(self):
        v = [1.0, 2.0, 3.0]
        result = cosine_similarity(v, v)
        assert result == pytest.approx(1.0)

    def test_orthogonal_vectors_return_zero(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert cosine_similarity(a, b) == pytest.approx(0.0)

    def test_opposite_vectors_return_minus_one(self):
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert cosine_similarity(a, b) == pytest.approx(-1.0)

    def test_zero_vector_returns_zero(self):
        assert cosine_similarity([0.0, 0.0], [1.0, 2.0]) == pytest.approx(0.0)

    def test_both_zero_vectors_returns_zero(self):
        assert cosine_similarity([0.0], [0.0]) == pytest.approx(0.0)

    def test_known_values(self):
        a = [1.0, 1.0, 0.0]
        b = [1.0, 0.0, 1.0]
        expected = 1.0 / 2.0  # dot=1, |a|=sqrt(2), |b|=sqrt(2) → 1/2
        assert cosine_similarity(a, b) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# EmbeddingClient
# ---------------------------------------------------------------------------

def _patched_embedding_client(
    mock_azure_cls: MagicMock,
    embedding_side_effect=None,
) -> EmbeddingClient:
    """Build an EmbeddingClient with openai.AzureOpenAI fully mocked."""
    client = EmbeddingClient(
        endpoint="https://test.openai.azure.com",
        api_key="key",
        deployment="text-embedding-3-small",
    )
    if embedding_side_effect is not None:
        client._client.embeddings.create.side_effect = embedding_side_effect
    return client


class TestEmbeddingClient:
    def test_embed_returns_vector(self):
        with patch("openai.AzureOpenAI") as MockOpenAI:
            embedding_data = MagicMock()
            embedding_data.embedding = [0.1, 0.2, 0.3]
            MockOpenAI.return_value.embeddings.create.return_value = MagicMock(
                data=[embedding_data]
            )
            client = EmbeddingClient(
                endpoint="https://test.openai.azure.com",
                api_key="key",
                deployment="text-embedding-3-small",
            )
            result = client.embed("hello world")

        assert result == [0.1, 0.2, 0.3]

    def test_embed_truncates_long_text(self):
        with patch("openai.AzureOpenAI") as MockOpenAI:
            embedding_data = MagicMock()
            embedding_data.embedding = [0.5]
            MockOpenAI.return_value.embeddings.create.return_value = MagicMock(
                data=[embedding_data]
            )
            client = EmbeddingClient(
                endpoint="https://test.openai.azure.com",
                api_key="key",
                deployment="text-embedding-3-small",
            )
            long_text = "x" * 5000
            client.embed(long_text)

            call_kwargs = MockOpenAI.return_value.embeddings.create.call_args[1]
            passed_input = call_kwargs["input"]
            assert len(passed_input) <= 2000

    def test_embed_batch_returns_list_of_vectors(self):
        with patch("openai.AzureOpenAI") as MockOpenAI:
            def _create(**kwargs):
                texts = kwargs["input"]
                data = []
                for i in range(len(texts)):
                    item = MagicMock()
                    item.index = i
                    item.embedding = [float(i)]
                    data.append(item)
                return MagicMock(data=data)

            MockOpenAI.return_value.embeddings.create.side_effect = _create
            client = EmbeddingClient(
                endpoint="https://test.openai.azure.com",
                api_key="key",
                deployment="text-embedding-3-small",
            )
            result = client.embed_batch(["a", "b", "c"])

        assert result == [[0.0], [1.0], [2.0]]

    def test_embed_batch_falls_back_on_error(self):
        """If batch call raises, falls back to sequential embed()."""
        with patch("openai.AzureOpenAI") as MockOpenAI:
            call_count = {"n": 0}

            def _create(**kwargs):
                inputs = kwargs.get("input", [])
                if isinstance(inputs, list) and len(inputs) > 1:
                    raise RuntimeError("batch not supported")
                item = MagicMock()
                item.index = 0
                item.embedding = [float(call_count["n"])]
                call_count["n"] += 1
                return MagicMock(data=[item])

            MockOpenAI.return_value.embeddings.create.side_effect = _create
            client = EmbeddingClient(
                endpoint="https://test.openai.azure.com",
                api_key="key",
                deployment="text-embedding-3-small",
            )
            result = client.embed_batch(["x", "y"])

        assert result == [[0.0], [1.0]]


# ---------------------------------------------------------------------------
# LocalRuleIndex
# ---------------------------------------------------------------------------

def _make_embedder_for_rules(rules: List[PciRule]) -> MagicMock:
    """Embedder that assigns orthogonal unit vectors per rule (batch + single)."""
    embedder = MagicMock(spec=EmbeddingClient)
    dim = len(rules)

    def _batch(texts):
        return [_unit_vector(dim, i) for i in range(len(texts))]

    embedder.embed_batch.side_effect = _batch
    return embedder


class TestLocalRuleIndex:
    def test_build_populates_index(self):
        rules = [_make_rule("1.1"), _make_rule("1.2"), _make_rule("1.3")]
        embedder = _make_embedder_for_rules(rules)
        idx = LocalRuleIndex()
        idx.build(rules, embedder)
        assert idx.is_built()

    def test_retrieve_returns_top_k(self):
        rules = [_make_rule(f"1.{i}") for i in range(5)]
        dim = len(rules)
        embedder = _make_embedder_for_rules(rules)
        # Query embedding matches rule at index 0 exactly
        embedder.embed.return_value = _unit_vector(dim, 0)

        idx = LocalRuleIndex()
        idx.build(rules, embedder)
        results = idx.retrieve("some code", embedder=embedder, top_k=2)

        assert len(results) == 2
        assert results[0].id == "1.0"

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        rules = [_make_rule("2.1"), _make_rule("2.2")]
        embedder = _make_embedder_for_rules(rules)

        cache_file = tmp_path / "rule_embeddings.json"
        idx = LocalRuleIndex()
        idx.build(rules, embedder)
        idx.save(path=cache_file)

        assert cache_file.exists()

        idx2 = LocalRuleIndex()
        assert idx2.load(path=cache_file)
        assert idx2.is_built()
        loaded = json.loads(cache_file.read_text())
        assert len(loaded["embeddings"]) == 2

    def test_retrieve_raises_when_not_built(self):
        idx = LocalRuleIndex()
        with pytest.raises(RuntimeError, match="empty"):
            idx.retrieve("code", embedder=MagicMock(), top_k=1)

    def test_retrieve_returns_most_similar_rule(self, tmp_path: Path):
        rules = [_make_rule("3.1"), _make_rule("3.2")]
        dim = len(rules)
        embedder = _make_embedder_for_rules(rules)
        # Query vector best matches rule at index 1
        embedder.embed.return_value = _unit_vector(dim, 1)

        idx = LocalRuleIndex()
        idx.build(rules, embedder)
        results = idx.retrieve("some code", embedder=embedder, top_k=1)

        assert len(results) == 1
        assert results[0].id == "3.2"


# ---------------------------------------------------------------------------
# AzureSearchRuleIndex
# ---------------------------------------------------------------------------

class TestAzureSearchRuleIndex:
    def _make_idx(self):
        return AzureSearchRuleIndex(
            search_endpoint="https://test.search.windows.net",
            search_api_key="key",
            index_name="pci-test",
        )

    def test_build_calls_put_and_post(self, tmp_path: Path):
        rules = [_make_rule("4.1"), _make_rule("4.2")]
        embedder = MagicMock(spec=EmbeddingClient)
        # build() calls embed() for first rule, then embed_batch for the rest
        embedder.embed.return_value = [0.1, 0.2]
        embedder.embed_batch.return_value = [[0.3, 0.4]]

        idx = self._make_idx()
        meta_path = tmp_path / "meta.json"

        mock_response = MagicMock(status_code=200)
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.put.return_value = mock_response
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client), \
             patch("pci_auditor.ai.rule_index._AZURE_META_PATH", meta_path):
            idx.build(rules, embedder)

        mock_client.put.assert_called_once()   # index schema
        mock_client.post.assert_called_once()  # docs batch

    def test_retrieve_parses_search_response(self, tmp_path: Path):
        idx = self._make_idx()

        meta = {
            "5.1": {
                "id": "5.1",
                "requirement": "Requirement text",
                "severity": "HIGH",
                "category": "Test",
                "code_indicators": ["indicator"],
                "ai_prompt_hint": "Hint for 5.1",
            }
        }
        meta_path = tmp_path / "meta.json"
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        search_response = {"value": [{"id": "5-1", "@search.score": 0.9}]}

        embedder = MagicMock(spec=EmbeddingClient)
        embedder.embed.return_value = [0.1, 0.2]

        mock_response = MagicMock(status_code=200)
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = search_response
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client), \
             patch("pci_auditor.ai.rule_index._AZURE_META_PATH", meta_path):
            results = idx.retrieve("code snippet", embedder=embedder, top_k=1)

        assert len(results) == 1
        assert results[0].id == "5.1"


# ---------------------------------------------------------------------------
# RuleRetriever
# ---------------------------------------------------------------------------

class TestRuleRetriever:
    def test_retrieve_delegates_to_index(self):
        rule = _make_rule("6.1")
        mock_index = MagicMock()
        mock_index.retrieve.return_value = [rule]
        mock_embedder = MagicMock()

        retriever = RuleRetriever(
            index=mock_index,
            embedder=mock_embedder,
            all_rules=[rule],
            top_k=5,
        )
        results = retriever.retrieve("print('hello')")
        assert results == [rule]

    def test_retrieve_falls_back_to_all_rules_on_error(self):
        all_rules = [_make_rule("7.1"), _make_rule("7.2")]
        mock_index = MagicMock()
        mock_index.retrieve.side_effect = RuntimeError("index offline")
        mock_embedder = MagicMock()

        retriever = RuleRetriever(
            index=mock_index,
            embedder=mock_embedder,
            all_rules=all_rules,
            top_k=5,
        )
        results = retriever.retrieve("some code")
        assert results == all_rules


# ---------------------------------------------------------------------------
# build_retriever factory
# ---------------------------------------------------------------------------

class TestBuildRetriever:
    def _make_cfg(
        self,
        embedding_deployment: str = "text-embedding-3-small",
        endpoint: str = "https://test.openai.azure.com",
        api_key: str = "key",
    ):
        from pci_auditor.config import AuditorConfig
        return AuditorConfig(
            azure_openai_endpoint=endpoint,
            azure_openai_api_key=api_key,
            azure_openai_api_version="2024-02-01",
            azure_openai_deployment="gpt-4o",
            azure_openai_embedding_deployment=embedding_deployment,
            top_k_rules=8,
        )

    def test_returns_none_when_no_embedding_deployment(self):
        cfg = self._make_cfg(embedding_deployment="")
        result = build_retriever(cfg, [_make_rule("8.1")])
        assert result is None

    def test_returns_none_when_no_endpoint(self):
        cfg = self._make_cfg(endpoint="")
        result = build_retriever(cfg, [_make_rule("8.2")])
        assert result is None

    def test_returns_none_when_no_api_key(self):
        cfg = self._make_cfg(api_key="")
        result = build_retriever(cfg, [_make_rule("8.3")])
        assert result is None

    def test_returns_none_when_local_cache_missing(self):
        """No azure_search_endpoint → tries local index → load() returns False."""
        cfg = self._make_cfg()
        with patch("pci_auditor.ai.rule_index.LocalRuleIndex") as MockLocal, \
             patch("openai.AzureOpenAI"):
            instance = MagicMock()
            instance.load.return_value = False  # cache not built
            MockLocal.return_value = instance

            result = build_retriever(cfg, [_make_rule("8.4")])

        assert result is None

    def test_returns_retriever_when_local_cache_exists(self):
        cfg = self._make_cfg()
        with patch("pci_auditor.ai.rule_index.LocalRuleIndex") as MockLocal, \
             patch("openai.AzureOpenAI"):
            instance = MagicMock()
            instance.load.return_value = True   # cache exists
            MockLocal.return_value = instance

            result = build_retriever(cfg, [_make_rule("8.5")])

        assert isinstance(result, RuleRetriever)

