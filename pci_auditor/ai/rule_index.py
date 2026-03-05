"""Semantic rule index for retrieving the most relevant PCI DSS rules per code chunk.

Two backends are supported:

* **LocalRuleIndex** – stores rule embeddings as a JSON file under
  ``~/.pci-auditor/rule_embeddings.json`` and ranks rules using
  cosine similarity (pure Python, no extra infrastructure required).

* **AzureSearchRuleIndex** – indexes rules in Azure AI Search using its
  vector search API (via httpx).  Requires ``AZURE_SEARCH_ENDPOINT`` and
  ``AZURE_SEARCH_API_KEY`` in the environment or config file.

The factory function :func:`build_retriever` chooses the right backend
based on the active :class:`~pci_auditor.config.AuditorConfig` and returns
a :class:`RuleRetriever` facade.  Returns ``None`` when semantic search is
not configured, in which case the scanner falls back to injecting all rules
into every AI prompt (the original behaviour).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Union

from pci_auditor.ai.rule_embedder import EmbeddingClient, cosine_similarity
from pci_auditor.rules.rule_loader import PciRule

if TYPE_CHECKING:
    from pci_auditor.config import AuditorConfig

logger = logging.getLogger(__name__)

_CACHE_PATH = Path.home() / ".pci-auditor" / "rule_embeddings.json"
_AZURE_META_PATH = Path.home() / ".pci-auditor" / "azure_search_rules_meta.json"
_AZURE_SEARCH_API_VERSION = "2024-07-01"


def _rule_embedding_text(rule: PciRule) -> str:
    """Canonical text used to generate a rule's embedding vector."""
    return f"Rule {rule.id}: {rule.requirement}. {rule.ai_prompt_hint}"


# ---------------------------------------------------------------------------
# Local backend
# ---------------------------------------------------------------------------

class LocalRuleIndex:
    """In-process cosine-similarity index backed by a JSON cache file.

    Build once with :meth:`build`, persist with :meth:`save`,
    reload on subsequent runs with :meth:`load`::

        idx = LocalRuleIndex()
        idx.build(rules, embedder)
        idx.save()

        # Later…
        idx = LocalRuleIndex()
        assert idx.load()
        relevant = idx.retrieve(code_snippet, embedder, top_k=8)
    """

    def __init__(self) -> None:
        self._rules: Dict[str, PciRule] = {}
        self._embeddings: Dict[str, List[float]] = {}

    def is_built(self) -> bool:
        return bool(self._embeddings)

    def build(self, rules: List[PciRule], embedder: EmbeddingClient) -> None:
        """Embed all rules and store vectors in memory."""
        texts = [_rule_embedding_text(r) for r in rules]
        vectors = embedder.embed_batch(texts)
        self._rules = {r.id: r for r in rules}
        self._embeddings = {r.id: vec for r, vec in zip(rules, vectors)}
        logger.info("Built local rule index with %d rule embeddings.", len(rules))

    def save(self, path: Path = _CACHE_PATH) -> None:
        """Persist embeddings and rule metadata to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "rules": {
                rid: {
                    "id": r.id,
                    "requirement": r.requirement,
                    "severity": r.severity,
                    "category": r.category,
                    "ai_prompt_hint": r.ai_prompt_hint,
                    "code_indicators": r.code_indicators,
                }
                for rid, r in self._rules.items()
            },
            "embeddings": self._embeddings,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        logger.info("Saved rule embeddings to %s", path)

    def load(self, path: Path = _CACHE_PATH) -> bool:
        """Load cached embeddings from disk.  Returns True on success."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._rules = {
                rid: PciRule.from_dict(rd)
                for rid, rd in data["rules"].items()
            }
            self._embeddings = data["embeddings"]
            logger.debug(
                "Loaded %d rule embeddings from %s", len(self._embeddings), path
            )
            return True
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            logger.warning("Could not load rule embeddings from %s: %s", path, exc)
            return False

    def retrieve(
        self,
        code_snippet: str,
        embedder: EmbeddingClient,
        top_k: int = 8,
    ) -> List[PciRule]:
        """Return the *top_k* most semantically relevant rules for *code_snippet*."""
        if not self._embeddings:
            raise RuntimeError("Index is empty — call build() or load() first.")

        query_vec = embedder.embed(code_snippet)
        scored = [
            (cosine_similarity(query_vec, vec), rule_id)
            for rule_id, vec in self._embeddings.items()
        ]
        scored.sort(reverse=True)

        return [
            self._rules[rule_id]
            for _, rule_id in scored[:top_k]
            if rule_id in self._rules
        ]


# ---------------------------------------------------------------------------
# Azure AI Search backend
# ---------------------------------------------------------------------------

class AzureSearchRuleIndex:
    """Azure AI Search vector-search backend (httpx REST, no extra SDK needed).

    Requires an Azure AI Search service (Basic tier or higher for vector
    search).  The index schema is created automatically on :meth:`build`.

    Rule IDs contain dots (e.g. ``"3.3.1"``); because Azure AI Search
    requires alphanumeric/hyphen keys, dots are replaced with hyphens when
    storing documents and reversed on retrieval.
    """

    def __init__(
        self,
        search_endpoint: str,
        search_api_key: str,
        index_name: str = "pci-rules",
        embedding_dimension: int = 1536,
    ) -> None:
        self._endpoint = search_endpoint.rstrip("/")
        self._key = search_api_key
        self._index_name = index_name
        self._dimension = embedding_dimension

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {"api-key": self._key, "Content-Type": "application/json"}

    def _index_url(self) -> str:
        return (
            f"{self._endpoint}/indexes/{self._index_name}"
            f"?api-version={_AZURE_SEARCH_API_VERSION}"
        )

    def _docs_index_url(self) -> str:
        return (
            f"{self._endpoint}/indexes/{self._index_name}/docs/index"
            f"?api-version={_AZURE_SEARCH_API_VERSION}"
        )

    def _docs_search_url(self) -> str:
        return (
            f"{self._endpoint}/indexes/{self._index_name}/docs/search"
            f"?api-version={_AZURE_SEARCH_API_VERSION}"
        )

    @staticmethod
    def _to_key(rule_id: str) -> str:
        """Convert rule ID to a valid Azure AI Search document key."""
        return rule_id.replace(".", "-")

    @staticmethod
    def _from_key(key: str) -> str:
        """Reverse _to_key for display and rule lookup."""
        return key.replace("-", ".")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, rules: List[PciRule], embedder: EmbeddingClient) -> None:
        """Create or update the Azure AI Search index and upload all rules.

        Detects the embedding dimension from the first rule's vector so
        you don't need to set it manually.
        """
        import httpx

        # Detect dimension from first embedding
        first_vec = embedder.embed(rules[0].requirement)
        self._dimension = len(first_vec)

        # Build/recreate the index schema
        schema = {
            "name": self._index_name,
            "fields": [
                {
                    "name": "id",
                    "type": "Edm.String",
                    "key": True,
                    "filterable": True,
                },
                {
                    "name": "requirement",
                    "type": "Edm.String",
                    "searchable": True,
                },
                {
                    "name": "severity",
                    "type": "Edm.String",
                    "filterable": True,
                },
                {
                    "name": "category",
                    "type": "Edm.String",
                    "filterable": True,
                },
                {"name": "ai_prompt_hint", "type": "Edm.String"},
                {
                    "name": "embedding",
                    "type": "Collection(Edm.Single)",
                    "dimensions": self._dimension,
                    "vectorSearchProfile": "pci-profile",
                },
            ],
            "vectorSearch": {
                "algorithms": [{"name": "pci-algo", "kind": "hnsw"}],
                "profiles": [
                    {
                        "name": "pci-profile",
                        "algorithm": "pci-algo",
                    }
                ],
            },
        }

        with httpx.Client(timeout=60) as client:
            resp = client.put(
                self._index_url(),
                headers=self._headers(),
                json=schema,
            )
            resp.raise_for_status()
            logger.info(
                "Azure AI Search index '%s' schema created/updated.",
                self._index_name,
            )

            # Upload in batches of 10 (Azure Search limit is 1000/batch,
            # but small batches are safer during development)
            batch_size = 10
            remaining_rules = list(rules)
            # Reuse already-computed first vector
            all_texts = [_rule_embedding_text(r) for r in remaining_rules]
            all_vecs = [first_vec] + embedder.embed_batch(
                [_rule_embedding_text(r) for r in remaining_rules[1:]]
            ) if len(remaining_rules) > 1 else [first_vec]

            for i in range(0, len(remaining_rules), batch_size):
                batch_rules = remaining_rules[i : i + batch_size]
                batch_vecs = all_vecs[i : i + batch_size]
                docs = [
                    {
                        "@search.action": "mergeOrUpload",
                        "id": self._to_key(rule.id),
                        "requirement": rule.requirement,
                        "severity": rule.severity,
                        "category": rule.category,
                        "ai_prompt_hint": rule.ai_prompt_hint,
                        "embedding": vec,
                    }
                    for rule, vec in zip(batch_rules, batch_vecs)
                ]
                resp = client.post(
                    self._docs_index_url(),
                    headers=self._headers(),
                    json={"value": docs},
                )
                resp.raise_for_status()
                logger.info(
                    "Uploaded batch of %d rules to Azure AI Search.", len(docs)
                )

        # Persist rule metadata locally so code_indicators are available
        # after retrieval (Azure Search doesn't store them as a field)
        _AZURE_META_PATH.parent.mkdir(parents=True, exist_ok=True)
        rule_meta = {
            r.id: {
                "id": r.id,
                "requirement": r.requirement,
                "severity": r.severity,
                "category": r.category,
                "ai_prompt_hint": r.ai_prompt_hint,
                "code_indicators": r.code_indicators,
            }
            for r in rules
        }
        _AZURE_META_PATH.write_text(json.dumps(rule_meta), encoding="utf-8")
        logger.info("Saved Azure Search rule metadata to %s", _AZURE_META_PATH)

    def _load_rule_meta(self) -> Dict[str, PciRule]:
        if not _AZURE_META_PATH.exists():
            return {}
        try:
            data = json.loads(_AZURE_META_PATH.read_text(encoding="utf-8"))
            return {rid: PciRule.from_dict(rd) for rid, rd in data.items()}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load Azure Search rule metadata: %s", exc)
            return {}

    def retrieve(
        self,
        code_snippet: str,
        embedder: EmbeddingClient,
        top_k: int = 8,
    ) -> List[PciRule]:
        """Query Azure AI Search with a vector query and return matching rules."""
        import httpx

        query_vec = embedder.embed(code_snippet)
        rule_meta = self._load_rule_meta()

        payload = {
            "vectorQueries": [
                {
                    "kind": "vector",
                    "vector": query_vec,
                    "fields": "embedding",
                    "k": top_k,
                }
            ],
            "select": "id,requirement,severity,category,ai_prompt_hint",
            "top": top_k,
        }

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                self._docs_search_url(),
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            hits = resp.json().get("value", [])

        results: List[PciRule] = []
        for hit in hits:
            raw_id = self._from_key(hit.get("id", ""))
            # Prefer local meta (has code_indicators); fall back to hit fields
            rule = rule_meta.get(raw_id)
            if rule is None:
                rule = PciRule(
                    id=raw_id,
                    requirement=hit.get("requirement", ""),
                    severity=hit.get("severity", "medium"),
                    category=hit.get("category", ""),
                    ai_prompt_hint=hit.get("ai_prompt_hint", ""),
                )
            results.append(rule)

        return results


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------

class RuleRetriever:
    """High-level facade: wraps a backend + embedder and provides a single
    ``retrieve(code_snippet) -> List[PciRule]`` call.

    Falls back to returning *all_rules* if the underlying index call fails,
    so scanning always completes even when the vector service is unreachable.
    """

    def __init__(
        self,
        index: Union[LocalRuleIndex, AzureSearchRuleIndex],
        embedder: EmbeddingClient,
        all_rules: List[PciRule],
        top_k: int = 8,
    ) -> None:
        self._index = index
        self._embedder = embedder
        self._all_rules = all_rules
        self._top_k = top_k

    def retrieve(self, code_snippet: str) -> List[PciRule]:
        """Return the top-K relevant rules for *code_snippet*.

        On any error, logs a warning and returns all rules as fallback.
        """
        try:
            return self._index.retrieve(
                code_snippet, self._embedder, self._top_k
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Semantic rule retrieval failed (%s); "
                "falling back to all %d rules.",
                exc,
                len(self._all_rules),
            )
            return self._all_rules


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_retriever(
    cfg: "AuditorConfig",
    all_rules: List[PciRule],
) -> Optional[RuleRetriever]:
    """Build a :class:`RuleRetriever` from config, or return ``None``.

    Returns ``None`` (falling back to full-rule injection) when:

    * ``azure_openai_embedding_deployment`` is not set in config/env, OR
    * Azure OpenAI credentials are missing, OR
    * The local index cache doesn't exist (user hasn't run ``rules index-build``).

    When ``AZURE_SEARCH_ENDPOINT`` and ``AZURE_SEARCH_API_KEY`` are set the
    Azure AI Search backend is used; otherwise the local cosine-similarity
    backend is used.
    """
    if not getattr(cfg, "azure_openai_embedding_deployment", ""):
        return None
    # Determine which endpoint/key to use for embeddings.
    # AZURE_OPENAI_EMBEDDING_ENDPOINT / AZURE_OPENAI_EMBEDDING_API_KEY are
    # optional overrides; when absent the main resource credentials are used.
    embedding_endpoint = (
        getattr(cfg, "azure_openai_embedding_endpoint", "") or cfg.azure_openai_endpoint
    )
    embedding_api_key = (
        getattr(cfg, "azure_openai_embedding_api_key", "") or cfg.azure_openai_api_key
    )

    if not embedding_endpoint or not embedding_api_key:
        return None

    try:
        embedder = EmbeddingClient(
            endpoint=embedding_endpoint,
            api_key=embedding_api_key,
            deployment=cfg.azure_openai_embedding_deployment,
            api_version=cfg.azure_openai_api_version,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not create EmbeddingClient: %s", exc)
        return None

    if getattr(cfg, "azure_search_endpoint", "") and getattr(
        cfg, "azure_search_api_key", ""
    ):
        index: Union[LocalRuleIndex, AzureSearchRuleIndex] = AzureSearchRuleIndex(
            search_endpoint=cfg.azure_search_endpoint,
            search_api_key=cfg.azure_search_api_key,
            index_name=getattr(cfg, "azure_search_index_name", "pci-rules"),
        )
    else:
        local = LocalRuleIndex()
        if not local.load():
            logger.info(
                "No local rule embeddings found. "
                "Run 'pci-auditor rules index-build' to build the semantic index."
            )
            return None
        index = local

    return RuleRetriever(
        index=index,
        embedder=embedder,
        all_rules=all_rules,
        top_k=getattr(cfg, "top_k_rules", 8),
    )
