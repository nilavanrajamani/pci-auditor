"""Azure OpenAI Embeddings client and cosine similarity utility."""

from __future__ import annotations

import logging
import math
from typing import List

logger = logging.getLogger(__name__)

# Truncate text to this many characters before embedding.
# text-embedding-3-small / ada-002 token limit ~8192 tokens ≈ ~32k chars,
# but 2000 chars is plenty for a code chunk and keeps costs low.
_EMBED_CHAR_LIMIT = 2000


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Pure-Python cosine similarity between two equal-length float vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _truncate(text: str) -> str:
    return text[:_EMBED_CHAR_LIMIT].replace("\n", " ")


class EmbeddingClient:
    """Thin wrapper around the Azure OpenAI Embeddings API.

    Use ``embed`` for single texts and ``embed_batch`` for multiple texts
    (uses a single API call, which is more efficient and cheaper).

    Example::

        client = EmbeddingClient(
            endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            deployment="text-embedding-3-small",
        )
        vec = client.embed("SELECT * FROM cards")
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str = "2024-02-01",
    ) -> None:
        if not endpoint or not api_key or not deployment:
            raise ValueError(
                "Azure OpenAI endpoint, API key and embedding deployment name "
                "are all required. Set AZURE_OPENAI_ENDPOINT, "
                "AZURE_OPENAI_API_KEY, and AZURE_OPENAI_EMBEDDING_DEPLOYMENT."
            )
        try:
            from openai import AzureOpenAI  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required. Install with: pip install openai"
            ) from exc

        self._client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
        self._deployment = deployment

    def embed(self, text: str) -> List[float]:
        """Embed a single text string, returning a float vector."""
        try:
            response = self._client.embeddings.create(
                input=_truncate(text),
                model=self._deployment,
            )
            return response.data[0].embedding
        except Exception as exc:
            logger.warning("Embedding request failed for text: %s", exc)
            raise

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple texts in a single API call.

        Falls back to sequential individual calls on failure.
        """
        cleaned = [_truncate(t) for t in texts]
        try:
            response = self._client.embeddings.create(
                input=cleaned,
                model=self._deployment,
            )
            # Sort by .index so order matches the input list
            ordered = sorted(response.data, key=lambda d: d.index)
            return [d.embedding for d in ordered]
        except Exception as exc:
            logger.warning(
                "Batch embedding failed (%s); falling back to individual calls.", exc
            )
            return [self.embed(t) for t in cleaned]
