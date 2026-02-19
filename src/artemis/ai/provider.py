"""AI provider interface and implementations.

Every AI-powered feature goes through this layer. When provider is "none",
all methods return graceful fallbacks so Artemis works without any AI.
"""

from __future__ import annotations

import abc
import logging
from typing import Any

import httpx

from artemis.core.config import AIConfig

logger = logging.getLogger("artemis.ai")


class AIProvider(abc.ABC):
    """Base class for AI providers."""

    @abc.abstractmethod
    async def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        """Generate a text completion."""

    @abc.abstractmethod
    async def analyze(self, data: dict[str, Any], task: str) -> dict[str, Any]:
        """Structured analysis — returns parsed JSON response."""

    async def health_check(self) -> bool:
        """Check if the provider is reachable."""
        try:
            result = await self.generate("ping", system="Reply with just 'pong'.")
            return "pong" in result.lower()
        except Exception:
            return False


class OllamaProvider(AIProvider):
    """Local Ollama inference."""

    def __init__(self, config: AIConfig) -> None:
        self.model = config.model
        self.base_url = config.base_url.rstrip("/")
        self.timeout = config.timeout_seconds
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

    async def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        resp = await self._client.post("/api/generate", json={
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": temperature},
        })
        resp.raise_for_status()
        return resp.json()["response"]

    async def analyze(self, data: dict[str, Any], task: str) -> dict[str, Any]:
        import json
        prompt = f"Task: {task}\n\nData:\n```json\n{json.dumps(data, indent=2)}\n```\n\nRespond with valid JSON only."
        raw = await self.generate(prompt, system="You are a security analyst. Respond only with valid JSON.")
        # Strip markdown fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            raw = raw.rsplit("```", 1)[0]
        return json.loads(raw)


class OpenAIProvider(AIProvider):
    """OpenAI-compatible API (works with OpenAI, Azure, any compatible endpoint)."""

    def __init__(self, config: AIConfig) -> None:
        self.model = config.model
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout_seconds,
        )

    async def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = await self._client.post("/v1/chat/completions", json={
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        })
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def analyze(self, data: dict[str, Any], task: str) -> dict[str, Any]:
        import json
        prompt = f"Task: {task}\n\nData:\n```json\n{json.dumps(data, indent=2)}\n```\n\nRespond with valid JSON only."
        raw = await self.generate(prompt, system="You are a security analyst. Respond only with valid JSON.")
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            raw = raw.rsplit("```", 1)[0]
        return json.loads(raw)


class NullProvider(AIProvider):
    """No-AI fallback. All features degrade gracefully."""

    async def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        return "[AI disabled] No analysis available."

    async def analyze(self, data: dict[str, Any], task: str) -> dict[str, Any]:
        return {"status": "ai_disabled", "message": "AI provider not configured."}

    async def health_check(self) -> bool:
        return True  # Always "healthy" — it just does nothing


def create_provider(config: AIConfig) -> AIProvider:
    """Factory — create the right provider based on config."""
    providers = {
        "ollama": OllamaProvider,
        "openai": OpenAIProvider,
        "none": NullProvider,
    }
    cls = providers.get(config.provider)
    if cls is None:
        logger.warning("Unknown AI provider '%s', falling back to none", config.provider)
        return NullProvider(config)
    return cls(config)
