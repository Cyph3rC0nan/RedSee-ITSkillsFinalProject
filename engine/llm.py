# engine/llm.py
"""
BYOK LLM layer — Layer 3 of the RedSee agent engine (the pluggable "brain" wire).

Provider-agnostic client for an OpenAI-compatible /chat/completions endpoint.
Works with a paid OpenAI-compatible provider, a local Ollama server (no key),
and any other provider that speaks the same shape.

This layer has no opinion about agents or vulnerabilities: it sends messages
(with optional tool/function definitions), returns a normalized reply, tracks
token usage, and enforces a hard per-scan budget cap. Fail-closed: missing or
invalid config raises a clear LLMError — it never silently falls back to a
default provider.
"""

import os

import requests

from dataclasses import dataclass


@dataclass
class LLMConfig:
    base_url: str
    model: str
    api_key: str | None = None
    max_usd: float = 1.00
    price_in_per_1k: float = 0.0
    price_out_per_1k: float = 0.0
    timeout_sec: int = 120


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0


class LLMError(Exception):
    """Raised on missing/invalid LLM config or a request/network/protocol failure."""
    pass


class BudgetExceededError(LLMError):
    """Raised when the per-scan budget cap has already been reached."""
    pass


def load_llm_config() -> LLMConfig:
    """Load an LLMConfig from environment variables. Fail-closed: a missing
    base_url or model raises LLMError rather than defaulting to a provider."""
    base_url = os.environ.get("REDSEE_LLM_BASE_URL", "").strip()
    model = os.environ.get("REDSEE_LLM_MODEL", "").strip()
    if not base_url or not model:
        raise LLMError(
            "LLM not configured: set REDSEE_LLM_BASE_URL and REDSEE_LLM_MODEL "
            "(e.g. an OpenAI-compatible endpoint or a local Ollama /v1 URL)."
        )

    api_key = os.environ.get("REDSEE_LLM_API_KEY", "").strip() or None

    def _float_env(name: str, default: str) -> float:
        raw = os.environ.get(name, default).strip()
        try:
            return float(raw)
        except ValueError:
            raise LLMError(f"Invalid numeric value for {name}: {raw!r}")

    def _int_env(name: str, default: str) -> int:
        raw = os.environ.get(name, default).strip()
        try:
            return int(raw)
        except ValueError:
            raise LLMError(f"Invalid integer value for {name}: {raw!r}")

    return LLMConfig(
        base_url=base_url.rstrip("/"),
        model=model,
        api_key=api_key,
        max_usd=_float_env("REDSEE_LLM_MAX_USD", "1.00"),
        price_in_per_1k=_float_env("REDSEE_LLM_PRICE_IN_PER_1K", "0.0"),
        price_out_per_1k=_float_env("REDSEE_LLM_PRICE_OUT_PER_1K", "0.0"),
        timeout_sec=_int_env("REDSEE_LLM_TIMEOUT", "120"),
    )


def _estimate_tokens(text: str) -> int:
    """Rough char/4 fallback estimate for providers that omit usage (e.g. Ollama)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


class BudgetTracker:
    """Per-scan accumulator. Create one instance per scan and share it across
    every LLMClient.chat() call made during that scan."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.usage = Usage()

    def remaining_usd(self) -> float:
        return self.config.max_usd - self.usage.cost_usd

    def check_before_call(self) -> None:
        if self.remaining_usd() <= 0:
            raise BudgetExceededError(
                f"LLM budget exhausted: ${self.usage.cost_usd:.4f} spent of "
                f"${self.config.max_usd:.4f} cap. Refusing to make another call."
            )

    def record(self, input_tokens: int, output_tokens: int) -> None:
        cost = (input_tokens / 1000.0) * self.config.price_in_per_1k \
            + (output_tokens / 1000.0) * self.config.price_out_per_1k
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens
        self.usage.cost_usd += cost
        self.usage.calls += 1


class LLMClient:
    """Thin provider-agnostic chat-completions client bound to a BudgetTracker."""

    def __init__(self, config: LLMConfig, tracker: BudgetTracker):
        self.config = config
        self.tracker = tracker

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             max_tokens: int = 1024) -> dict:
        """Send messages (and optional tool defs) to the configured endpoint.

        Returns {"text": str, "tool_calls": list, "raw": <provider json>}.
        Raises BudgetExceededError (no HTTP call made) if the cap is already
        reached, or LLMError on any request/network/protocol failure.
        """
        # Budget gate first — refuse before spending any network time.
        self.tracker.check_before_call()

        body = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        url = f"{self.config.base_url}/chat/completions"

        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=self.config.timeout_sec
            )
        except requests.exceptions.RequestException as exc:
            raise LLMError(f"LLM request to {self.config.base_url} failed: {exc}") from exc

        if response.status_code != 200:
            raise LLMError(
                f"LLM endpoint returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise LLMError(f"LLM endpoint returned invalid JSON: {exc}") from exc

        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected LLM response shape: {exc}") from exc

        text = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        usage = data.get("usage") or {}
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")
        if input_tokens is None:
            input_tokens = _estimate_tokens(
                " ".join(m.get("content", "") or "" for m in messages)
            )
        if output_tokens is None:
            output_tokens = _estimate_tokens(text)

        self.tracker.record(input_tokens, output_tokens)

        return {"text": text, "tool_calls": tool_calls, "raw": data}
