"""LLM factory — DeepSeek API (default), Ollama fallback, offline mock for tests."""

from __future__ import annotations

import os
from typing import Any, Literal

from dotenv import load_dotenv

load_dotenv()

LLMProvider = Literal["deepseek", "ollama"]


def is_offline_mode() -> bool:
    """Return True when agents should use deterministic mock outputs."""
    return os.getenv("OFFLINE_MODE", "false").lower() in ("true", "1", "yes")


def get_llm_provider() -> LLMProvider:
    provider = os.getenv("LLM_PROVIDER", "deepseek").lower()
    if provider not in ("deepseek", "ollama"):
        raise ValueError(
            f"Unsupported LLM_PROVIDER '{provider}'. Use 'deepseek' or 'ollama'."
        )
    return provider  # type: ignore[return-value]


def _get_deepseek_llm(temperature: float) -> Any:
    from langchain_openai import ChatOpenAI

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError(
            "DEEPSEEK_API_KEY is required when LLM_PROVIDER=deepseek. "
            "Get a key at https://platform.deepseek.com"
        )

    return ChatOpenAI(
        model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key=api_key,
        base_url=os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com"),
        temperature=temperature,
    )


def _get_ollama_llm(temperature: float) -> Any:
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "qwen2.5:7b"),
        temperature=temperature,
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    )


def get_llm(temperature: float = 0.1) -> Any:
    """Return the configured LangChain chat model."""
    provider = get_llm_provider()
    if provider == "deepseek":
        return _get_deepseek_llm(temperature)
    return _get_ollama_llm(temperature)


def structured_output(llm: Any, schema: type) -> Any:
    """Wrap LLM for Pydantic output — DeepSeek needs function_calling, not json_schema."""
    if get_llm_provider() == "deepseek":
        return llm.with_structured_output(schema, method="function_calling")
    return llm.with_structured_output(schema)


def get_langfuse_callbacks() -> list:
    """Return Langfuse callback handlers when configured."""
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    if not public_key or not secret_key:
        return []

    try:
        from langfuse.callback import CallbackHandler

        handler = CallbackHandler(
            public_key=public_key,
            secret_key=secret_key,
            host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
        return [handler]
    except ImportError:
        return []
