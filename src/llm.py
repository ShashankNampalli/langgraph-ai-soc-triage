"""LLM factory — DeepSeek API (default), Ollama fallback, offline mock for tests."""

from __future__ import annotations

from typing import Any, Literal

from .config import get_setting

LLMProvider = Literal["deepseek", "ollama"]


def is_offline_mode() -> bool:
    """Return True when agents should use deterministic mock outputs."""
    return (get_setting("OFFLINE_MODE", "false") or "false").lower() in (
        "true",
        "1",
        "yes",
    )


def get_llm_provider() -> LLMProvider:
    provider = (get_setting("LLM_PROVIDER", "deepseek") or "deepseek").lower()
    if provider not in ("deepseek", "ollama"):
        raise ValueError(
            f"Unsupported LLM_PROVIDER '{provider}'. Use 'deepseek' or 'ollama'."
        )
    return provider  # type: ignore[return-value]


def _get_deepseek_llm(temperature: float) -> Any:
    from langchain_openai import ChatOpenAI

    api_key = get_setting("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError(
            "DEEPSEEK_API_KEY is not set. Use a .env file, environment variable, "
            "or Streamlit secrets (.streamlit/secrets.toml / Cloud Secrets)."
        )

    base_url = (
        get_setting("DEEPSEEK_API_BASE")
        or get_setting("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        or "https://api.deepseek.com"
    )
    model = get_setting("DEEPSEEK_MODEL", "deepseek-chat") or "deepseek-chat"

    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
    )


def _get_ollama_llm(temperature: float) -> Any:
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=get_setting("OLLAMA_MODEL", "qwen2.5:7b") or "qwen2.5:7b",
        temperature=temperature,
        base_url=get_setting("OLLAMA_BASE_URL", "http://localhost:11434")
        or "http://localhost:11434",
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
    public_key = get_setting("LANGFUSE_PUBLIC_KEY")
    secret_key = get_setting("LANGFUSE_SECRET_KEY")
    if not public_key or not secret_key:
        return []

    try:
        from langfuse.callback import CallbackHandler

        handler = CallbackHandler(
            public_key=public_key,
            secret_key=secret_key,
            host=get_setting("LANGFUSE_HOST", "https://cloud.langfuse.com")
            or "https://cloud.langfuse.com",
        )
        return [handler]
    except ImportError:
        return []
