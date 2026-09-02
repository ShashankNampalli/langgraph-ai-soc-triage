"""Tests for LLM provider configuration."""

import os

import pytest

from src.llm import get_llm_provider, is_offline_mode


def test_default_provider_is_deepseek(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert get_llm_provider() == "deepseek"


def test_ollama_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    assert get_llm_provider() == "ollama"


def test_invalid_provider_raises(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "invalid")
    with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
        get_llm_provider()


def test_offline_mode_enabled(monkeypatch):
    monkeypatch.setenv("OFFLINE_MODE", "true")
    assert is_offline_mode() is True


def test_deepseek_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "deepseek")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    from src.llm import get_llm

    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        get_llm()
