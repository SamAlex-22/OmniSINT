"""Centralized Pydantic v2 configuration for OmniSINT."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class OmniSINTSettings(BaseModel):
    """Application-wide settings loaded from environment variables or defaults."""

    model_config = ConfigDict(extra="ignore")

    app_name: str = Field(default_factory=lambda: os.getenv("OMNISINT_APP_NAME", "OmniSINT"))
    database_path: Path = Field(
        default_factory=lambda: Path(os.getenv("OMNISINT_DATABASE_PATH", ".omnisint_data/omnisint.db"))
    )
    cache_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("OMNISINT_CACHE_TTL_SECONDS", "86400")),
        ge=0,
    )
    http_timeout_seconds: float = Field(
        default_factory=lambda: float(os.getenv("OMNISINT_HTTP_TIMEOUT_SECONDS", "15.0")),
        gt=0.0,
    )
    max_concurrent_requests: int = Field(
        default_factory=lambda: int(os.getenv("OMNISINT_MAX_CONCURRENT_REQUESTS", "10")),
        ge=1,
        le=100,
    )
    user_agent: str = "OmniSINT/0.1.0 (+https://github.com/SamAlex-22/OmniSINT; Passive-OSINT-Research)"
    http_proxy: str | None = Field(default_factory=lambda: os.getenv("OMNISINT_HTTP_PROXY") or None)
    api_auth_token: str | None = Field(
        default_factory=lambda: os.getenv("OMNISINT_API_AUTH_TOKEN") or None
    )

    # Optional external API keys
    github_token: str | None = Field(default_factory=lambda: os.getenv("OMNISINT_GITHUB_TOKEN") or None)
    virustotal_api_key: str | None = Field(
        default_factory=lambda: os.getenv("OMNISINT_VIRUSTOTAL_API_KEY") or None
    )
    google_cse_api_key: str | None = Field(
        default_factory=lambda: os.getenv("OMNISINT_GOOGLE_CSE_API_KEY") or None
    )
    google_cse_cx: str | None = Field(default_factory=lambda: os.getenv("OMNISINT_GOOGLE_CSE_CX") or None)

    # AI Analyst settings
    llm_provider: Literal["deterministic", "ollama", "gemini", "openai"] = Field(
        default_factory=lambda: os.getenv("OMNISINT_LLM_PROVIDER", "deterministic")  # type: ignore[return-value]
    )
    llm_model: str = Field(default_factory=lambda: os.getenv("OMNISINT_LLM_MODEL", "gemini-2.5-flash"))
    llm_api_key: str | None = Field(default_factory=lambda: os.getenv("OMNISINT_LLM_API_KEY") or None)
    ollama_base_url: str = Field(
        default_factory=lambda: os.getenv("OMNISINT_OLLAMA_BASE_URL", "http://localhost:11434")
    )


def get_settings() -> OmniSINTSettings:
    """Return a fresh settings instance."""
    return OmniSINTSettings()
