from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELA_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./sentinela.db"
    redis_url: str = "redis://localhost:6379/0"
    execution_mode: str = "inline"

    ai_enabled: bool = True
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 180.0

    use_bandit: bool = True
    api_token: str | None = None
    github_token: str | None = None
    max_upload_mb: int = 20


@lru_cache
def get_settings() -> Settings:
    return Settings()
