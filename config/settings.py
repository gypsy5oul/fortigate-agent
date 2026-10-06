"""Application settings for FortiGate Firewall Intelligence Service."""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql://forti_intel:forti_secret_pw_2026@localhost:5432/forti_intelligence",
        description="Async PostgreSQL connection string",
    )
    sqlite_db_path: Optional[str] = Field(
        default=None,
        description="Optional SQLite file path for local unit tests when PostgreSQL is offline",
    )

    # Loki Ingestion Gateway
    loki_base_url: str = Field(
        default="https://loki-readonly.6dcorp.internal/loki/api/v1/query_range",
        description="Loki query_range URL",
    )
    loki_user: Optional[str] = Field(default=None, description="HTTP Basic auth user")
    loki_password: Optional[str] = Field(default=None, description="HTTP Basic auth password")
    loki_bearer_token: Optional[str] = Field(default=None, description="HTTP Bearer token if used")
    loki_tenant_id: Optional[str] = Field(default=None, description="X-Scope-OrgID tenant header")
    loki_selector: str = Field(
        default='{service_name="forticlient"}',
        description="LogQL stream selector",
    )
    loki_tls_verify: bool = Field(default=True, description="Verify TLS certificates")
    loki_query_timeout_seconds: float = Field(default=15.0, description="HTTP query deadline")
    loki_poll_interval_seconds: float = Field(default=15.0, description="Polling loop cycle interval")
    loki_replay_overlap_seconds: int = Field(default=120, description="Overlap lookback for late arrival recovery")
    loki_slice_seconds: int = Field(default=30, description="Query interval step size")
    loki_max_entries_per_query: int = Field(default=1000, description="Max lines per Loki query")

    # Local Qwen Model
    llm_enabled: bool = Field(default=True, description="Enable local LLM investigation agent")
    llm_base_url: str = Field(
        default="http://10.0.6.31:8000/v1",
        description="Local vLLM / OpenAI-compatible endpoint",
    )
    llm_model: str = Field(default="qwen3.8-27b", description="Model identifier in serving runtime")
    llm_api_key: str = Field(default="EMPTY", description="API key (EMPTY for local vLLM)")
    llm_timeout_seconds: float = Field(default=60.0, description="Max timeout per LLM inference call")
    llm_max_input_tokens: int = Field(default=12000, description="Max input prompt token budget")
    llm_max_output_tokens: int = Field(default=1500, description="Max completion token budget")

    # Google Chat
    gchat_webhook_url: Optional[str] = Field(default=None, description="Google Chat webhook incoming URL")
    gchat_dry_run: bool = Field(default=True, description="When True, logs cards without making HTTP calls")
    gchat_rate_limit_delay_seconds: float = Field(default=2.0, description="Delay between consecutive outbox deliveries")
    gchat_thread_by_incident: bool = Field(default=True, description="Group incident revisions under the same thread")

    # Grafana Links
    grafana_base_url: str = Field(
        default="https://grafana.6dcorp.internal",
        description="Base URL for drill-down explore links",
    )
    grafana_datasource_uid: str = Field(default="loki", description="Loki datasource UID in Grafana")

    # Metrics & Logging
    log_level: str = Field(default="INFO", description="Application log level")
    metrics_port: int = Field(default=8000, description="HTTP port for metrics and health checks")


def get_settings() -> Settings:
    return Settings()
