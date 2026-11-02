"""Application settings, loaded from environment variables (prefix ``TW_``) and ``.env``."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TW_", env_file=".env", extra="ignore")

    # Core
    database_url: str = "sqlite:///./data/threatwatch.db"
    host: str = "127.0.0.1"
    port: int = 8000
    api_key: str | None = None
    log_level: str = "INFO"
    data_dir: str = "./data"  # runtime data (synced ATT&CK catalogue, ...)

    # Outbound HTTP
    user_agent: str = "Mozilla/5.0 (compatible; ThreatWatch/1.0; +https://github.com/threatwatch)"
    http_timeout: float = 20.0
    http_proxy: str | None = None
    tor_proxy: str | None = None
    onion_sources: str = ""

    # Dark web / leak integrations
    hibp_api_key: str | None = None
    intelx_api_key: str | None = None
    intelx_api_url: str = "https://free.intelx.io"
    github_token: str | None = None

    # Threat intel feeds
    abusech_auth_key: str | None = None
    otx_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    feed_max_items: int = 20000
    ioc_retention_days: int = 90

    # Scheduler
    scheduler_enabled: bool = True
    feeds_interval_minutes: int = 60
    darkweb_interval_hours: int = 24
    phishing_interval_hours: int = 24
    asm_interval_hours: int = 0

    # Alerting
    alert_min_severity: str = "medium"
    alert_webhook_url: str | None = None

    # Anti-phishing
    phishing_max_permutations: int = 1500

    # ASM
    asm_active_default: bool = False
    asm_max_hosts: int = 150
    asm_concurrency: int = 200

    @property
    def onion_source_list(self) -> list[str]:
        return [s.strip() for s in self.onion_sources.split(",") if s.strip()]

    def integration_status(self) -> dict[str, bool]:
        """Which optional integrations have credentials configured (never exposes values)."""
        return {
            "hibp": bool(self.hibp_api_key),
            "intelx": bool(self.intelx_api_key),
            "github": bool(self.github_token),
            "abusech": bool(self.abusech_auth_key),
            "otx": bool(self.otx_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
            "tor": bool(self.tor_proxy),
            "webhook": bool(self.alert_webhook_url),
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
