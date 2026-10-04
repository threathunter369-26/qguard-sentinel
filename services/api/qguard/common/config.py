"""Typed application configuration.

Every setting is sourced from the environment (see `.env.example`). Settings are
validated at import time so a misconfigured deployment fails fast and loudly
instead of silently degrading security controls.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
AuthProvider = Literal["local", "supabase"]
StorageBackend = Literal["local", "supabase", "s3"]
SandboxMode = Literal["subprocess", "docker", "none"]


def _split_csv(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item.strip() for item in value if str(item).strip()]
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    """Root configuration object. Instantiated once via :func:`get_settings`."""

    model_config = SettingsConfigDict(
        env_prefix="QG_",
        env_file=(".env", "../.env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ----------------------------------------------------------------- runtime
    env: Environment = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    instance_name: str = "qguard-local"

    # ---------------------------------------------------------------- database
    database_url: str = "postgresql://qguard:qguard@localhost:5432/qguard"
    database_replica_url: str | None = None
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_echo: bool = False
    database_statement_timeout_ms: int = 30_000

    # ---------------------------------------------------------------- supabase
    auth_provider: AuthProvider = "local"
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    supabase_service_role_key: str | None = None
    supabase_jwt_secret: str | None = None
    supabase_jwks_url: str | None = None
    supabase_jwt_audience: str = "authenticated"
    supabase_storage_bucket: str = "qguard-evidence"

    # ------------------------------------------------------- local auth/tokens
    jwt_secret: str = Field(default="")
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 1_209_600
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_seconds: int = 900
    mfa_issuer: str = "QGuard Sentinel"
    encryption_key: str | None = None

    # ---------------------------------------------------------------- http/api
    api_host: str = "0.0.0.0"  # noqa: S104 - container deployments bind all interfaces
    api_port: int = 8000
    api_root_path: str = ""
    public_api_url: str = "http://localhost:8000"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    trusted_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    secure_cookies: bool = False
    cookie_domain: str | None = None
    rate_limit_enabled: bool = True
    rate_limit_default: str = "300/minute"
    rate_limit_auth: str = "10/minute"
    max_upload_bytes: int = 2_147_483_648
    request_timeout_seconds: int = 60

    # ----------------------------------------------------------------- storage
    storage_backend: StorageBackend = "local"
    storage_local_root: str = "./var/storage"
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_region: str | None = None
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None

    # ----------------------------------------------------------------- workers
    worker_concurrency: int = 4
    worker_poll_interval_seconds: float = 2.0
    worker_heartbeat_seconds: int = 15
    job_max_attempts: int = 3
    job_lease_seconds: int = 900
    job_retention_days: int = 90
    sandbox_mode: SandboxMode = "subprocess"
    sandbox_cpu_seconds: int = 120
    sandbox_memory_mb: int = 2048
    sandbox_max_output_bytes: int = 16_777_216
    sandbox_docker_image: str = "qguard/sandbox:latest"

    # ------------------------------------------------------- scanning guardrails
    active_scan_enabled: bool = True
    allow_private_network_targets: bool = True
    scan_deny_networks: list[str] = Field(
        default_factory=lambda: ["169.254.0.0/16", "::1/128", "fc00::/7"]
    )
    scan_max_requests_per_second: float = 10.0
    scan_max_concurrency: int = 8
    scan_user_agent: str = "QGuardSentinel/1.0 (authorized security assessment)"
    scan_http_timeout_seconds: float = 15.0
    scan_max_crawl_pages: int = 250

    # ------------------------------------------------- vulnerability intelligence
    osv_api_url: str = "https://api.osv.dev/v1"
    osv_enabled: bool = True
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    cve_cache_ttl_hours: int = 24
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    threat_intel_outbound_enabled: bool = False

    # ----------------------------------------------------------- observability
    metrics_enabled: bool = True
    otel_exporter_otlp_endpoint: str | None = None
    sentry_dsn: str | None = None

    # ---------------------------------------------------------------- dev seed
    seed_demo_data: bool = False
    seed_admin_email: str = "admin@qguard.local"
    seed_admin_password: str | None = None

    # --------------------------------------------------------------- validators
    @field_validator("cors_origins", "trusted_hosts", "scan_deny_networks", mode="before")
    @classmethod
    def _parse_csv_lists(cls, value: object) -> list[str]:
        return _split_csv(value)  # type: ignore[arg-type]

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return upper

    @field_validator("scan_deny_networks")
    @classmethod
    def _validate_networks(cls, value: list[str]) -> list[str]:
        for net in value:
            ipaddress.ip_network(net, strict=False)
        return value

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Settings:
        # A development instance may auto-generate ephemeral token material so
        # `uvicorn` starts with zero configuration. Production never may.
        if not self.jwt_secret:
            if self.env in ("development", "test"):
                self.jwt_secret = secrets.token_hex(32)
            else:
                raise ValueError("QG_JWT_SECRET is required when QG_ENV is staging or production")

        if self.env == "production":
            problems: list[str] = []
            if self.debug:
                problems.append("QG_DEBUG must be false in production")
            if self.jwt_secret.startswith("change-me") or len(self.jwt_secret) < 32:
                problems.append("QG_JWT_SECRET must be a strong value of at least 32 characters")
            if not self.secure_cookies:
                problems.append("QG_SECURE_COOKIES must be true in production")
            if self.sandbox_mode == "none":
                problems.append("QG_SANDBOX_MODE=none is not permitted in production")
            if "*" in self.cors_origins:
                problems.append("QG_CORS_ORIGINS must not be a wildcard in production")
            if self.seed_demo_data:
                problems.append("QG_SEED_DEMO_DATA must be false in production")
            if not self.encryption_key:
                problems.append("QG_ENCRYPTION_KEY is required in production")
            if self.auth_provider == "supabase" and not (
                self.supabase_jwt_secret or self.supabase_jwks_url
            ):
                problems.append(
                    "Supabase auth requires QG_SUPABASE_JWT_SECRET or QG_SUPABASE_JWKS_URL"
                )
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))

        if self.auth_provider == "supabase" and not self.supabase_url:
            raise ValueError("QG_SUPABASE_URL is required when QG_AUTH_PROVIDER=supabase")

        return self

    # ------------------------------------------------------------- computed
    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def async_database_url(self) -> str:
        """DSN with the asyncpg driver, regardless of how it was supplied."""
        return _with_driver(self.database_url, "postgresql+asyncpg")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sync_database_url(self) -> str:
        """DSN with a synchronous driver, used by Alembic and the CLI."""
        return _with_driver(self.database_url, "postgresql+psycopg")

    @property
    def deny_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n, strict=False) for n in self.scan_deny_networks]


def _with_driver(dsn: str, driver: str) -> str:
    if "://" not in dsn:
        raise ValueError(f"Malformed database URL: {dsn!r}")
    _, _, remainder = dsn.partition("://")
    return f"{driver}://{remainder}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the settings cache. Only used by tests that mutate the environment."""
    get_settings.cache_clear()


def running_under_pytest() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ
