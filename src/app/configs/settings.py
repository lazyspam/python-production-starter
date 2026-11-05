from functools import lru_cache
from typing import Annotated, Literal

from cryptography.fernet import Fernet
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

CsvList = Annotated[list[str], NoDecode]
PLACEHOLDERS = ("replace-with", "changeme", "example", "password")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "python-production-starter"
    environment: Literal["development", "production", "test"] = "development"
    port: int = 3000
    backend_url: str = "http://localhost:3000"
    frontend_url: str = "http://localhost:5173"
    rate_limit_ttl: int = 60
    rate_limit_limit: int = 100

    database_url: str
    database_pool_size: int = 10

    redis_url: str
    redis_key_prefix: str = "app:"

    jwt_access_secret: str = Field(min_length=32)
    jwt_access_ttl_seconds: int = 15 * 60
    jwt_refresh_secret: str = Field(min_length=32)
    jwt_refresh_ttl_seconds: int = 30 * 24 * 3600
    auth_cookie_domain: str | None = None
    auth_cookie_same_site: Literal["lax", "strict", "none"] = "lax"
    auth_encryption_key: str

    totp_issuer: str = "PythonProductionStarter"
    totp_window: int = 1

    mail_host: str = "smtp.gmail.com"
    mail_port: int = 587
    mail_secure: bool = False
    mail_user: str | None = None
    mail_pass: str | None = None
    mail_from: str = "App <no-reply@localhost>"

    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_from_number: str | None = None

    s3_region: str = "us-east-1"
    s3_bucket: str = "app-uploads"
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None
    s3_endpoint: str | None = None
    s3_force_path_style: bool = False
    s3_public_base_url: str | None = None
    s3_upload_url_ttl_seconds: int = 900
    s3_download_url_ttl_seconds: int = 900
    s3_max_upload_bytes: int = 10 * 1024 * 1024

    log_level: str = "info"
    otel_exporter_otlp_endpoint: str | None = None

    google_client_ids: CsvList = []
    apple_client_ids: CsvList = []

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @field_validator("google_client_ids", "apple_client_ids", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        return [v.strip() for v in value.split(",") if v.strip()] if isinstance(value, str) else value

    @field_validator("database_url")
    @classmethod
    def _use_asyncpg(cls, value: str) -> str:
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)

    @field_validator("auth_encryption_key")
    @classmethod
    def _valid_fernet_key(cls, value: str) -> str:
        Fernet(value)
        return value

    @field_validator(
        "auth_cookie_domain", "mail_user", "mail_pass", "twilio_account_sid", "twilio_auth_token",
        "twilio_from_number", "s3_access_key_id", "s3_secret_access_key", "s3_endpoint", "s3_public_base_url",
        "otel_exporter_otlp_endpoint", mode="before",
    )  # fmt: skip
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return value or None

    @model_validator(mode="after")
    def _no_placeholders_in_production(self) -> Settings:
        if self.is_production:
            for name in ("jwt_access_secret", "jwt_refresh_secret"):
                if any(marker in getattr(self, name).lower() for marker in PLACEHOLDERS):
                    raise ValueError(f"{name.upper()} looks like a placeholder")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
