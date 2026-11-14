from functools import lru_cache

from cryptography.fernet import Fernet
from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    app_env: str = "development"
    app_secret_key: SecretStr = SecretStr("development-only-change-this-secret")
    database_url: str = "sqlite+aiosqlite:///./vpn_manager.db"
    redis_url: str = "redis://127.0.0.1:6379/0"
    bot_token: SecretStr | None = None
    admin_telegram_ids: str = ""
    panel_credential_encryption_key: SecretStr | None = None
    log_level: str = "INFO"

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.app_env.lower() == "production":
            if len(self.app_secret_key.get_secret_value()) < 32:
                raise ValueError("APP_SECRET_KEY must contain at least 32 characters in production")
            if self.panel_credential_encryption_key is None:
                raise ValueError("PANEL_CREDENTIAL_ENCRYPTION_KEY is required in production")
            try:
                Fernet(self.panel_credential_encryption_key.get_secret_value().encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError(
                    "PANEL_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key"
                ) from exc
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
