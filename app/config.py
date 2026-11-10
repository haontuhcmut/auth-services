from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    DATABASE_URL: SecretStr
    REDIS_URL: SecretStr

    ACCESS_TOKEN_EXPIRES_MINUTES: int
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str

    REFRESH_TOKEN_EXPIRES_DAYS: int

    REFRESH_COOKIE_NAME: str = "refresh_token"
    REFRESH_COOKIE_SECURE: bool = False
    REFRESH_COOKIE_SAMESITE: str = "lax"
    REFRESH_COOKIE_PATH: str = "/api/v1/auth"
    SESSION_ABSOLUTE_EXPIRES_DAYS: int = 30

    SMTP_HOST: str = "mailpit"
    SMTP_PORT: int = 1025
    SMTP_FROM: str = "no-reply@auth.local"
    PASSWORD_RESET_URL: str = "http://localhost:3000/reset-password"
    EMAIL_VERIFICATION_URL: str = "http://localhost:3000/verify-email"

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
