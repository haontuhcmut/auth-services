from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    DATABASE_URL: SecretStr

    ACCESS_TOKEN_EXPIRES_MINUTES: int
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str

    REFRESH_TOKEN_EXPIRES_DAYS: int

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
