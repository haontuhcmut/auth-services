import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.config import settings

password_hash = PasswordHash.recommended()


def hash_password(plain_password: str) -> str:
    return password_hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(user_id: uuid.uuid7()) -> tuple[str, int]:
    expires_in = settings.ACCESS_TOKEN_EXPIRES_MINUTES * 60
    now = datetime.now(UTC)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "exp": now + timedelta(seconds=expires_in),
        "iat": now,
        "jti": str(uuid.uuid7()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )
    return str(token), expires_in


def create_refresh_token(user_id: uuid.uuid7()) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    expires_in = settings.REFRESH_TOKEN_EXPIRES_DAYS

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": now + timedelta(days=expires_in),
        "iat": now,
        "jti": str(uuid.uuid7()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )

    return str(token), expires_in


def hash_refresh_token(refresh_token: str) -> str:
    # Redis stores the hash, not the original refresh token
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def decode_access_token(token: str) -> uuid.UUID:
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "jti", "exp", "iat", "type"]},
    )

    if payload.get("type") != "access":
        raise jwt.exceptions.InvalidTokenError

    return uuid.UUID(payload["sub"])


def decode_refresh_token(token: str) -> uuid.UUID:
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "jti", "exp", "iat", "type"]},
    )

    if payload.get("type") != "refresh":
        raise jwt.exceptions.InvalidTokenError

    user_id = uuid.UUID(payload["sub"])
    token_id = uuid.UUID(payload["jti"])

    return user_id, str(token_id)


def generate_reset_token() -> str:
    # Utility for a future password-reset flow
    # Store only its hash if you persist this token
    return secrets.token_urlsafe(32)
