import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from pwdlib import PasswordHash

from app.config import settings

password_hash = PasswordHash.recommended()


@dataclass(frozen=True, slots=True)
class TokenClaims:
    user_id: UUID
    session_id: UUID
    token_id: UUID
    expires_at: datetime
    scopes: frozenset[str] = frozenset()


def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_session_id() -> UUID:
    return uuid.uuid7()


def create_access_token(
    user_id: UUID,
    session_id: UUID,
    scopes: list[str] | None = None,
) -> tuple[str, int]:
    expires_in = settings.ACCESS_TOKEN_EXPIRES_MINUTES * 60
    now = datetime.now(UTC)

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "access",
        "exp": now + timedelta(seconds=expires_in),
        "iat": now,
        "jti": str(uuid.uuid7()),
    }

    if scopes:
        payload["scope"] = " ".join(sorted(set(scopes)))

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )

    return token, expires_in


def create_refresh_token(
    user_id: UUID,
    session_id: UUID,
    session_expires_at: datetime,
) -> tuple[str, datetime]:
    now = datetime.now(UTC)

    if session_expires_at.tzinfo is None:
        raise ValueError("Session expiration must be timezone-aware")

    refresh_expires_at = min(
        now + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS),
        session_expires_at,
    )

    if refresh_expires_at <= now:
        raise ValueError("Session has expired")

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "refresh",
        "exp": refresh_expires_at,
        "iat": now,
        "jti": str(uuid.uuid7()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )

    return token, refresh_expires_at


def hash_refresh_token(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def _decode_token(token: str, expected_type: str) -> TokenClaims:
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "require": ["sub", "sid", "jti", "exp", "iat", "type"],
        },
    )

    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Invalid token type")

    try:
        raw_scope = payload.get("scope", "")

        if not isinstance(raw_scope, str):
            raise ValueError("Invalid scope claim")

        scopes = frozenset(raw_scope.split())

        return TokenClaims(
            user_id=UUID(payload["sub"]),
            session_id=UUID(payload["sid"]),
            token_id=UUID(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            scopes=scopes if expected_type == "access" else frozenset(),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise jwt.InvalidTokenError("Invalid token claims") from exc


def decode_access_token(token: str) -> TokenClaims:
    return _decode_token(token, "access")


def decode_refresh_token(token: str) -> TokenClaims:
    return _decode_token(token, "refresh")


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)
