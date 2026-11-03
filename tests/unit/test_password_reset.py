from unittest.mock import AsyncMock

import pytest

from app.core.password_reset import (
    RESET_TOKEN_TTL_SECONDS,
    consume_reset_token,
    generate_reset_token,
    hash_reset_token,
    store_reset_token,
)


def test_generate_reset_token():
    first = generate_reset_token()
    second = generate_reset_token()

    assert first != second
    assert len(first) > 32


def test_hash_reset_token():
    token = "example-reset-token"

    assert hash_reset_token(token) == hash_reset_token(token)
    assert hash_reset_token(token) != token


@pytest.mark.asyncio
async def test_store_reset_token():
    redis = AsyncMock()
    token = generate_reset_token()

    await store_reset_token(redis, token, "user-123")

    redis.set.assert_awaited_once_with(
        f"auth:password-reset:{hash_reset_token(token)}",
        "user-123",
        ex=RESET_TOKEN_TTL_SECONDS,
    )


@pytest.mark.asyncio
async def test_consume_reset_token():
    redis = AsyncMock()
    redis.eval.return_value = b"user-123"

    user_id = await consume_reset_token(redis, "example-token")

    assert user_id == "user-123"
    redis.eval.assert_awaited_once()
