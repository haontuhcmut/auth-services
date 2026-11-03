import hashlib
import secrets
from uuid import UUID

from redis.asyncio import Redis

VERIFICATION_TOKEN_TTL_SECONDS = 30 * 60
VERIFICATION_TOKEN_PREFIX = "auth:email-verification"


def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


def hash_verification_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def store_verification_token(
    redis: Redis,
    token: str,
    user_id: UUID,
) -> None:
    token_hash = hash_verification_token(token)
    key = f"{VERIFICATION_TOKEN_PREFIX}:{token_hash}"

    await redis.set(
        key,
        str(user_id),
        ex=VERIFICATION_TOKEN_TTL_SECONDS,
    )


async def consume_verification_token(
    redis: Redis,
    token: str,
) -> str | None:
    token_hash = hash_verification_token(token)
    key = f"{VERIFICATION_TOKEN_PREFIX}:{token_hash}"

    script = """
    local user_id = redis.call('GET', KEYS[1])
    if user_id then
        redis.call('DEL', KEYS[1])
    end
    return user_id
    """

    result = await redis.eval(script, 1, key)

    if result is None:
        return None

    if isinstance(result, bytes):
        return result.decode("utf-8")

    return str(result)
