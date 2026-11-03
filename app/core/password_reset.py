import hashlib
import secrets

from redis.asyncio import Redis

RESET_TOKEN_TTL_SECONDS = 15 * 60
RESET_TOKEN_PREFIX = "auth:password-reset"


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def store_reset_token(
    redis: Redis,
    token: str,
    user_id: str,
) -> None:
    token_hash = hash_reset_token(token)
    key = f"{RESET_TOKEN_PREFIX}:{token_hash}"

    await redis.set(
        key,
        user_id,
        ex=RESET_TOKEN_TTL_SECONDS,
    )


async def consume_reset_token(
    redis: Redis,
    token: str,
) -> str | None:
    token_hash = hash_reset_token(token)
    key = f"{RESET_TOKEN_PREFIX}:{token_hash}"

    script = """
    local value = redis.call('GET', KEYS[1])
    if value then
        redis.call('DEL', KEYS[1])
    end
    return value
    """

    result = await redis.eval(script, 1, key)

    if result is None:
        return None

    if isinstance(result, bytes):
        return result.decode("utf-8")

    return str(result)
