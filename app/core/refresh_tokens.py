from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from redis.asyncio import Redis

from app.core.security import hash_refresh_token
from app.core.sessions import (
    refresh_tokens_key,
    revoke_session,
    session_key,
    used_refresh_tokens_key,
)


class RotationResult(StrEnum):
    ROTATED = "rotated"
    INVALID = "invalid"
    REUSED = "reused"
    SESSION_INVALID = "session_invalid"
    TOKEN_COLLISION = "token_collision"


REGISTER_REFRESH_TOKEN_SCRIPT = """
local session_user_id = redis.call('HGET', KEYS[1], 'user_id')
local status = redis.call('HGET', KEYS[1], 'status')
local absolute_expiry = tonumber(
    redis.call('HGET', KEYS[1], 'absolute_expires_at')
)

local now = tonumber(ARGV[2])
local token_expiry = tonumber(ARGV[3])

if not session_user_id or session_user_id ~= ARGV[1] then
    return 0
end

if status ~= 'active' or not absolute_expiry then
    return 0
end

if absolute_expiry <= now or token_expiry <= now then
    return 0
end

if token_expiry > absolute_expiry then
    return 0
end

local added = redis.call(
    'ZADD', KEYS[2], 'NX', token_expiry, ARGV[4]
)

if added ~= 1 then
    return 0
end

redis.call('PEXPIREAT', KEYS[2], absolute_expiry * 1000)
redis.call('PEXPIREAT', KEYS[3], absolute_expiry * 1000)

return 1
"""


ROTATE_REFRESH_TOKEN_SCRIPT = """
local session_user_id = redis.call('HGET', KEYS[1], 'user_id')
local status = redis.call('HGET', KEYS[1], 'status')
local absolute_expiry = tonumber(
    redis.call('HGET', KEYS[1], 'absolute_expires_at')
)

local now = tonumber(ARGV[3])
local new_expiry = tonumber(ARGV[4])

if not session_user_id or session_user_id ~= ARGV[1] then
    return -3
end

if status ~= 'active' or not absolute_expiry then
    return -3
end

if absolute_expiry <= now then
    redis.call('HSET', KEYS[1], 'status', 'expired')
    redis.call('DEL', KEYS[2], KEYS[3])
    return -3
end

if new_expiry <= now or new_expiry > absolute_expiry then
    return -3
end

-- Remove expired active tokens before checking the old token.
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)

local old_score = redis.call('ZSCORE', KEYS[2], ARGV[2])

if not old_score then
    -- A consumed token being presented again indicates possible theft.
    if redis.call('ZSCORE', KEYS[3], ARGV[2]) then
        redis.call('HSET', KEYS[1], 'status', 'revoked')
        redis.call('DEL', KEYS[2], KEYS[3])
        return -2
    end

    return 0
end

if tonumber(old_score) <= now then
    redis.call('ZREM', KEYS[2], ARGV[2])
    return 0
end

-- Never allow a new token hash to collide with an existing token.
if redis.call('ZSCORE', KEYS[2], ARGV[5]) then
    return -1
end

if redis.call('ZSCORE', KEYS[3], ARGV[5]) then
    return -1
end

-- Consume the old token and register the new one atomically.
redis.call('ZREM', KEYS[2], ARGV[2])
redis.call('ZADD', KEYS[3], absolute_expiry, ARGV[2])
redis.call('ZADD', KEYS[2], new_expiry, ARGV[5])

redis.call('PEXPIREAT', KEYS[2], absolute_expiry * 1000)
redis.call('PEXPIREAT', KEYS[3], absolute_expiry * 1000)

return 1
"""


async def register_refresh_token(
    redis: Redis,
    user_id: UUID,
    session_id: UUID,
    refresh_token: str,
    expires_at: datetime,
) -> bool:
    """
    Register a refresh token hash against an active session.

    The token expiration cannot exceed the session's absolute expiration.
    """
    if expires_at.tzinfo is None:
        raise ValueError("Token expiration must be timezone-aware")

    now = int(datetime.now(UTC).timestamp())
    token_expiry = int(expires_at.timestamp())

    if token_expiry <= now:
        return False

    token_hash = hash_refresh_token(refresh_token)

    result = await redis.eval(
        REGISTER_REFRESH_TOKEN_SCRIPT,
        3,
        session_key(session_id),
        refresh_tokens_key(session_id),
        used_refresh_tokens_key(session_id),
        str(user_id),
        now,
        token_expiry,
        token_hash,
    )

    return result == 1


async def rotate_refresh_token(
    redis: Redis,
    user_id: UUID,
    session_id: UUID,
    old_token: str,
    new_token: str,
    new_expires_at: datetime,
) -> RotationResult:
    """
    Atomically consume an old refresh token and register a new one.

    Reuse of a previously consumed token revokes the entire session.
    """
    if new_expires_at.tzinfo is None:
        raise ValueError("Token expiration must be timezone-aware")

    now = int(datetime.now(UTC).timestamp())
    new_expiry = int(new_expires_at.timestamp())

    if new_expiry <= now:
        return RotationResult.SESSION_INVALID

    old_hash = hash_refresh_token(old_token)
    new_hash = hash_refresh_token(new_token)

    result = await redis.eval(
        ROTATE_REFRESH_TOKEN_SCRIPT,
        3,
        session_key(session_id),
        refresh_tokens_key(session_id),
        used_refresh_tokens_key(session_id),
        str(user_id),
        old_hash,
        now,
        new_expiry,
        new_hash,
    )

    if result == 1:
        return RotationResult.ROTATED

    if result == -2:
        # The Lua script already marked the session revoked.
        # This call also removes its entry from the user's session index.
        await revoke_session(redis, session_id)
        return RotationResult.REUSED

    if result == -1:
        return RotationResult.TOKEN_COLLISION

    if result == -3:
        await revoke_session(redis, session_id)
        return RotationResult.SESSION_INVALID

    return RotationResult.INVALID


async def is_refresh_token_active(
    redis: Redis,
    session_id: UUID,
    refresh_token: str,
) -> bool:
    """
    Check whether a refresh token hash is currently registered and unexpired.
    """
    now = int(datetime.now(UTC).timestamp())
    token_hash = hash_refresh_token(refresh_token)

    key = refresh_tokens_key(session_id)

    await redis.zremrangebyscore(key, "-inf", now)

    score = await redis.zscore(key, token_hash)

    return score is not None and int(score) > now
