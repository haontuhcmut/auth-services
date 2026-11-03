from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from redis.asyncio import Redis

from app.config import settings
from app.core.security import create_session_id

SESSION_KEY = "auth:{sid}:session"
REFRESH_TOKENS_KEY = "auth:{sid}:refresh_tokens"
USED_REFRESH_TOKENS_KEY = "auth:{sid}:used_refresh_tokens"
USER_SESSIONS_KEY = "auth:user:{uid}:sessions"


@dataclass(frozen=True, slots=True)
class SessionInfo:
    session_id: UUID
    user_id: UUID
    created_at: datetime
    absolute_expires_at: datetime
    status: str


def session_key(session_id: UUID) -> str:
    return SESSION_KEY.format(sid=session_id)


def refresh_tokens_key(session_id: UUID) -> str:
    return REFRESH_TOKENS_KEY.format(sid=session_id)


def used_refresh_tokens_key(session_id: UUID) -> str:
    return USED_REFRESH_TOKENS_KEY.format(sid=session_id)


def user_sessions_key(user_id: UUID) -> str:
    return USER_SESSIONS_KEY.format(uid=user_id)


def _to_session_info(data: dict[str, str]) -> SessionInfo:
    return SessionInfo(
        session_id=UUID(data["session_id"]),
        user_id=UUID(data["user_id"]),
        created_at=datetime.fromtimestamp(int(data["created_at"]), UTC),
        absolute_expires_at=datetime.fromtimestamp(
            int(data["absolute_expires_at"]),
            UTC,
        ),
        status=data["status"],
    )


async def create_session(
    redis: Redis,
    user_id: UUID,
) -> SessionInfo:
    now = datetime.now(UTC)
    session_id = create_session_id()

    expires_at = now + timedelta(
        days=settings.SESSION_ABSOLUTE_EXPIRES_DAYS,
    )

    session_data = {
        "session_id": str(session_id),
        "user_id": str(user_id),
        "created_at": str(int(now.timestamp())),
        "absolute_expires_at": str(int(expires_at.timestamp())),
        "status": "active",
    }

    current_session_key = session_key(session_id)
    current_refresh_key = refresh_tokens_key(session_id)
    current_user_key = user_sessions_key(user_id)

    try:
        await redis.hset(current_session_key, mapping=session_data)
        await redis.expireat(current_session_key, int(expires_at.timestamp()))

        await redis.sadd(current_user_key, str(session_id))
        await redis.expireat(current_user_key, int(expires_at.timestamp()))
    except Exception:
        await redis.delete(current_session_key, current_refresh_key)
        await redis.srem(current_user_key, str(session_id))
        raise

    return _to_session_info(session_data)


async def get_session(
    redis: Redis,
    session_id: UUID,
) -> SessionInfo | None:
    data = await redis.hgetall(session_key(session_id))

    if not data:
        return None

    try:
        session = _to_session_info(data)
    except KeyError, TypeError, ValueError:
        return None

    if session.status != "active":
        return None

    if session.absolute_expires_at <= datetime.now(UTC):
        await revoke_session(redis, session_id)
        return None

    return session


async def list_user_sessions(
    redis: Redis,
    user_id: UUID,
) -> list[SessionInfo]:
    current_user_key = user_sessions_key(user_id)
    session_ids = await redis.smembers(current_user_key)

    sessions: list[SessionInfo] = []

    for raw_session_id in session_ids:
        try:
            session_id = UUID(raw_session_id)
        except ValueError:
            await redis.srem(current_user_key, raw_session_id)
            continue

        session = await get_session(redis, session_id)

        if session is None:
            await redis.srem(current_user_key, raw_session_id)
            continue

        if session.user_id != user_id:
            await revoke_session(redis, session_id)
            continue

        sessions.append(session)

    return sorted(
        sessions,
        key=lambda item: item.created_at,
        reverse=True,
    )


async def revoke_session(
    redis: Redis,
    session_id: UUID,
) -> bool:
    current_session_key = session_key(session_id)
    data = await redis.hgetall(current_session_key)

    if not data:
        return False

    try:
        user_id = UUID(data["user_id"])
    except KeyError, ValueError:
        user_id = None

    await redis.delete(
        current_session_key,
        refresh_tokens_key(session_id),
        used_refresh_tokens_key(session_id),
    )

    if user_id is not None:
        await redis.srem(
            user_sessions_key(user_id),
            str(session_id),
        )

    return True


async def revoke_all_user_sessions(
    redis: Redis,
    user_id: UUID,
) -> int:
    current_user_key = user_sessions_key(user_id)
    session_ids = await redis.smembers(current_user_key)

    revoked_count = 0

    for raw_session_id in session_ids:
        try:
            session_id = UUID(raw_session_id)
        except ValueError:
            await redis.srem(current_user_key, raw_session_id)
            continue

        if await revoke_session(redis, session_id):
            revoked_count += 1

    await redis.delete(current_user_key)

    return revoked_count
