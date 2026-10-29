from collections.abc import Generator

from fastapi import Request
from redis.asyncio import Redis

from app.config import settings

redis_client: Redis = Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_timeout=2,
    socket_connect_timeout=2,
    health_check_interval=30,
)


async def get_redis(request: Request) -> Generator[Redis]:
    # The application lifespan owns the Redis connection.
    yield request.app.state.redis
