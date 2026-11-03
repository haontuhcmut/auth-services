from collections.abc import AsyncGenerator

from fastapi import Request
from redis.asyncio import Redis

from app.config import settings


def create_redis_client() -> Redis:
    return Redis.from_url(
        settings.REDIS_URL.get_secret_value(),
        decode_responses=True,
        socket_timeout=2,
        socket_connect_timeout=2,
        health_check_interval=30,
    )


async def get_redis(request: Request) -> AsyncGenerator[Redis]:
    yield request.app.state.redis
