from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.db.database import engine
from app.db.redis.redis import create_redis_client


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    redis = create_redis_client()

    try:
        await redis.ping()
        app.state.redis = redis
        yield
    finally:
        await redis.aclose()
        await engine.dispose()


app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(api_router)


@app.get("/health", tags=["Health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
