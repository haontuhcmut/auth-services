from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.security import TokenClaims, decode_access_token
from app.core.sessions import SessionInfo
from app.core.sessions import get_session as get_auth_session
from app.db.database import get_session
from app.db.model import User
from app.db.redis.redis import get_redis

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
)


async def get_current_claims(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> TokenClaims:
    try:
        return decode_access_token(token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_session(
    claims: Annotated[TokenClaims, Depends(get_current_claims)],
    redis: Annotated[Redis, Depends(get_redis)],
) -> SessionInfo:
    session = await get_auth_session(redis, claims.session_id)

    if session is None or session.user_id != claims.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session


async def get_current_user(
    claims: Annotated[TokenClaims, Depends(get_current_claims)],
    auth_session: Annotated[SessionInfo, Depends(get_current_session)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    if auth_session.user_id != claims.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(
        select(User).where(User.id == claims.user_id),
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive or does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


RedisDep = Annotated[Redis, Depends(get_redis)]
DatabaseDep = Annotated[AsyncSession, Depends(get_session)]
CurrentClaims = Annotated[TokenClaims, Depends(get_current_claims)]
CurrentSession = Annotated[SessionInfo, Depends(get_current_session)]
CurrentUser = Annotated[User, Depends(get_current_user)]
