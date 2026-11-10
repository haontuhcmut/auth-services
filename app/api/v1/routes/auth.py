from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Cookie,
    Depends,
    HTTPException,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import (
    CurrentSession,
    CurrentUser,
    DatabaseDep,
    RedisDep,
)
from app.config import settings
from app.core.email_verification import (
    consume_verification_token,
    generate_verification_token,
    store_verification_token,
)
from app.core.refresh_tokens import (
    RotationResult,
    register_refresh_token,
    rotate_refresh_token,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)
from app.core.sessions import (
    create_session,
    get_session,
    list_user_sessions,
    revoke_all_user_sessions,
    revoke_session,
)
from app.db.model import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SessionRead,
    TokenResponse,
    UserCreate,
    UserRead,
    VerifyEmailRequest,
)
from app.services.email import (
    send_password_reset_email,
    send_verification_email,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def set_refresh_cookie(
    response: Response,
    refresh_token: str,
    expires_at: datetime,
) -> None:
    max_age = max(
        0,
        int((expires_at - datetime.now(UTC)).total_seconds()),
    )

    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age,
        expires=expires_at,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


def unauthorized(detail: str = "Invalid credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: UserCreate,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    redis: RedisDep,
) -> User:
    email = payload.email.strip().lower()
    username = payload.username.strip()

    if not email or not username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email and username cannot be empty",
        )

    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(payload.password),
        is_active=False,
        email_verified=False,
    )

    db.add(user)

    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered",
        ) from exc

    token = generate_verification_token()
    await store_verification_token(redis, token, user.id)

    verification_url = f"{settings.EMAIL_VERIFICATION_URL}?token={token}"

    background_tasks.add_task(
        send_verification_email,
        smtp_host=settings.SMTP_HOST,
        smtp_port=settings.SMTP_PORT,
        sender=settings.SMTP_FROM,
        recipient=user.email,
        verification_url=verification_url,
    )

    return user


@router.post("/verify-email")
async def verify_email(
    payload: VerifyEmailRequest,
    db: DatabaseDep,
    redis: RedisDep,
) -> dict[str, str]:
    user_id = await consume_verification_token(redis, payload.token)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    from uuid import UUID

    try:
        parsed_user_id = UUID(user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        ) from exc

    result = await db.execute(select(User).where(User.id == parsed_user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    user.email_verified = True
    user.is_active = True

    await db.commit()

    return {"message": "Email verified successfully"}


@router.post("/resend-verification")
async def resend_verification(
    payload: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    redis: RedisDep,
) -> dict[str, str]:
    email = payload.email.strip().lower()

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is not None and not user.email_verified:
        token = generate_verification_token()
        await store_verification_token(redis, token, user.id)

        verification_url = f"{settings.EMAIL_VERIFICATION_URL}?token={token}"

        background_tasks.add_task(
            send_verification_email,
            smtp_host=settings.SMTP_HOST,
            smtp_port=settings.SMTP_PORT,
            sender=settings.SMTP_FROM,
            recipient=user.email,
            verification_url=verification_url,
        )

    return {"message": ("If an unverified account exists, a verification link will be sent.")}


@router.post("/login", response_model=TokenResponse)
async def login(
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DatabaseDep,
    redis: RedisDep,
) -> TokenResponse:
    email = form.username.strip().lower()

    user_result = await db.execute(
        select(User).where(User.email == email),
    )
    user = user_result.scalar_one_or_none()

    if user is None or not verify_password(
        form.password,
        user.hashed_password,
    ):
        raise unauthorized()

    if not user.is_active:
        raise unauthorized("User account is inactive")

    auth_session = await create_session(redis, user.id)

    refresh_token, refresh_expires_at = create_refresh_token(
        user_id=user.id,
        session_id=auth_session.session_id,
        session_expires_at=auth_session.absolute_expires_at,
    )

    registered = await register_refresh_token(
        redis=redis,
        user_id=user.id,
        session_id=auth_session.session_id,
        refresh_token=refresh_token,
        expires_at=refresh_expires_at,
    )

    if not registered:
        await revoke_session(redis, auth_session.session_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not create authentication session",
        )

    access_token, expires_in = create_access_token(
        user_id=user.id,
        session_id=auth_session.session_id,
    )

    set_refresh_cookie(
        response,
        refresh_token,
        refresh_expires_at,
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_expires_at=refresh_expires_at,
        session_id=auth_session.session_id,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    response: Response,
    db: DatabaseDep,
    redis: RedisDep,
    refresh_token: Annotated[
        str | None,
        Cookie(alias=settings.REFRESH_COOKIE_NAME),
    ] = None,
) -> TokenResponse:
    if not refresh_token:
        raise unauthorized("Refresh token is missing")

    try:
        claims = decode_refresh_token(refresh_token)
    except jwt.InvalidTokenError as exc:
        raise unauthorized("Invalid or expired refresh token") from exc

    auth_session = await get_session(redis, claims.session_id)

    if auth_session is None or auth_session.user_id != claims.user_id:
        raise unauthorized("Session is invalid or expired")

    user_result = await db.execute(
        select(User).where(User.id == claims.user_id),
    )
    user = user_result.scalar_one_or_none()

    if user is None or not user.is_active:
        await revoke_session(redis, claims.session_id)
        raise unauthorized("User account is inactive or does not exist")

    new_refresh_token, refresh_expires_at = create_refresh_token(
        user_id=user.id,
        session_id=auth_session.session_id,
        session_expires_at=auth_session.absolute_expires_at,
    )

    rotation_result = await rotate_refresh_token(
        redis=redis,
        user_id=user.id,
        session_id=auth_session.session_id,
        old_token=refresh_token,
        new_token=new_refresh_token,
        new_expires_at=refresh_expires_at,
    )

    if rotation_result == RotationResult.REUSED:
        raise unauthorized("Refresh token reuse detected; session revoked")

    if rotation_result != RotationResult.ROTATED:
        raise unauthorized("Refresh token is invalid or has already been used")

    access_token, expires_in = create_access_token(
        user_id=user.id,
        session_id=auth_session.session_id,
    )

    set_refresh_cookie(
        response,
        new_refresh_token,
        refresh_expires_at,
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_expires_at=refresh_expires_at,
        session_id=auth_session.session_id,
    )


@router.post("/logout")
async def logout(
    response: Response,
    auth_session: CurrentSession,
    redis: RedisDep,
) -> dict[str, str]:
    await revoke_session(redis, auth_session.session_id)
    clear_refresh_cookie(response)

    return {"detail": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all(
    response: Response,
    user: CurrentUser,
    redis: RedisDep,
) -> dict[str, int | str]:
    revoked_count = await revoke_all_user_sessions(redis, user.id)
    clear_refresh_cookie(response)

    return {
        "detail": "All sessions have been revoked",
        "revoked_sessions": revoked_count,
    }


@router.get("/sessions", response_model=list[SessionRead])
async def get_sessions(
    user: CurrentUser,
    redis: RedisDep,
) -> list[SessionRead]:
    sessions = await list_user_sessions(redis, user.id)

    return [
        SessionRead(
            session_id=item.session_id,
            created_at=item.created_at,
            absolute_expires_at=item.absolute_expires_at,
            status=item.status,
        )
        for item in sessions
    ]


@router.get("/me", response_model=UserRead)
async def get_me(user: CurrentUser) -> User:
    return user


@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    redis: RedisDep,
) -> dict[str, str]:
    email = payload.email.strip().lower()

    result = await db.execute(
        select(User).where(User.email == email),
    )
    user = result.scalar_one_or_none()

    # Do not reveal whether an email address is registered.
    if user is not None and user.is_active:
        from app.core.password_reset import (
            generate_reset_token,
            store_reset_token,
        )

        token = generate_reset_token()

        await store_reset_token(
            redis=redis,
            token=token,
            user_id=str(user.id),
        )

        reset_url = f"{settings.PASSWORD_RESET_URL}?token={token}"

        background_tasks.add_task(
            send_password_reset_email,
            smtp_host=settings.SMTP_HOST,
            smtp_port=settings.SMTP_PORT,
            sender=settings.SMTP_FROM,
            recipient=user.email,
            reset_url=reset_url,
        )

    return {"message": ("If the account exists, a password reset link will be sent.")}


@router.post("/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    db: DatabaseDep,
    redis: RedisDep,
) -> dict[str, str]:
    from uuid import UUID

    from app.core.password_reset import consume_reset_token

    user_id = await consume_reset_token(redis, payload.token)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    try:
        parsed_user_id = UUID(user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        ) from exc

    result = await db.execute(
        select(User).where(User.id == parsed_user_id),
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    try:
        user.hashed_password = hash_password(payload.new_password)
        db.add(user)

        # Send pending database changes to PostgreSQL before revoking sessions.
        await db.flush()

        # Revoke all sessions, including refresh-token state in Redis.
        await revoke_all_user_sessions(redis, user.id)

        await db.commit()

    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset could not be completed. Request a new reset link.",
        ) from exc

    return {"message": "Password has been reset successfully"}
