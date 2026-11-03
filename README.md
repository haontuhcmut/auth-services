# auth-services# Auth Services

A backend authentication service built with **FastAPI**, **PostgreSQL**, and **Redis**. It provides user registration, email verification, JWT-based authentication, refresh-token rotation, session management, and password recovery.

## Features

### Authentication
- User registration
- Email verification with time-limited tokens
- Login using email and password
- JWT access tokens
- Refresh-token rotation
- Logout current session
- Logout all sessions
- Retrieve authenticated user information

### Session Management
- Create and manage user sessions
- Store refresh-token state in Redis
- Track session expiration
- Revoke individual sessions
- Revoke all user sessions
- Invalidate sessions after password reset

### Password Management
- Secure password hashing
- Forgot-password workflow
- Time-limited password-reset tokens
- Single-use password-reset tokens
- Revoke existing sessions after password reset

### Email
- Email verification
- Password-reset emails
- SMTP integration
- Mailpit for local email testing

## Tech Stack

| Component | Technology |
|---|---|
| Backend framework | FastAPI |
| Language | Python 3.14 |
| Database | PostgreSQL |
| ORM | SQLModel / SQLAlchemy |
| Database migrations | Alembic |
| Cache and token storage | Redis |
| Authentication | JWT |
| Password hashing | Password hashing utilities |
| Configuration | Pydantic Settings |
| Email | SMTP |
| Local email testing | Mailpit |
| Containerization | Docker / Docker Compose |
| Code quality | Ruff |

## Architecture

The service uses PostgreSQL for persistent user data and Redis for temporary authentication state, token management, and session operations.

```text
                    Client
                      |
                      v
               FastAPI Application
                      |
             API Router (/api/v1)
                      |
               Authentication
                 Endpoints
                      |
          +-----------+-----------+
          |                       |
          v                       v
      PostgreSQL                Redis
          |                       |
     User records          Session state
     User credentials      Refresh tokens
                            Verification tokens
                            Password-reset tokens

                      |
                      v
                 SMTP Service
                      |
                      v
                    Mailpit
```

### Storage Responsibilities

**PostgreSQL**
- User information
- Email and username
- Password hashes
- Account activation status
- Email verification status

**Redis**
- Refresh-token state
- Session state
- Email-verification tokens
- Password-reset tokens
- Temporary authentication data

## Project Structure

```text
auth-services/
├── app/
│   ├── api/
│   │   ├── deps.py
│   │   └── v1/
│   │       ├── router.py
│   │       └── routes/
│   │           └── auth.py
│   ├── core/
│   │   ├── email_verification.py
│   │   ├── password_reset.py
│   │   ├── refresh_tokens.py
│   │   ├── security.py
│   │   └── sessions.py
│   ├── db/
│   │   └── model.py
│   ├── schemas/
│   │   └── auth.py
│   ├── services/
│   │   └── email.py
│   ├── config.py
│   └── main.py
├── alembic/
│   └── versions/
├── docker-compose-dev.yaml
├── alembic.ini
├── pyproject.toml
├── uv.lock
└── README.md
```

## Getting Started

### Prerequisites

- Docker
- Docker Compose
- Git

Python and local PostgreSQL/Redis installations are not required when running the development environment entirely through Docker.

### 1. Clone the repository

```bash
git clone <repository-url>
cd auth-services
```

### 2. Configure environment variables

Create a `.env` file in the project root.

Example:

```dotenv
# Database
DATABASE_URL=postgresql+asyncpg://<username>:<password>@auth-postgres:5432/auth_db

# Redis
REDIS_URL=redis://auth-redis:6379/0

# JWT
JWT_SECRET_KEY=<your-secret-key>
JWT_ALGORITHM=HS256

# Token expiration
ACCESS_TOKEN_EXPIRES_MINUTES=15
REFRESH_TOKEN_EXPIRES_DAYS=7
SESSION_ABSOLUTE_EXPIRES_DAYS=30

# SMTP
SMTP_HOST=mailpit
SMTP_PORT=1025
SMTP_FROM=no-reply@auth.local

# Email URLs
PASSWORD_RESET_URL=http://localhost:3000/reset-password
EMAIL_VERIFICATION_URL=http://localhost:3000/verify-email
```

Replace placeholder credentials and secrets with appropriate development values.

Do not commit `.env` or production secrets to version control.

### 3. Start services

```bash
docker compose -f docker-compose-dev.yaml up -d --build
```

Check running containers:

```bash
docker compose -f docker-compose-dev.yaml ps
```

View application logs:

```bash
docker compose -f docker-compose-dev.yaml logs -f auth-api
```

### 4. Run database migrations

Run Alembic inside the API container so it can resolve the Docker service hostname and use the configured database connection.

```bash
docker compose -f docker-compose-dev.yaml exec auth-api \
  uv run --no-sync alembic upgrade head
```

Check the current migration revision:

```bash
docker compose -f docker-compose-dev.yaml exec auth-api \
  uv run --no-sync alembic current
```

### 5. Access services

| Service | URL |
|---|---|
| FastAPI API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| OpenAPI schema | http://localhost:8000/openapi.json |
| Mailpit UI | http://localhost:8025 |

## API Endpoints

Base URL:

```text
http://localhost:8000/api/v1
```

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/verify-email` | Verify email address |
| POST | `/auth/resend-verification` | Resend verification email |
| POST | `/auth/login` | Authenticate user |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Revoke current session |
| POST | `/auth/logout-all` | Revoke all user sessions |
| GET | `/auth/me` | Get current authenticated user |
| GET | `/auth/sessions` | List user sessions |

### Password Recovery

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/forgot-password` | Request password-reset email |
| POST | `/auth/reset-password` | Reset password using token |

Refer to Swagger UI for request schemas, response models, and authentication requirements.

## Authentication Workflow

### Registration and Email Verification

```text
Client
  |
  | POST /auth/register
  v
FastAPI
  |
  | Create inactive user
  | Generate verification token
  | Store token in Redis
  v
PostgreSQL + Redis
  |
  | Send verification email
  v
Mailpit / SMTP
  |
  | User receives verification link
  v
Client
  |
  | POST /auth/verify-email
  v
FastAPI
  |
  | Consume verification token
  | Activate and verify account
  v
PostgreSQL
```

### Login and Refresh Token Rotation

```text
Client
  |
  | POST /auth/login
  v
FastAPI
  |
  | Verify credentials
  | Create session
  | Issue access token
  | Issue refresh token
  v
Client
  |
  | Access protected endpoints
  |
  | POST /auth/refresh
  v
FastAPI
  |
  | Validate refresh token
  | Rotate refresh token
  | Issue new token pair
  v
Client
```

### Password Reset

```text
Client
  |
  | POST /auth/forgot-password
  v
FastAPI
  |
  | Generate reset token
  | Store token in Redis
  | Send reset email
  v
Client
  |
  | POST /auth/reset-password
  v
FastAPI
  |
  | Validate and consume token
  | Update password hash
  | Revoke user sessions
  v
PostgreSQL + Redis
```

## Testing

The project includes a Postman collection for testing the authentication lifecycle.

Import:

- `auth-service-full-flow.postman_collection.json`
- `auth-service-local.postman_environment.json`

The collection covers:

- Registration
- Duplicate registration
- Email verification
- Login
- Authenticated user endpoints
- Session listing
- Refresh-token rotation
- Logout
- Forgot-password
- Password reset
- Token reuse and invalid-token scenarios
- Logout all sessions

Run the collection against the local Docker environment.

## Development Commands

### Start development environment

```bash
docker compose -f docker-compose-dev.yaml up -d --build
```

### Stop containers

```bash
docker compose -f docker-compose-dev.yaml down
```

This stops and removes containers and the Compose network without deleting named database volumes.

### View logs

```bash
docker compose -f docker-compose-dev.yaml logs -f auth-api
```

### Run migrations

```bash
docker compose -f docker-compose-dev.yaml exec auth-api \
  uv run --no-sync alembic upgrade head
```

### Check code quality

```bash
uv run ruff check app alembic
uv run ruff format --check app alembic
```

### Compile Python modules

```bash
uv run python -m compileall -q app
```

## Security Considerations

- Store password hashes instead of plaintext passwords.
- Keep JWT signing secrets outside source control.
- Use short-lived access tokens.
- Rotate refresh tokens when they are used.
- Store temporary tokens in Redis with expiration.
- Hash verification and password-reset tokens before storing them.
- Consume single-use tokens atomically.
- Avoid exposing whether an email address exists in password-recovery responses.
- Revoke sessions after password changes.
- Use HTTPS and secure cookie settings when integrating with a production frontend.
- Configure rate limiting for authentication and recovery endpoints before production deployment.

## Current Scope

This repository focuses on the authentication backend and its local development infrastructure.

Frontend user interfaces, production SMTP configuration, deployment infrastructure, and production-grade rate limiting are separate concerns.

## License

Add the project's license information here.
