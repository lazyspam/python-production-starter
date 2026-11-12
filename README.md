# Python Production Starter

A production-oriented FastAPI starter. It includes PostgreSQL with SQLAlchemy and Alembic, Redis, cached queries, BullMQ-compatible background jobs, JWT authentication with two-factor sign-in and sudo mode, typed settings that fail fast, and OpenTelemetry with structured logs.

## Features

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) on [uvicorn](https://www.uvicorn.org/), Python 3.14, managed with [uv](https://docs.astral.sh/uv/).
- **Database**: [SQLAlchemy 2](https://www.sqlalchemy.org/) (async, asyncpg) with [Alembic](https://alembic.sqlalchemy.org/) migrations on PostgreSQL.
- **Authentication**: JWT access and refresh tokens ([PyJWT](https://pyjwt.readthedocs.io/)), passwords hashed with argon2 ([pwdlib](https://github.com/frankie567/pwdlib)), TOTP two-factor ([pyotp](https://github.com/pyauth/pyotp)), and an encryption key for secrets at rest ([cryptography](https://cryptography.io/)).
- **Settings**: Typed environment variables with [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/). The app refuses to start on an invalid or missing value.
- **Caching**: Redis-backed caching through [cashews](https://github.com/Krukov/cashews), with a `@cache(...)` decorator.
- **Background jobs**: [BullMQ](https://bullmq.io/) queues on Redis, consumed by a separate worker process.
- **Notifications**: Mail through [aiosmtplib](https://aiosmtplib.readthedocs.io/), SMS through [Twilio](https://www.twilio.com/docs/libraries/python).
- **Files**: Presigned S3 upload and download URLs through [aioboto3](https://github.com/terricain/aioboto3). Bytes never pass through the API.
- **Observability**: [OpenTelemetry](https://opentelemetry.io/) traces and metrics over OTLP HTTP, and JSON logs from [structlog](https://www.structlog.org/) that include the trace and span IDs.
- **API documentation**: Swagger UI at `/api/docs`, served outside production only.
- **Containers**: Multi-stage Dockerfile on `python:3.14-slim`, non-root user, liveness healthcheck, Compose stack with Postgres and Redis.
- **CI**: Lint, migrations, and tests on push and pull request. Image build workflow. Dependabot for uv, Docker, and GitHub Actions.

## Architecture

This project follows a feature-module layout. Shared plumbing lives in `infrastructure`, foundational features in `core`, and business features in `modules`.

```text
src/app/
  main.py                 # FastAPI app (exports `asgi`), routers included here
  worker.py               # Queue worker entrypoint (python -m app.worker)
  configs/                # settings.py (typed env), policy.py (security constants)
  common/                 # Shared schemas (Envelope, Schema), errors, security, rate limits
  database/               # Engine, session, declarative base and mixins
  infrastructure/         # Cache, queue, observability, storage, messaging, realtime
  core/                   # Foundational features: auth, health, files, fcm_token, audit
  modules/                # Business features: one package per feature
  locals/                 # Message catalogs (JSON), exposed as `msg`
migrations/               # Alembic env and template; revisions are generated per project
docker/entrypoint.sh      # Container entrypoint: start uvicorn
tests/                    # pytest suite
```

Every feature in `core/` and `modules/` is split into strict layers:

```text
<feature>/
  models.py            # SQLAlchemy models
  controllers/         # FastAPI routers only
  services/            # Business logic, one file per use-case area
  repositories/        # All database access, one file per aggregate
  dto/request/         # Request models
  dto/response/        # Response models
```

A folder is omitted when a feature has no use for it: `audit` has no controllers or DTOs, and `health` has no models. For example, `core/auth` looks like this:

```text
core/auth/
  models.py  types.py  constants.py  deps.py
  controllers/    session, password, verify, identifier, two_factor, sudo, helpers
  services/       tokens, otp, login, oauth, verify, password, identifiers, two_factor, sudo, sessions
  repositories/   user, identifier, credential, session, two_factor
  helpers/        normalize.py
  dto/request/    common, session, password, verify, sudo, two_factor
  dto/response/   session, password, verify, identifier, sudo, two_factor
```

Dependencies point one way: controllers call services, services call repositories.

### Key design choices

- **Plain async functions**: Services and routes are functions, not classes. Dependencies are passed explicitly.
- **Thin controllers**: A controller parses the request, calls one service, and builds the `Envelope`. It never queries the database.
- **Queries only in repositories**: Repositories are plain functions that take `db` and return models. They never commit, raise HTTP errors, or touch the cache or queues.
- **Explicit commits**: Services commit their own writes (`await db.commit()`), so a write is kept even when the HTTP response is an error.
- **Uniform responses**: Every success response uses the `Envelope` schema. Errors use one JSON shape.
- **Messages in one place**: User-facing text comes from `app.locals`, so a language can be added by loading another folder of JSON.

## Getting Started

### Prerequisites

- [uv](https://docs.astral.sh/uv/getting-started/installation/), which installs Python 3.14 for you if needed
- Docker and Docker Compose, for local Postgres and Redis

### Installation

1. **Install dependencies**

   ```bash
   uv sync
   ```

2. **Set up environment variables**

   ```bash
   cp .env.example .env
   ```

   Replace every `replace-with-*` value. Generate the secrets this way:

   ```bash
   openssl rand -hex 32   # JWT_ACCESS_SECRET and JWT_REFRESH_SECRET, 32+ characters
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # AUTH_ENCRYPTION_KEY
   ```

3. **Start Postgres and Redis**

   ```bash
   docker compose up -d postgres redis
   ```

4. **Generate and run migrations**

   The template ships no migration files (`migrations/versions/` is git-ignored). Generate the first revision from
   the models, then apply it:

   ```bash
   uv run alembic revision --autogenerate -m "initial schema"
   uv run alembic upgrade head
   ```

   Generated files are linted and formatted by ruff automatically. Review each one before applying: autogenerate
   does not drop enum types on downgrade, and sees a renamed column as a drop plus an add.

### Running the application

```bash
# API with auto-reload (development)
uv run uvicorn app.main:asgi --reload --host 127.0.0.1 --port 3000

# Worker
uv run python -m app.worker
```

With `ENVIRONMENT=production`, the API serves no Swagger UI and rejects placeholder JWT secrets at startup.

### Running with Docker

```bash
docker compose up --build -d    # api + worker + postgres + redis
docker compose logs -f app
docker compose down             # stop and keep data
docker compose down -v          # stop and remove volumes
```

A one-off `migrate` service runs `alembic upgrade head` and exits; the API and worker start only after it succeeds, so replicas never race on migrations. Outside compose, run migrations as a separate deploy step. The worker is healthy while its Redis heartbeat is fresh (`python -m app.worker --check`). Cookie-authenticated writes must send an `Origin` (or `Referer`) matching `FRONTEND_URL` or `BACKEND_URL`; bearer clients are exempt. Uploads live under `uploads/public/` or `uploads/private/`, so a bucket policy can expose public files only.

## Authentication (Cookies vs. Bearer Tokens)

> **Status**: This is the intended contract, copied from the NestJS starter it mirrors. The auth routes are not wired in this repository yet.

Tokens are accepted from either source:

1. **`Authorization: Bearer <token>`**: for mobile apps and API clients.
2. **HTTP-only cookies**: for web frontends, which keeps tokens away from JavaScript.

On login and registration, the `X-Auth-Transport` request header chooses where tokens are returned:

- **`X-Auth-Transport: bearer`**: tokens come back in the JSON body. Use this for mobile apps.
- **Header omitted**: tokens are set as HTTP-only cookies and the body contains no tokens. Use this for web apps.

Cookie behavior comes from `AUTH_COOKIE_DOMAIN` and `AUTH_COOKIE_SAME_SITE`. Token lifetimes come from `JWT_ACCESS_TTL_SECONDS` and `JWT_REFRESH_TTL_SECONDS`.

## API Documentation

- **Base path**: every route is under `/api/v1`.
- **Swagger UI**: `http://localhost:3000/api/docs`, served only when `ENVIRONMENT` is not `production`.
- **Liveness**: `GET /api/v1/health/liveness` returns `200` when the process is up. The Docker healthcheck uses it.

## Observability (OpenTelemetry)

- **Traces and metrics**: exported over OTLP HTTP to `OTEL_EXPORTER_OTLP_ENDPOINT`. Leave it blank to turn telemetry off, for example in tests.
- **Logs**: structlog writes JSON to stdout at `LOG_LEVEL`. Each record carries `trace_id`, `span_id`, and `request_id` when available.
- **Instrumentation**: FastAPI, SQLAlchemy, and Redis are auto-instrumented.

## Caching

Cache reads and writes go through cashews. Decorate a function and give it a key template:

```python
from cashews import cache


@cache(ttl="5m", key="thing:{id}")
async def get_thing(id: str) -> dict:
    return await load_thing_from_db(id)
```

Keys are prefixed with `REDIS_KEY_PREFIX`. A Redis outage raises an error, and it does not silently skip the cache, because login lockouts and OTP checks depend on Redis.

## Background Jobs (BullMQ)

Enqueue work from a service. The worker process consumes the queue.

```python
from app.infrastructure.queue import MAIL_QUEUE, enqueue


async def send_welcome(email: str) -> None:
    await enqueue(MAIL_QUEUE, "welcome", {"to": email})
```

Queues are `mail`, `sms`, `audit`, and `maintenance`. Each job retries 5 times with exponential backoff. Jobs are stored in Redis, so several API and worker instances can share one queue.

## Testing

Tests use pytest with pytest-asyncio in auto mode, and HTTP tests use httpx. They need Postgres and Redis running, so start them first with `docker compose up -d postgres redis`.

```bash
uv run ruff check     # lint
uv run pytest         # tests in tests/
```

CI runs the same commands on every push and pull request, with service containers for Postgres 18 and Redis 8.

## Adding a Feature

1. Create `src/app/modules/<feature>/` with `models.py`, `controllers/`, `services/`, `repositories/`, `dto/request/` and `dto/response/`, each with an `__init__.py`.
2. Put queries in `repositories/<aggregate>.py` as plain async functions taking `db`. They return models and never commit.
3. Put business logic in `services/<area>.py`. Services call repositories and commit explicitly with `await db.commit()`.
4. Put the router in `controllers/<area>.py`. It parses the request, calls one service, and returns an `Envelope`.
5. Add the models to `src/app/database/models.py`, then include the router in `src/app/main.py` under the `/api/v1` prefix.
6. Add an Alembic revision for any new table: `uv run alembic revision --autogenerate -m "<message>"`.
7. Add tests under `tests/`.

## Contributing

Read [AGENTS.md](AGENTS.md) before changing code. It lists the conventions, the layout, and the commit format.
