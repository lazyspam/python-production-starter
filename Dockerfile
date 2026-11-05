# syntax=docker/dockerfile:1.7
#
# Production image for the FastAPI API and background worker.
#
# Build:    docker build -t python-production-starter:latest .
# Run:      docker run --rm --env-file .env -p 3000:3000 python-production-starter:latest
#
# Layout:
#   builder — uv installs the locked dependencies into /app/.venv (no dev group)
#   runner  — slim Python image with the venv, src/, migrations and a non-root user
#
# Choices worth knowing:
#   - python:3.14-slim (Debian) keeps glibc wheels working for asyncpg, argon2 and cryptography.
#   - uv is copied from a pinned image tag, so builds do not drift with uv releases.
#   - UV_PYTHON_DOWNLOADS=never: uv uses the Python in the base image, never downloads one.
#   - The app runs as uid 10001 and never as root.
#   - HEALTHCHECK uses the Python standard library (no curl or wget) against /api/v1/health/liveness.
#   - The same image runs the API (entrypoint) and the worker (docker-compose overrides entrypoint).

FROM ghcr.io/astral-sh/uv:0.13.6 AS uv


# ─── builder: locked dependencies only ───────────────────────────────────────
FROM python:3.14-slim AS builder
COPY --from=uv /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependencies first, so source edits do not invalidate this layer.
COPY pyproject.toml uv.lock .python-version ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Then the project itself (the app package in src/app).
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


# ─── runner: final image ─────────────────────────────────────────────────────
FROM python:3.14-slim AS runner

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    PORT=3000

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

# Files are owned by root and only readable by the app user, so the app cannot modify its own code.
COPY --from=builder /app/.venv /app/.venv
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

USER app
EXPOSE 3000

# Liveness probe. Exits 0 only when /api/v1/health/liveness answers 200.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, sys, urllib.request as r; sys.exit(r.urlopen('http://127.0.0.1:%s/api/v1/health/liveness' % os.environ.get('PORT', '3000'), timeout=4).status != 200)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
