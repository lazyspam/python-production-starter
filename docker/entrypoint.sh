#!/bin/sh
# Container entrypoint for the API image.
#
# 1. Applies pending Alembic migrations against $DATABASE_URL.
#    `alembic upgrade head` is idempotent, so re-running on a healthy DB is a no-op.
# 2. `exec`s into uvicorn so the app becomes PID 1 and receives SIGTERM / SIGINT directly.
#
# The worker container overrides this entrypoint (see docker-compose.yml) and does not migrate.

set -eu

echo "[entrypoint] applying alembic migrations"
alembic upgrade head

echo "[entrypoint] starting api on port ${PORT:-3000}"
exec uvicorn app.main:asgi --host 0.0.0.0 --port "${PORT:-3000}" --proxy-headers
