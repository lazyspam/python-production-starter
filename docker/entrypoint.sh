#!/bin/sh
# Container entrypoint for the API image.
#
# Migrations are not run here: with several replicas they would race. Run `alembic upgrade head`
# once per deploy as its own job (docker-compose.yml has a `migrate` service).
#
# `exec`s into uvicorn so the app becomes PID 1 and receives SIGTERM / SIGINT directly.
# The worker container overrides this entrypoint (see docker-compose.yml).

set -eu

echo "[entrypoint] starting api on port ${PORT:-3000}"
exec uvicorn app.main:asgi --host 0.0.0.0 --port "${PORT:-3000}" --proxy-headers
