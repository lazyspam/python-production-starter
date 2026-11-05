# Agent instructions

Conventions for this repo. Follow them as written.

## Layout

- `src/app/main.py`: FastAPI app (`asgi`). Feature routers are included here.
- `src/app/worker.py`: queue worker entrypoint (`python -m app.worker`).
- `src/app/configs/`: `settings.py` (typed env via `get_settings()`), `policy.py` (security constants).
- `src/app/common/`: shared schemas (`Envelope`, `Schema`), errors, security, rate limits.
- `src/app/locals/`: message catalogs, read through `msg`.
- `src/app/database/`: engine, session, base mixins.
- `src/app/infrastructure/`: cache, queue, observability, storage, messaging, realtime.
- `src/app/core/`: foundational features (auth, health, files, fcm_token, audit).
- `src/app/modules/<feature>/`: business features. Files: `models.py`, `schemas.py`, `service.py`, `router.py`.

## Rules

- Use plain async functions for services and routes. Do not add classes unless a library requires one.
- Services commit explicitly (`await session.commit()`), so a write survives when the HTTP response is an error.
- Routes return `Envelope[T]` from `app.common.schemas`. Request and response models subclass `Schema`, which is snake_case in Python and camelCase on the wire.
- User-facing text comes from `app.locals` (`msg.<file>.<key>`). Do not write inline strings in responses.
- Read configuration through `get_settings()`. Do not read `os.environ` directly.
- Security policy values (lockouts, TTLs, OTP limits) live in `configs/policy.py`.
- Cache with `@cache(ttl=..., key=...)` from cashews. Run background work with `enqueue(...)` from `infrastructure/queue.py`.
- Before writing a helper, check whether a package already in `pyproject.toml` does the job. Prefer the package.
- Avoid over-engineering. Do not add an abstraction layer until a second caller needs it.

## Commits

- One line: `__type: subject`. No body.
- Types: `__feat` (new feature), `__update` (change or improvement), `__fix` (bug fix), `__mod` (general modification).
- Lowercase, plain words, about 4 to 10 words, one idea.
- No AI attribution: no `Co-Authored-By`, no "Generated with" lines, no session links.
- Commit only when asked. Never commit to `main`. Work on `beta`.
