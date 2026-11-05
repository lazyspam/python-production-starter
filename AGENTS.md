# Agent instructions

Conventions for this repo. Follow them as written.

## Layout

- `src/app/main.py`: FastAPI app (`asgi`). Feature controllers' routers are included here.
- `src/app/worker.py`: queue worker entrypoint (`python -m app.worker`).
- `src/app/configs/`: `settings.py` (typed env via `get_settings()`), `policy.py` (security constants).
- `src/app/common/`: shared schemas (`Envelope`, `Schema`), errors, security, rate limits.
- `src/app/locals/`: message catalogs, read through `msg`.
- `src/app/database/`: engine, session, base mixins.
- `src/app/infrastructure/`: cache, queue, observability, storage, messaging, realtime.
- `src/app/core/`: foundational features (auth, health, files, fcm_token, audit).
- `src/app/modules/<feature>/`: business features. Same layout as a core feature (below).

Every feature in `core/` and `modules/` is split into strict layers:

```text
<feature>/
  models.py            SQLAlchemy models
  controllers/         FastAPI routers only
  services/            business logic, one file per use-case area
  repositories/        all database access, one file per aggregate
  dto/request/         request models
  dto/response/        response models
```

Omit a folder the feature has no use for (`audit` has no controllers or DTOs, `health` has no models).
`core/auth` also has `deps.py` (permission dependencies), `constants.py`, `types.py` and `helpers/normalize.py`.
Controllers, DTOs and services are named by topic: `controllers/sudo.py`, `dto/request/sudo.py`, `services/sudo.py`.
Request DTOs shared between topics go in `dto/request/common.py`.

## Rules

- Use plain async functions for controllers, services and repositories. Do not add classes (or base classes, or generic CRUD) unless a library requires one.
- Controllers only parse the request, call one service and build the `Envelope`. They never import a repository, `select` or `cache`, and never call `db.get/add/commit/execute/scalar`. They may take `db: Db` to pass to the service, and may read cookies and headers and set cookies. Permission checks live in `deps.py`.
- Services hold the logic and never build queries: no `select/update/delete` and no `db.get/scalar/scalars/execute/add/add_all/delete`. They call repositories. They may call `db.flush()`.
- Services commit explicitly (`await db.commit()`), so a write survives when the HTTP response is an error (for example, revoking every session when a refresh token is replayed). Keep each commit at the same point in the logic.
- Repositories hold all queries and creates. They are plain async functions taking `db: AsyncSession`, return models, and never commit, raise `HTTPException`, or touch cache or queues. Atomic operations stay one statement (the backup-code claim is one UPDATE; `lock_user` is `SELECT ... FOR UPDATE`).
- `deps.py` may call repositories for the current-user lookup. Workers and jobs call services, never queries.
- `common/pagination.py` is a shared helper for repositories.
- Controllers return `Envelope[T]` from `app.common.schemas`. Request and response models subclass `Schema`, which is snake_case in Python and camelCase on the wire.
- User-facing text comes from `app.locals` (`msg.<file>.<key>`). Do not write inline strings in responses.
- Read configuration through `get_settings()`. Do not read `os.environ` directly.
- Security policy values (lockouts, TTLs, OTP limits) live in `configs/policy.py`.
- Cache with `@cache(ttl=..., key=...)` from cashews. Run background work with `enqueue(...)` from `infrastructure/queue.py`.
- Before writing a helper, check whether a package already in `pyproject.toml` does the job. Prefer the package.
- Avoid over-engineering. Do not add an abstraction layer until a second caller needs it. Comment only to explain a non-obvious reason. Line length is 130.

## Commits

- One line: `__type: subject`. No body.
- Types: `__feat` (new feature), `__update` (change or improvement), `__fix` (bug fix), `__mod` (general modification).
- Lowercase, plain words, about 4 to 10 words, one idea.
- No AI attribution: no `Co-Authored-By`, no "Generated with" lines, no session links.
- Commit only when asked. Never commit to `main`. Work on `beta`.
