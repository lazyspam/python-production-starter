"""Google and Apple sign-in. The client gets an ID token from the provider; we verify it against the provider's keys."""

from dataclasses import dataclass

import jwt
from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.settings import get_settings
from app.core.audit import service as audit
from app.core.auth import repository as repo
from app.core.auth.login import LoginResult, finish_login
from app.core.auth.models import AuthProvider, Credential, IdentifierType, Profile, User, UserStatus
from app.core.auth.repository import normalize_email
from app.core.auth.tokens import unauthorized
from app.locals import msg


@dataclass(frozen=True)
class _Provider:
    jwks_url: str
    issuers: tuple[str, ...]


_PROVIDERS = {
    AuthProvider.GOOGLE: _Provider(
        "https://www.googleapis.com/oauth2/v3/certs", ("https://accounts.google.com", "accounts.google.com")
    ),
    AuthProvider.APPLE: _Provider("https://appleid.apple.com/auth/keys", ("https://appleid.apple.com",)),
}
_jwks = {provider: jwt.PyJWKClient(config.jwks_url) for provider, config in _PROVIDERS.items()}


@dataclass(frozen=True)
class Identity:
    provider: AuthProvider
    provider_id: str
    email: str | None
    email_verified: bool
    name: str | None


async def verify_id_token(provider: AuthProvider, id_token: str) -> Identity:
    s = get_settings()
    audiences = s.google_client_ids if provider == AuthProvider.GOOGLE else s.apple_client_ids
    if not audiences:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.oauth_not_configured)
    try:
        signing_key = await run_in_threadpool(_jwks[provider].get_signing_key_from_jwt, id_token)
        claims = jwt.decode(
            id_token, signing_key.key, algorithms=["RS256", "ES256"], audience=audiences,
            issuer=list(_PROVIDERS[provider].issuers), options={"require": ["exp", "iat", "sub"]},
        )  # fmt: skip
    except jwt.PyJWTError as exc:
        raise unauthorized(msg.auth.oauth_token_invalid) from exc
    email = claims.get("email")
    return Identity(
        provider=provider,
        provider_id=claims["sub"],
        email=email,
        email_verified=bool(email) and str(claims.get("email_verified")).lower() == "true",
        name=claims.get("name"),
    )


async def login_or_create(db: AsyncSession, identity: Identity) -> LoginResult:
    credential = await repo.find_credential_by_identity(db, identity.provider, identity.provider_id)
    existing = await db.get(User, credential.user_id) if credential else None
    if existing and existing.is_deleted is False:
        if existing.status != UserStatus.ACTIVE:
            raise unauthorized(msg.auth.account_no_longer_available)
        result = await finish_login(db, existing.id)
        if result.tokens:
            await audit.record(
                "oauth.login", user_id=existing.id, resource_type="user", resource_id=existing.id,
                metadata={"provider": identity.provider},
            )  # fmt: skip
        return result
    if existing:
        raise unauthorized(msg.auth.account_no_longer_available)

    email = normalize_email(identity.email) if identity.email else None
    # Never attach to an account by email alone: the owner links providers from inside their account.
    if email and await repo.find_identifier(db, IdentifierType.EMAIL, email):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_email_conflict)
    if email and not identity.email_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.oauth_email_unverified)

    user = User()
    db.add(user)
    await db.flush()
    db.add(Credential(user_id=user.id, provider=identity.provider, provider_id=identity.provider_id))
    if identity.name:
        db.add(Profile(user_id=user.id, name=identity.name))
    if email:
        db.add(repo.new_identifier(user.id, IdentifierType.EMAIL, email, primary=True, verified=True))
    await db.commit()

    result = await finish_login(db, user.id)
    await audit.record(
        "oauth.login", user_id=user.id, resource_type="user", resource_id=user.id,
        metadata={"provider": identity.provider, "created": True},
    )  # fmt: skip
    return result


async def link(db: AsyncSession, user_id: str, identity: Identity) -> None:
    existing = await repo.find_credential_by_identity(db, identity.provider, identity.provider_id)
    if existing:
        if existing.user_id != user_id:
            raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_account_conflict)
        return
    if await repo.find_credential(db, user_id, identity.provider):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_account_conflict)
    db.add(Credential(user_id=user_id, provider=identity.provider, provider_id=identity.provider_id))
    await db.commit()
    await audit.record(
        "oauth.linked", user_id=user_id, resource_type="user", resource_id=user_id,
        metadata={"provider": identity.provider},
    )  # fmt: skip


async def unlink(db: AsyncSession, user_id: str, provider: AuthProvider) -> None:
    await repo.lock_user(db, user_id)
    credential = await repo.find_credential(db, user_id, provider)
    if not credential:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.oauth_not_linked)
    password = await repo.find_credential(db, user_id, AuthProvider.EMAIL)
    other = AuthProvider.APPLE if provider == AuthProvider.GOOGLE else AuthProvider.GOOGLE
    if not (password and password.password_hash) and not await repo.find_credential(db, user_id, other):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.cannot_unlink_last_login_method)
    await db.delete(credential)
    await db.commit()
    await audit.record(
        "oauth.unlinked", user_id=user_id, resource_type="user", resource_id=user_id,
        metadata={"provider": provider},
    )  # fmt: skip
