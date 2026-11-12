"""Google and Apple sign-in. The client gets an ID token from the provider; we verify it against the provider's keys."""

from dataclasses import dataclass

import jwt
from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.security import sha256
from app.configs.settings import get_settings
from app.core.audit.services import audit
from app.core.auth.helpers.normalize import normalize_email
from app.core.auth.models import AuthProvider, IdentifierType, UserStatus
from app.core.auth.repositories import credential as credential_repo
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services.login import LoginResult, finish_login
from app.core.auth.services.tokens import unauthorized
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


async def verify_id_token(provider: AuthProvider, id_token: str, nonce: str | None = None) -> Identity:
    """`nonce` is the raw value the client gave the provider; the token may carry it as is or as its SHA-256 (Apple)."""
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
    if nonce and claims.get("nonce") not in (nonce, sha256(nonce)):
        raise unauthorized(msg.auth.oauth_token_invalid)
    email = claims.get("email")
    return Identity(
        provider=provider,
        provider_id=claims["sub"],
        email=email,
        email_verified=bool(email) and str(claims.get("email_verified")).lower() == "true",
        name=claims.get("name"),
    )


async def login_or_create(db: AsyncSession, identity: Identity, *, retry: bool = True) -> LoginResult:
    credential = await credential_repo.find_credential_by_identity(db, identity.provider, identity.provider_id)
    existing = await user_repo.get_user(db, credential.user_id) if credential else None
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
    if email and await identifier_repo.find_identifier(db, IdentifierType.EMAIL, email):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_email_conflict)
    if email and not identity.email_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.oauth_email_unverified)

    user = await user_repo.add_user(db)
    await db.flush()
    await credential_repo.add_credential(db, user.id, identity.provider, identity.provider_id)
    if identity.name:
        await user_repo.add_profile(db, user.id, identity.name)
    if email:
        await identifier_repo.add_identifier(db, user.id, IdentifierType.EMAIL, email, primary=True, verified=True)
    try:
        await db.commit()
    except IntegrityError:
        # A concurrent first sign-in created the credential or took the email: run again against what now exists.
        await db.rollback()
        if not retry:
            raise
        return await login_or_create(db, identity, retry=False)

    result = await finish_login(db, user.id)
    await audit.record(
        "oauth.login", user_id=user.id, resource_type="user", resource_id=user.id,
        metadata={"provider": identity.provider, "created": True},
    )  # fmt: skip
    return result


async def link(db: AsyncSession, user_id: str, identity: Identity) -> None:
    existing = await credential_repo.find_credential_by_identity(db, identity.provider, identity.provider_id)
    if existing:
        if existing.user_id != user_id:
            raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_account_conflict)
        return
    if await credential_repo.find_credential(db, user_id, identity.provider):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.oauth_account_conflict)
    await credential_repo.add_credential(db, user_id, identity.provider, identity.provider_id)
    await db.commit()
    await audit.record(
        "oauth.linked", user_id=user_id, resource_type="user", resource_id=user_id,
        metadata={"provider": identity.provider},
    )  # fmt: skip


async def unlink(db: AsyncSession, user_id: str, provider: AuthProvider) -> None:
    await user_repo.lock_user(db, user_id)
    credential = await credential_repo.find_credential(db, user_id, provider)
    if not credential:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.oauth_not_linked)
    password = await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL)
    other = AuthProvider.APPLE if provider == AuthProvider.GOOGLE else AuthProvider.GOOGLE
    if not (password and password.password_hash) and not await credential_repo.find_credential(db, user_id, other):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.cannot_unlink_last_login_method)
    await credential_repo.delete_credential(db, credential)
    await db.commit()
    await audit.record(
        "oauth.unlinked", user_id=user_id, resource_type="user", resource_id=user_id,
        metadata={"provider": provider},
    )  # fmt: skip


def _provider_named(name: str) -> AuthProvider:
    provider = {"google": AuthProvider.GOOGLE, "apple": AuthProvider.APPLE}.get(name)
    if provider is None:
        raise unauthorized(msg.auth.oauth_token_invalid)
    return provider


async def sign_in(db: AsyncSession, provider: AuthProvider, id_token: str, nonce: str | None = None) -> LoginResult:
    return await login_or_create(db, await verify_id_token(provider, id_token, nonce))


async def link_account(db: AsyncSession, user_id: str, provider_name: str, id_token: str, nonce: str | None = None) -> None:
    provider = _provider_named(provider_name)
    await link(db, user_id, await verify_id_token(provider, id_token, nonce))


async def unlink_account(db: AsyncSession, user_id: str, provider_name: str) -> None:
    await unlink(db, user_id, _provider_named(provider_name))
