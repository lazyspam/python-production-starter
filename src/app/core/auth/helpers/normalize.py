from app.core.auth.models import IdentifierType


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    trimmed = phone.strip()
    digits = "".join(c for c in trimmed if c.isdigit())
    return f"+{digits}" if trimmed.startswith("+") else digits


def resolve_identifier(raw: str) -> tuple[IdentifierType, str]:
    raw = raw.strip()
    return (IdentifierType.EMAIL, normalize_email(raw)) if "@" in raw else (IdentifierType.PHONE, normalize_phone(raw))
