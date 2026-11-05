def _segment(value: str) -> str:
    if len(value) <= 1:
        return "*"
    if len(value) == 2:
        return f"{value[0]}*"
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return _segment(email)
    host, dot, tld = domain.partition(".")
    return f"{_segment(local)}@{_segment(host)}{dot}{tld}"


def mask_phone(phone: str) -> str:
    return f"•••• {''.join(c for c in phone if c.isdigit())[-4:]}"
