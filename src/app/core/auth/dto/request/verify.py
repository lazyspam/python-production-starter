from app.core.auth.dto.request.common import CodeIn, EmailIn, PhoneIn


class EmailCodeIn(EmailIn, CodeIn):
    pass


class PhoneCodeIn(PhoneIn, CodeIn):
    pass
