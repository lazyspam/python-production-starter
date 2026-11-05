"""Mail and SMS. Callers enqueue; the worker process delivers with retries."""

from email.message import EmailMessage

import aiosmtplib
import structlog
from fastapi.concurrency import run_in_threadpool
from twilio.rest import Client

from app.configs.settings import get_settings
from app.infrastructure.queue import MAIL_QUEUE, SMS_QUEUE, enqueue

log = structlog.get_logger()


async def queue_mail(to: str, subject: str, text: str, html: str | None = None) -> None:
    await enqueue(MAIL_QUEUE, "send", {"to": to, "subject": subject, "text": text, "html": html})


async def queue_sms(to: str, body: str) -> None:
    await enqueue(SMS_QUEUE, "send", {"to": to, "body": body})


async def deliver_mail(to: str, subject: str, text: str, html: str | None = None) -> None:
    s = get_settings()
    if not s.mail_user:
        log.warning("mail_not_configured", to=to, subject=subject)
        return
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = s.mail_from, to, subject
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    await aiosmtplib.send(
        message, hostname=s.mail_host, port=s.mail_port, username=s.mail_user, password=s.mail_pass,
        use_tls=s.mail_secure, start_tls=not s.mail_secure,
    )  # fmt: skip


def sms_configured() -> bool:
    s = get_settings()
    return bool(s.twilio_account_sid and s.twilio_auth_token and s.twilio_from_number)


async def deliver_sms(to: str, body: str) -> None:
    s = get_settings()
    if not sms_configured():
        log.warning("sms_not_configured", to=to)
        return
    client = Client(s.twilio_account_sid, s.twilio_auth_token)
    await run_in_threadpool(client.messages.create, to=to, from_=s.twilio_from_number, body=body)
