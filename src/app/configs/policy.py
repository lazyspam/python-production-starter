"""Auth and OTP policy. These are security decisions: change them in code review, not per environment."""

LOGIN_MAX_FAILS = 10
"""Per identity and client IP."""
LOGIN_MAX_FAILS_PER_IDENTITY = 100
"""Per identity from any IP: stops a distributed guess without letting one IP lock the owner out."""
LOGIN_LOCKOUT_TTL = 900
PASSWORD_RESET_TTL = 600
PASSWORD_RESET_CHALLENGE_TTL = 600
EMAIL_VERIFY_TTL = 600
TWO_FACTOR_CHALLENGE_TTL = 180
IDENTIFIER_CHANGE_TTL = 600
SUDO_GRANT_TTL = 600
IDENTIFIER_RECLAIM_GRACE = 30 * 24 * 3600

OTP_LENGTH = 6
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60
OTP_TTL = 600
OTP_SUDO_TTL = 180
OTP_MAX_SENDS_PER_WINDOW = 5
OTP_SEND_WINDOW = 3600

# Per user, across challenges and sessions: a stolen password or session can't keep guessing second factors.
TWO_FACTOR_MAX_FAILS = 10
TWO_FACTOR_LOCKOUT_TTL = 900
SUDO_MAX_FAILS = 5
SUDO_LOCKOUT_TTL = 900

BACKUP_CODE_COUNT = 10
BACKUP_CODE_BYTES = 5
APPLE_RELAY_DOMAIN = "@privaterelay.appleid.com"
