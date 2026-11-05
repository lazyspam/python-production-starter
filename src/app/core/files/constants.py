KEY_PREFIX = "uploads"
LIST_LIMIT = 50
# Allowlist, not a UX hint: extend deliberately.
ALLOWED_CONTENT_TYPES = (
    "image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "application/pdf",
    "application/zip", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain", "text/csv", "video/mp4", "video/webm", "audio/mpeg", "audio/webm",
)  # fmt: skip
