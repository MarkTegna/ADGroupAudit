"""Password encoding/decoding utilities for AD Group Audit.

Uses base64 encoding with an 'ENC:' prefix to indicate encoded values.
This is encoding (not encryption) per the requirements.
"""

import base64

ENC_PREFIX = "ENC:"


def encode_password(plaintext: str) -> str:
    """Return 'ENC:' + base64-encoded plaintext."""
    encoded = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
    return f"{ENC_PREFIX}{encoded}"


def decode_password(value: str) -> str:
    """If value starts with 'ENC:', base64-decode the remainder. Otherwise return as-is."""
    if is_encoded(value):
        encoded_part = value[len(ENC_PREFIX):]
        return base64.b64decode(encoded_part.encode("utf-8")).decode("utf-8")
    return value


def is_encoded(value: str) -> bool:
    """Return True if value starts with 'ENC:' prefix."""
    return value.startswith(ENC_PREFIX)
