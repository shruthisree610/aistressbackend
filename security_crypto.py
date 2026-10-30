"""
NIVARA Cryptographic Protection Module — Task 7
Authenticated Encryption at Rest using AES-256-GCM.

- Protects confidential safety-plan notes, emergency notes, trusted contacts, duress words, safe havens, and evidence.
- Cryptographically secure 96-bit random nonces per encryption operation.
- 128-bit authentication tag detects any data corruption or tampering.
- Zero key hardcoding in source code — strictly loaded from environment configuration (DATA_ENCRYPTION_KEY / NIVARA_ENCRYPTION_KEY).
- Fail-safe: missing or unconfigured encryption keys raise EncryptionConfigError, preventing silent fallback to plaintext.
"""

import os
import json
import base64
import logging
from typing import Any, Optional, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

PREFIX_V1 = "enc:v1:"


class EncryptionError(Exception):
    """Base exception for cryptographic errors."""
    pass


class EncryptionConfigError(EncryptionError):
    """Raised when encryption key is missing, invalid, or misconfigured."""
    pass


class DecryptionError(EncryptionError):
    """Raised when ciphertext authentication fails or data is tampered with."""
    pass


def get_encryption_key() -> bytes:
    """
    Retrieves the 256-bit AES encryption key from environment configuration.
    Fails safely if missing or invalid — NEVER falls back to hardcoded default keys.
    """
    raw_key = os.environ.get("DATA_ENCRYPTION_KEY") or os.environ.get("NIVARA_ENCRYPTION_KEY")
    if not raw_key:
        raise EncryptionConfigError(
            "CRITICAL: DATA_ENCRYPTION_KEY environment variable is not configured. "
            "Refusing operation to prevent silent unencrypted plaintext storage."
        )

    raw_key = raw_key.strip()
    # Check if 64-character hex string (32 bytes)
    if len(raw_key) == 64:
        try:
            return bytes.fromhex(raw_key)
        except ValueError:
            pass

    # Check if base64 encoded 32 bytes
    try:
        decoded = base64.b64decode(raw_key)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    # If raw bytes encoded as UTF-8 of exactly 32 bytes
    key_bytes = raw_key.encode("utf-8")
    if len(key_bytes) == 32:
        return key_bytes

    raise EncryptionConfigError(
        f"Invalid encryption key length ({len(raw_key)} chars). "
        "A valid 256-bit AES key must be 64 hex characters or 32 bytes."
    )


def is_encrypted(value: Any) -> bool:
    """Checks if a string has the Nivara authenticated encryption prefix."""
    return isinstance(value, str) and value.startswith(PREFIX_V1)


def encrypt_value(value: Any) -> Optional[str]:
    """
    Encrypts a string, dictionary, or list using AES-256-GCM.
    Returns formatted ciphertext string: 'enc:v1:<base64(nonce + ciphertext + tag)>'.
    Fails safely if encryption key is missing or invalid.
    """
    if value is None:
        return None

    # Already encrypted?
    if isinstance(value, str) and value.startswith(PREFIX_V1):
        return value

    # If dict or list, serialize to JSON
    if isinstance(value, (dict, list)):
        plaintext_bytes = json.dumps(value, ensure_ascii=False).encode("utf-8")
    elif isinstance(value, str):
        plaintext_bytes = value.encode("utf-8")
    elif isinstance(value, bytes):
        plaintext_bytes = value
    else:
        plaintext_bytes = str(value).encode("utf-8")

    key = get_encryption_key()
    aesgcm = AESGCM(key)

    # 96-bit (12 bytes) cryptographically secure random nonce
    nonce = os.urandom(12)

    # AES-GCM seal: returns ciphertext + 16-byte authentication tag
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Package: nonce (12 bytes) + ciphertext + tag
    payload = nonce + ciphertext
    b64_payload = base64.b64encode(payload).decode("ascii")

    return f"{PREFIX_V1}{b64_payload}"


def decrypt_value(enc_string: Any, fallback_to_raw_on_unencrypted: bool = True) -> Any:
    """
    Decrypts an AES-256-GCM encrypted string.
    - If the value does not have the 'enc:v1:' prefix and fallback is True,
      treats it as legacy plaintext and returns it without claiming it was encrypted.
    - If ciphertext or tag is modified/tampered, raises DecryptionError.
    - Automatically parses JSON dicts/lists back to their original types.
    """
    if enc_string is None:
        return None

    if not isinstance(enc_string, str):
        return enc_string

    if not enc_string.startswith(PREFIX_V1):
        if fallback_to_raw_on_unencrypted:
            return enc_string
        raise DecryptionError("Value is not an encrypted payload.")

    raw_b64 = enc_string[len(PREFIX_V1):]
    try:
        payload = base64.b64decode(raw_b64)
    except Exception as e:
        raise DecryptionError(f"Malformed base64 ciphertext: {e}") from e

    if len(payload) < 12 + 16:  # nonce (12) + tag (16)
        raise DecryptionError("Ciphertext payload too short to be valid AES-GCM.")

    nonce = payload[:12]
    ciphertext_and_tag = payload[12:]

    key = get_encryption_key()
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag as e:
        raise DecryptionError(
            "Decryption failed: Authentication tag mismatch. "
            "Data has been tampered with, corrupted, or an incorrect encryption key was used."
        ) from e
    except Exception as e:
        raise DecryptionError(f"Decryption error: {e}") from e

    decrypted_str = decrypted_bytes.decode("utf-8")
    # Try parsing as JSON if it was a serialized dict/list
    if (decrypted_str.startswith("{") and decrypted_str.endswith("}")) or \
       (decrypted_str.startswith("[") and decrypted_str.endswith("]")):
        try:
            return json.loads(decrypted_str)
        except Exception:
            pass

    return decrypted_str
