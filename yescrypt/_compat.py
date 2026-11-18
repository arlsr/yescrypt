"""Compatibility helpers for Python 2.6 through Python 3.x."""

import hashlib
import hmac
import struct

try:
    text_type = unicode  # noqa: F821 (Python 2)
except NameError:
    text_type = str


def to_bytes(value):
    """Return value as bytes. Text is encoded as UTF-8."""
    if isinstance(value, text_type):
        return value.encode('utf-8')
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError('expected text or bytes, got %s' % type(value).__name__)


def constant_time_equal(a, b):
    """Compare two byte strings without returning early on the first mismatch."""
    a = bytearray(to_bytes(a))
    b = bytearray(to_bytes(b))
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def sha256_digest(data):
    """Return SHA-256 digest of data as bytes."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key, message):
    """Return HMAC-SHA256 digest as bytes."""
    return hmac.new(key, message, hashlib.sha256).digest()


def pbkdf2_sha256(password, salt, iterations, dklen):
    """PBKDF2-HMAC-SHA256. Uses hashlib when available (2.7.8+, 3.4+)."""
    pbkdf2 = getattr(hashlib, 'pbkdf2_hmac', None)
    if pbkdf2 is not None:
        return pbkdf2('sha256', password, salt, iterations, dklen)
    return _pbkdf2_fallback(password, salt, iterations, dklen)


def _pbkdf2_fallback(password, salt, iterations, dklen):
    hlen = hashlib.sha256().digest_size
    blocks = []
    block_index = 1
    total = 0
    while total < dklen:
        u = hmac_sha256(password, salt + struct.pack('>I', block_index))
        acc = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            for i in range(hlen):
                acc[i] ^= bytearray(u)[i]
        blocks.append(bytes(acc))
        total += hlen
        block_index += 1
    return b''.join(blocks)[:dklen]
