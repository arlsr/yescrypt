# yescrypt password hashing, pure Python.

import os

from ._compat import constant_time_equal, text_type, to_bytes
from ._core import yescrypt_rw
from ._encoding import encode_bytes, format_setting, parse_setting

__version__ = '1.0.0'
__author__ = 'github.com/arlsr'
__all__ = ['hash_password', 'verify']


def _check_params(N, r, p, t):
    if N < 2 or N & (N - 1):
        raise ValueError('N must be a power of 2 greater than 1')
    if r < 1 or p < 1 or t < 0:
        raise ValueError('r and p must be at least 1, t must not be negative')
    if N // p <= 1:
        raise ValueError('N must be greater than p')
    if r * p >= (1 << 30):
        raise ValueError('r * p is too large')


def hash_password(password, salt=None, N=4096, r=32, p=1, t=0):
    """Return a '$y$...' yescrypt hash string for password."""
    if salt is None:
        salt = os.urandom(16)
    salt = to_bytes(salt)
    if not 1 <= len(salt) <= 64:
        raise ValueError('salt must be 1 to 64 bytes')
    _check_params(N, r, p, t)
    setting = format_setting(N, r, p, t, salt)
    digest = yescrypt_rw(to_bytes(password), salt, N, r, p, t)
    return setting + '$' + encode_bytes(digest)


def verify(password, hashed):
    """Return True if password matches the yescrypt hash string hashed."""
    try:
        if not isinstance(hashed, text_type):
            hashed = hashed.decode('ascii')
        head, _, _ = hashed.rpartition('$')
        params = parse_setting(head)
        _check_params(params['N'], params['r'], params['p'], params['t'])
        digest = yescrypt_rw(to_bytes(password), params['salt'],
                             params['N'], params['r'], params['p'], params['t'])
        candidate = head + '$' + encode_bytes(digest)
    except (ValueError, UnicodeError):
        return False
    return constant_time_equal(candidate, hashed)
