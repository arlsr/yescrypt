# Development helper: libcrypt vectors covering p, t, salt lengths, passwords.
# Prints Python tuples to paste into tests. Not used at runtime.
import ctypes
import sys
sys.path.insert(0, '.')
from yescrypt._encoding import format_setting

lc = ctypes.CDLL('libcrypt.so.1')
lc.crypt.restype = ctypes.c_char_p
lc.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

SALT = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

# (password, salt_len, N, r, p, t)
CASES = [
    (b'', 16, 16, 8, 1, 0),
    (b'pw', 1, 32, 8, 1, 0),
    (b'p\xc3\xa4ssw\xc3\xb6rd', 16, 64, 8, 2, 0),
    (b'password', 16, 64, 4, 1, 1),
    (b'password', 24, 128, 8, 2, 2),
    (b'password', 64, 1024, 8, 4, 0),
    (b'x' * 100, 16, 256, 1, 1, 3),
    (b'password', 16, 16384, 8, 1, 0),
    (b'password', 16, 8192, 32, 2, 0),
]

for pw, sl, N, r, p, t in CASES:
    salt = SALT[:sl]
    setting = format_setting(N, r, p, t, salt).encode('ascii')
    out = lc.crypt(pw, setting)
    sys.stdout.write('%r\n' % ((pw, setting.decode('ascii'), out.decode('ascii')),))
