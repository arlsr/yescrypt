# Development helper: maps the characters that follow '$y$j9' to the r value libcrypt uses.
import ctypes
import sys

lc = ctypes.CDLL('libcrypt.so.1')
lc.crypt.restype = ctypes.c_char_p
lc.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

ALPHA = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

for i in range(len(ALPHA)):
    c = ALPHA[i:i + 1]
    setting = b'$y$j9' + c + b'$saltsaltsaltsalt'
    out = lc.crypt(b'password', setting)
    ok = out is not None and out.startswith(b'$y$')
    sys.stdout.write('%s %d %s\n' % (c.decode('ascii'), i, 'valid' if ok else 'invalid'))
