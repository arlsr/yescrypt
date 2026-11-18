# Development helper: prints known-good yescrypt hashes from the system libcrypt.
# Not used by the library or the test suite at runtime.
import ctypes
import sys

lc = ctypes.CDLL('libcrypt.so.1')
lc.crypt.restype = ctypes.c_char_p
lc.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

settings = [
    b'$y$j9T$saltsaltsaltsalt',
    b'$y$j5T$saltsaltsaltsalt',
    b'$y$j6T$saltsaltsaltsalt',
    b'$y$j8T$saltsaltsaltsalt',
    b'$y$j9$saltsaltsaltsalt',
]

for s in settings:
    out = lc.crypt(b'password', s)
    sys.stdout.write('%r -> %r\n' % (s, out))
