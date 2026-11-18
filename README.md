# yescrypt

Pure-Python yescrypt password hashing. It uses only the standard library and runs on Python 2.6 and on Python 3.

It creates and verifies `$y$` hash strings compatible with libxcrypt, the crypt library used by many Linux distributions for `ENCRYPT_METHOD YESCRYPT`. Hashes made here can be checked by libcrypt, and the reverse also works.

## Installation

```
python setup.py install
```

Or use the package directly by putting the `yescrypt/` directory on `PYTHONPATH`.

## Usage

```python
import yescrypt

hashed = yescrypt.hash_password('correct horse battery staple')
# '$y$j9T$<salt>$<43-character digest>'

yescrypt.verify('correct horse battery staple', hashed)  # True
yescrypt.verify('wrong', hashed)                         # False
```

### `hash_password(password, salt=None, N=4096, r=32, p=1, t=0)`

Returns a hash string. `password` may be text (encoded as UTF-8) or bytes.

* `salt`: bytes or text, 1 to 64 bytes long. If omitted, 16 random bytes come from `os.urandom`.
* `N`: CPU/memory cost, a power of 2 greater than `p`. The default is 4096.
* `r`: block size. The default is 32. Working memory is about 128 × r × N bytes, which is 16 MiB for the defaults.
* `p`: parallelism. The default is 1.
* `t`: extra time cost. The default is 0.

Raises `ValueError` for invalid parameters or salt length, and `TypeError` for a password that isn't text or bytes.

### `verify(password, hashed)`

Returns `True` if `password` produces `hashed`, otherwise `False`. The hash can be text or bytes. A malformed or unsupported hash string also returns `False` and does not raise an exception. The comparison runs in constant time.

## Supported settings

* The default RW flavor (`$y$j...`), which is the one libxcrypt produces.
* Any valid `N`, `r`, `p` and `t`. The pre-hash pass that libxcrypt uses for large `N` is included.

Not supported, and rejected with `ValueError` or `False` from `verify`:

* The ROM and NROM modes.
* Hash upgrade (`g` greater than 0).
* Other flavors, including plain scrypt.

## Performance

This is pure Python, so it is slow compared with the C implementation. The default settings take several seconds for each hash. Verification costs the same as hashing, because it recomputes the hash with the parameters stored in the string. For a login system, a native libcrypt binding is a better choice.

## Testing

```
python tests/test_yescrypt.py
```

The default run takes about a minute and a quarter. To also run the two large-parameter vectors (about one minute more), set `YESCRYPT_SLOW_TESTS=1`.

The test vectors were generated once with the system libcrypt. The test suite does not use libcrypt. The scripts in `tests/` that call libcrypt (`gen_vectors.py`, `probe_settings.py`, `gen_extra.py`, `check_vectors.py`) are development helpers and are not needed to use the library.

## Layout

```
yescrypt/
    __init__.py   hash_password() and verify()
    _core.py      yescrypt RW calculation (port of yescrypt-ref.c)
    _encoding.py  base64 and $y$ setting encoding
    _compat.py    text/bytes, constant-time compare, HMAC and PBKDF2
tests/            unit tests and development helpers
```

