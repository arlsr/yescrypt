# yescrypt setting and hash encoding, ported from yescrypt-common.c (1.0.3).

ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
ATOI64 = dict((c, i) for i, c in enumerate(ITOA64))

# Flavor character 'j' decodes to 47, which maps to RW flags 0xB6
# (ROUNDS_6 | GATHER_4 | SIMPLE_2 | SBOX_12K | RW).
DEFAULT_FLAVOR = 47


def encode_uint(value, minv):
    """Variable-length base64 integer, as used for N, r, p, t in settings."""
    if value < minv:
        raise ValueError('value below minimum')
    value -= minv
    start, end, chars, bits = 0, 47, 1, 0
    while True:
        count = (end + 1 - start) << bits
        if value < count:
            break
        if start >= 63:
            raise ValueError('value too large')
        start = end + 1
        end = start + (62 - end) // 2
        value -= count
        chars += 1
        bits += 6
    out = [ITOA64[start + (value >> bits)]]
    for _ in range(chars - 1):
        bits -= 6
        out.append(ITOA64[(value >> bits) & 0x3f])
    return ''.join(out)


def decode_uint(s, pos, minv):
    """Read one variable-length integer from s at pos. Returns (value, newpos)."""
    start, end, chars, bits = 0, 47, 1, 0
    c = _atoi(s, pos)
    pos += 1
    val = minv
    while c > end:
        val += (end + 1 - start) << bits
        start = end + 1
        end = start + (62 - end) // 2
        chars += 1
        bits += 6
    val += (c - start) << bits
    for _ in range(chars - 1):
        c = _atoi(s, pos)
        pos += 1
        bits -= 6
        val += c << bits
    return val, pos


def _atoi(s, pos):
    if pos >= len(s):
        raise ValueError('truncated setting')
    c = ATOI64.get(s[pos], 64)
    if c > 63:
        raise ValueError('invalid character in setting')
    return c


def encode_bytes(data):
    """Encode bytes as yescrypt base64 (little-endian bit stream, 6 bits per char)."""
    out = []
    acc = 0
    bits = 0
    for b in bytearray(data):
        acc |= b << bits
        bits += 8
        while bits >= 6:
            out.append(ITOA64[acc & 0x3f])
            acc >>= 6
            bits -= 6
    if bits:
        out.append(ITOA64[acc & 0x3f])
    return ''.join(out)


def decode_bytes(s):
    """Decode yescrypt base64 text to bytes. Trailing pad bits are ignored."""
    out = bytearray()
    acc = 0
    bits = 0
    for ch in s:
        v = ATOI64.get(ch, 64)
        if v > 63:
            raise ValueError('invalid base64 character')
        acc |= v << bits
        bits += 6
        while bits >= 8:
            out.append(acc & 0xff)
            acc >>= 8
            bits -= 8
    return bytes(out)


def parse_setting(setting):
    """Parse '$y$<params>$<salt>' into a dict with N, r, p, t and salt bytes."""
    if not setting.startswith('$y$'):
        raise ValueError('not a yescrypt setting')
    flavor, pos = decode_uint(setting, 3, 0)
    if flavor != DEFAULT_FLAVOR:
        raise ValueError('unsupported yescrypt flavor')
    n_log2, pos = decode_uint(setting, pos, 1)
    if n_log2 > 63:
        raise ValueError('N out of range')
    r, pos = decode_uint(setting, pos, 1)
    p, t = 1, 0
    if setting[pos:pos + 1] != '$':
        have, pos = decode_uint(setting, pos, 1)
        if have & ~3:
            raise ValueError('unsupported yescrypt parameters')
        if have & 1:
            p, pos = decode_uint(setting, pos, 2)
        if have & 2:
            t, pos = decode_uint(setting, pos, 1)
    if setting[pos:pos + 1] != '$':
        raise ValueError('malformed yescrypt setting')
    salt = decode_bytes(setting[pos + 1:])
    return {'N': 1 << n_log2, 'r': r, 'p': p, 't': t, 'salt': salt}


def format_setting(N, r, p, t, salt):
    """Build '$y$<params>$<salt>' for the default flavor."""
    n_log2 = N.bit_length() - 1 if hasattr(N, 'bit_length') else _log2(N)
    have = (1 if p != 1 else 0) | (2 if t else 0)
    out = ['$y$', ITOA64[DEFAULT_FLAVOR], encode_uint(n_log2, 1), encode_uint(r, 1)]
    if have:
        out.append(encode_uint(have, 1))
    if p != 1:
        out.append(encode_uint(p, 2))
    if t:
        out.append(encode_uint(t, 1))
    out.append('$')
    out.append(encode_bytes(salt))
    return ''.join(out)


def _log2(N):
    n = 0
    while (1 << (n + 1)) <= N:
        n += 1
    return n
