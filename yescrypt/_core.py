# This file is a Python port of yescrypt-ref.c from yescrypt 1.0.3, which
# carries this license:
#
# Copyright 2009 Colin Percival
# Copyright 2013-2018 Alexander Peslyak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""Pure-Python port of the yescrypt reference (yescrypt-ref.c, 1.0.3).

Only the RW flavor with the default pwxform settings is implemented, which
is what the 'j' flavor in '$y$' strings selects. Words are kept as Python
ints in the same layout the C code uses, so the port can be checked step by
step against it.
"""

import struct

from ._compat import hmac_sha256, pbkdf2_sha256, sha256_digest

M = 0xFFFFFFFF

# Salsa20 quarter-round schedule: (dst, src1, src2, rotation).
# Each step is x[dst] ^= rotl32((x[src1] + x[src2]) mod 2^32, rotation).
_SALSA_OPS = (
    (4, 0, 12, 7), (8, 4, 0, 9), (12, 8, 4, 13), (0, 12, 8, 18),
    (9, 5, 1, 7), (13, 9, 5, 9), (1, 13, 9, 13), (5, 1, 13, 18),
    (14, 10, 6, 7), (2, 14, 10, 9), (6, 2, 14, 13), (10, 6, 2, 18),
    (3, 15, 11, 7), (7, 3, 15, 9), (11, 7, 3, 13), (15, 11, 7, 18),
    (1, 0, 3, 7), (2, 1, 0, 9), (3, 2, 1, 13), (0, 3, 2, 18),
    (6, 5, 4, 7), (7, 6, 5, 9), (4, 7, 6, 13), (5, 4, 7, 18),
    (11, 10, 9, 7), (8, 11, 10, 9), (9, 8, 11, 13), (10, 9, 8, 18),
    (12, 15, 14, 7), (13, 12, 15, 9), (14, 13, 12, 13), (15, 14, 13, 18),
)


def _rotl(v, b):
    return ((v << b) | (v >> (32 - b))) & M


def _salsa20(B, off, rounds):
    """Salsa20 core applied in place to the 16 words B[off:off+16]."""
    x = [0] * 16
    for i in range(16):
        x[(i * 5) % 16] = B[off + i]
    for _ in range(0, rounds, 2):
        for d, a, b, s in _SALSA_OPS:
            x[d] ^= _rotl((x[a] + x[b]) & M, s)
    for i in range(16):
        B[off + i] = (B[off + i] + x[(i * 5) % 16]) & M


def _blockmix_salsa8(B, Y, r):
    """BlockMix with Salsa20/8 over 2r blocks of 16 words, in place."""
    X = B[(2 * r - 1) * 16:2 * r * 16]
    for i in range(2 * r):
        for k in range(16):
            X[k] ^= B[i * 16 + k]
        _salsa20(X, 0, 8)
        Y[i * 16:(i + 1) * 16] = X
    for i in range(r):
        B[i * 16:(i + 1) * 16] = Y[2 * i * 16:(2 * i + 1) * 16]
    for i in range(r):
        B[(i + r) * 16:(i + r + 1) * 16] = Y[(2 * i + 1) * 16:(2 * i + 2) * 16]


def _pwxform(X, S, ctx):
    """pwxform over 16 words X (4 lanes x 2 pairs x 2 halves), in place.

    S is the flat list of S-box words. ctx = [s0, s1, s2, w] holds word
    offsets of the three 512-pair S-boxes and the write cursor w (in pairs).
    """
    s0, s1, s2, w = ctx
    for i in range(6):
        for j in range(4):
            xl = X[j * 4]
            xh = X[j * 4 + 1]
            p0 = s0 + ((xl & 0xFF0) >> 2)
            p1 = s1 + ((xh & 0xFF0) >> 2)
            for k in range(2):
                q0 = p0 + 2 * k
                q1 = p1 + 2 * k
                v0 = (S[q0 + 1] << 32) + S[q0]
                v1 = (S[q1 + 1] << 32) + S[q1]
                xl = X[j * 4 + k * 2]
                xh = X[j * 4 + k * 2 + 1]
                x = (xh * xl + v0) & 0xFFFFFFFFFFFFFFFF
                x ^= v1
                X[j * 4 + k * 2] = x & M
                X[j * 4 + k * 2 + 1] = x >> 32
                if i != 0 and i != 5:
                    S[s2 + 2 * w] = x & M
                    S[s2 + 2 * w + 1] = x >> 32
                    w += 1
    ctx[0], ctx[1], ctx[2] = s2, s0, s1
    ctx[3] = w & 511


def _blockmix_pwxform(B, Y, S, ctx, r):
    """BlockMix with pwxform and Salsa20/2 over 2r blocks, in place."""
    r1 = 2 * r
    Y[0:16] = B[(r1 - 1) * 16:r1 * 16]
    for i in range(r1):
        for k in range(16):
            Y[k] ^= B[i * 16 + k]
        _pwxform(Y, S, ctx)
        B[i * 16:(i + 1) * 16] = Y[0:16]
    _salsa20(B, (r1 - 1) * 16, 2)


def _integerify(B, r):
    base = (2 * r - 1) * 16
    return (B[base + 13] << 32) + B[base]


def _p2floor(x):
    while True:
        y = x & (x - 1)
        if not y:
            return x
        x = y


def _wrap(x, i):
    n = _p2floor(i)
    return (x & (n - 1)) + (i - n)


def _load_block_order(B, X, count):
    for k in range(count):
        for i in range(16):
            X[k * 16 + i] = B[k * 16 + (i * 5) % 16]


def _store_block_order(B, X, count):
    for k in range(count):
        for i in range(16):
            B[k * 16 + (i * 5) % 16] = X[k * 16 + i]


def _smix1(B, r, N, rw, V, voff, X, Y, S, ctx):
    s = 32 * r
    _load_block_order(B, X, 2 * r)
    for i in range(N):
        base = voff + i * s
        V[base:base + s] = X[0:s]
        if rw and i > 1:
            j = _wrap(_integerify(X, r), i)
            vb = voff + j * s
            for t in range(s):
                X[t] ^= V[vb + t]
        if ctx is not None:
            _blockmix_pwxform(X, Y, S, ctx, r)
        else:
            _blockmix_salsa8(X, Y, r)
    _store_block_order(B, X, 2 * r)


def _smix2(B, r, N, Nloop, rw, V, voff, X, Y, S, ctx):
    s = 32 * r
    _load_block_order(B, X, 2 * r)
    for _ in range(Nloop):
        j = _integerify(X, r) & (N - 1)
        vb = voff + j * s
        for t in range(s):
            X[t] ^= V[vb + t]
        if rw:
            V[vb:vb + s] = X[0:s]
        if ctx is not None:
            _blockmix_pwxform(X, Y, S, ctx, r)
        else:
            _blockmix_salsa8(X, Y, r)
    _store_block_order(B, X, 2 * r)


def _smix(B, r, N, p, t, passwd, V, X, Y):
    s = 32 * r
    Nchunk = N // p
    Nloop_all = Nchunk
    if t <= 1:
        if t:
            Nloop_all *= 2
        Nloop_all = (Nloop_all + 2) // 3
    else:
        Nloop_all *= t - 1
    Nloop_rw = Nloop_all // p
    Nchunk &= ~1
    Nloop_all = (Nloop_all + 1) & ~1
    Nloop_rw = (Nloop_rw + 1) & ~1
    Slists = [[0] * 3072 for _ in range(p)]
    ctxs = [[2048, 1024, 0, 0] for _ in range(p)]
    for i in range(p):
        Vchunk = i * Nchunk
        Np = Nchunk if i < p - 1 else N - Vchunk
        Bp = B[i * s:(i + 1) * s]
        S = Slists[i]
        ctx = ctxs[i]
        _smix1(Bp, 1, 96, False, S, 0, X, Y, None, None)
        if i == 0:
            key = struct.pack('<16I', *Bp[(2 * r - 1) * 16:2 * r * 16])
            passwd = hmac_sha256(key, passwd)
        _smix1(Bp, r, Np, True, V, Vchunk * s, X, Y, S, ctx)
        _smix2(Bp, r, _p2floor(Np), Nloop_rw, True, V, Vchunk * s, X, Y, S, ctx)
        B[i * s:(i + 1) * s] = Bp
    for i in range(p):
        Bp = B[i * s:(i + 1) * s]
        _smix2(Bp, r, N, Nloop_all - Nloop_rw, False, V, 0, X, Y, Slists[i], ctxs[i])
        B[i * s:(i + 1) * s] = Bp
    return passwd


def yescrypt_rw(passwd, salt, N, r, p, t):
    # Default 'j' flavor: RW with pwxform, 32-byte output.
    # Large parameters first run a smaller pre-hash pass (yescrypt_kdf).
    if N // p >= 0x100 and (N // p) * r >= 0x20000:
        passwd = _kdf_body(passwd, salt, N >> 6, r, p, 0, True)
    return _kdf_body(passwd, salt, N, r, p, t, False)


def _kdf_body(passwd, salt, N, r, p, t, prehash):
    key = b'yescrypt-prehash' if prehash else b'yescrypt'
    passwd = hmac_sha256(key, passwd)
    n = 32 * r * p
    B = list(struct.unpack('<%dI' % n, pbkdf2_sha256(passwd, salt, 1, 128 * r * p)))
    passwd = struct.pack('<8I', *B[0:8])
    V = [0] * (32 * r * N)
    X = [0] * (32 * r)
    Y = [0] * (32 * r)
    passwd = _smix(B, r, N, p, t, passwd, V, X, Y)
    dk = pbkdf2_sha256(passwd, struct.pack('<%dI' % n, *B), 1, 32)
    if prehash:
        return dk
    client_key = hmac_sha256(dk, b'Client Key')
    return sha256_digest(client_key)


