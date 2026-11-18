# Tests for the pure-Python yescrypt library. Compatible with Python 2.6+.
# Vectors were generated once with the system libcrypt (libxcrypt).
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import yescrypt
from yescrypt._encoding import parse_setting

PW = b'password'

FAST = [
    (b'', '$y$j15$k2XAnEHBqQ1Ct2aMXFKNa/$2hFkUnubSTMrZlDd9WyeIaBM4bAfedKYXf3QsUnyNg8'),
    (b'pw', '$y$j25$k.$pgJ.enHOW1lcQ8hwhgZnt0IBIZE4L5C9HRU6.2Pl5L.'),
    (b'p\xc3\xa4ssw\xc3\xb6rd', '$y$j35..$k2XAnEHBqQ1Ct2aMXFKNa/$WXMO4DZDKAOntI6lQJ8ZUjowgmq855lBhqpVUfq1fu5'),
    (PW, '$y$j31/.$k2XAnEHBqQ1Ct2aMXFKNa/$Bhaw9RZ4Q2/fUhNkvLYwLOcyG4oxYaV72E6bWFtVo01'),
    (PW, '$y$j450./$k2XAnEHBqQ1Ct2aMXFKNaR4OddqOgpaP$.jYMC4D.oj7X.wTApg3uZQBEu/AObCdetbmNYNQgh55'),
    (PW, '$y$j75.0$k2XAnEHBqQ1Ct2aMXFKNaR4OddqOgpaPj/LQmB5RpNrRsZbS/7oE2JYF5VIG8h2HBtoHE3ZIHFJJKR3KNd3Al.$mM0sg967lTjYX0bRjqQPg0FjD2M1aTJrF8Iq3W1h2eA'),
    (b'x' * 100, '$y$j5./0$k2XAnEHBqQ1Ct2aMXFKNa/$hN30JTfLqKB27wtbWDxYr/0xACia4ITFy/oELeLleUD'),
    (PW, '$y$j5T$saltsaltsaltsalt$cxF.3g293y3.Z8R8fZ99hyyBXMGY12HNeVpq7Tc0wvB'),
    (PW, '$y$j6T$saltsaltsaltsalt$ZkYNa4dMAGjTtSc/Nj9S7hSsd2b2510VVcY6Tlbwyp1'),
    (PW, '$y$j8T$saltsaltsaltsalt$3AmdJlblcRLUZGcfZ1G1y.qsYNkOwS96sZWcNOPhzb4'),
    # Default parameters (N=4096, r=32); this one uses the pre-hash pass.
    (PW, '$y$j9T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD'),
]

SLOW = [
    (PW, '$y$jB5$k2XAnEHBqQ1Ct2aMXFKNa/$b8M2OKdrEtcuXhRlOhtW9E.nWff0M547no98Y6aaBZ6'),
    (PW, '$y$jAT..$k2XAnEHBqQ1Ct2aMXFKNa/$4k8DQ0eh.e10fs3KjedrZ8BiqqbKH/l3PE.MFy7TgvD'),
]


def _head(hashed):
    return hashed.rpartition('$')[0]


def _recompute(password, hashed):
    salt = parse_setting(_head(hashed))['salt']
    p = parse_setting(_head(hashed))
    return yescrypt.hash_password(password, salt=salt, N=p['N'], r=p['r'],
                                  p=p['p'], t=p['t'])


class VectorTests(unittest.TestCase):
    def test_hash_matches_libcrypt(self):
        for password, hashed in FAST:
            self.assertEqual(_recompute(password, hashed), hashed)

    def test_verify_accepts_correct_password(self):
        for password, hashed in FAST[:4] + FAST[-1:]:
            self.assertTrue(yescrypt.verify(password, hashed))

    def test_verify_rejects_wrong_password(self):
        for password, hashed in FAST[:4]:
            self.assertFalse(yescrypt.verify(password + b'x', hashed))

    def test_verify_accepts_bytes_hash(self):
        password, hashed = FAST[0]
        self.assertTrue(yescrypt.verify(password, hashed.encode('ascii')))

    def test_text_and_bytes_passwords_agree(self):
        password, hashed = FAST[2]
        self.assertTrue(yescrypt.verify(password.decode('utf-8'), hashed))


if os.environ.get('YESCRYPT_SLOW_TESTS'):
    class SlowVectorTests(unittest.TestCase):
        def test_large_parameters(self):
            for password, hashed in SLOW:
                self.assertEqual(_recompute(password, hashed), hashed)


class MalformedTests(unittest.TestCase):
    def test_verify_returns_false_for_bad_hashes(self):
        bad = [
            '',
            'not a hash',
            '$y$',
            '$y$j9T$saltsaltsaltsalt',
            '$y$j9T$saltsaltsaltsalt$',
            '$y$a9T$saltsaltsaltsalt$abc',
            '$y$j15$k2XAnEHBqQ1Ct2aMXFKNa/$short',
            '$y$j15$k2XAnEHBqQ1Ct2aMXFKNa/$' + '!' * 43,
            '$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234',
            b'$y$j15$\xff\xfe$abc',
        ]
        for hashed in bad:
            self.assertFalse(yescrypt.verify(PW, hashed))


class ParameterTests(unittest.TestCase):
    def test_invalid_parameters_raise_valueerror(self):
        calls = [
            dict(N=1), dict(N=3), dict(N=16, r=0), dict(N=16, p=0),
            dict(N=16, t=-1), dict(N=2, p=2), dict(N=16, salt=b''),
            dict(N=16, salt=b'x' * 65),
        ]
        for kwargs in calls:
            self.assertRaises(ValueError, yescrypt.hash_password, PW, **kwargs)

    def test_invalid_password_type_raises_typeerror(self):
        self.assertRaises(TypeError, yescrypt.hash_password, 123, N=16, r=1)


class RoundTripTests(unittest.TestCase):
    def test_roundtrip_and_random_salt(self):
        h1 = yescrypt.hash_password(PW, N=16, r=1)
        h2 = yescrypt.hash_password(PW, N=16, r=1)
        self.assertTrue(h1.startswith('$y$j'))
        self.assertEqual(len(h1.rpartition('$')[2]), 43)
        self.assertTrue(h1 != h2)
        self.assertTrue(yescrypt.verify(PW, h1))
        self.assertFalse(yescrypt.verify(b'other', h1))

    def test_roundtrip_with_p_and_t(self):
        h = yescrypt.hash_password(u'caf\u00e9', N=64, r=2, p=2, t=1)
        self.assertTrue(yescrypt.verify(u'caf\u00e9', h))
        self.assertFalse(yescrypt.verify(u'cafe', h))


if __name__ == '__main__':
    unittest.main()
