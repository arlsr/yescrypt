# Development check: compares yescrypt against libcrypt vectors.
import sys
sys.path.insert(0, '.')
from yescrypt import hash_password, verify
from yescrypt._encoding import decode_bytes

VECTORS = [
    ('$y$j5T$saltsaltsaltsalt$cxF.3g293y3.Z8R8fZ99hyyBXMGY12HNeVpq7Tc0wvB', 256),
    ('$y$j6T$saltsaltsaltsalt$ZkYNa4dMAGjTtSc/Nj9S7hSsd2b2510VVcY6Tlbwyp1', 512),
    ('$y$j8T$saltsaltsaltsalt$3AmdJlblcRLUZGcfZ1G1y.qsYNkOwS96sZWcNOPhzb4', 2048),
    ('$y$j9T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD', 4096),
]

for expected, n in VECTORS:
    salt = decode_bytes('saltsaltsaltsalt')
    got = hash_password('password', salt=salt, N=n, r=32)
    ok = got == expected
    print('%s hash_password match=%s verify=%s wrong_pw=%s' % (
        expected[:8], ok, verify('password', expected), verify('wrong', expected)))
