#!/usr/bin/env python3
"""Regenerate sdks/swift-pca/test-data/attest-crypto-differential.json: verdicts of real implementations on edge inputs for the Swift
RSA and big-number code. PSS and PKCS#1 verdicts come from OpenSSL through `cryptography`, modular powers from Python integers, and
certificate verdicts from the openssl CLI (`openssl verify`). Needs `cryptography` and an openssl binary."""
import hashlib, json, os, random, subprocess, sys, tempfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

OUT = sys.argv[1]
random.seed(0x50ca)
HS = {'sha1': (hashes.SHA1, hashlib.sha1), 'sha256': (hashes.SHA256, hashlib.sha256), 'sha384': (hashes.SHA384, hashlib.sha384), 'sha512': (hashes.SHA512, hashlib.sha512)}
OID = {'sha1': '2b0e03021a', 'sha256': '608648016503040201', 'sha384': '608648016503040202', 'sha512': '608648016503040203'}
DI = {k: bytes.fromhex(v) for k, v in {'sha256': '3031300d060960864801650304020105000420', 'sha384': '3041300d060960864801650304020205000430', 'sha512': '3051300d060960864801650304020305000440'}.items()}

def i2b(x, n): return x.to_bytes(n, 'big')
def mgf1(seed, n, h):
    out, c = b'', 0
    while len(out) < n: out += HS[h][1](seed + c.to_bytes(4, 'big')).digest(); c += 1
    return out[:n]
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def pss_em(msg, h, salt, em_bits, db_edit=None, top_or=0, trailer=0xbc, h_flip=False):
    em_len = (em_bits + 7) // 8; hl = HS[h][1]().digest_size
    H = HS[h][1](b'\0' * 8 + HS[h][1](msg).digest() + salt).digest()
    db = bytearray(b'\0' * (em_len - len(salt) - hl - 2) + b'\1' + salt)
    if db_edit: db_edit(db)
    m = bytearray(xor(bytes(db), mgf1(H, len(db), h)))
    m[0] &= 0xff >> (8 * em_len - em_bits)
    m[0] |= top_or
    if h_flip: H = bytes([H[0] ^ 1]) + H[1:]
    return bytes(m) + H + bytes([trailer])

def is_prime(n):
    if n % 2 == 0: return n == 2
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(40):
        x = pow(random.randrange(2, n - 1), d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True
def prime(bits, e):
    while True:
        p = random.getrandbits(bits) | (3 << (bits - 2)) | 1
        if pow(p, 1, e) != 1 and is_prime(p): return p
def key_of_bits(bits, e=65537):
    # own primes: the library's generator does not honour every odd key size. Top two bits set, so p*q has exactly `bits` bits.
    p, q = prime((bits + 1) // 2, e), prime(bits // 2, e)
    assert (p * q).bit_length() == bits
    return {'n': p * q, 'e': e, 'd': pow(e, -1, (p - 1) * (q - 1))}

KEY_BITS = [1024, 1025, 1031, 1032, 1033, 2048, 2049]
keys = {str(b): key_of_bits(b) for b in KEY_BITS}
keys['2048e3'] = key_of_bits(2048, 3)
def pub(k):
    try: return rsa.RSAPublicNumbers(k['e'], k['n']).public_key()
    except Exception: return None
def pss_ok(k, sig, msg, h, salt):
    p = pub(k)
    if p is None: return False
    try: p.verify(sig, msg, padding.PSS(padding.MGF1(HS[h][0]()), salt), HS[h][0]()); return True
    except (InvalidSignature, ValueError): return False
def pkcs_ok(k, sig, msg, h):
    p = pub(k)
    if p is None: return False
    try: p.verify(sig, msg, padding.PKCS1v15(), HS[h][0]()); return True
    except (InvalidSignature, ValueError): return False
def raw_sign(k, block):
    v = int.from_bytes(block, 'big')
    return None if v >= k['n'] else i2b(pow(v, k['d'], k['n']), (k['n'].bit_length() + 7) // 8)

# Swift's profile: a signature of exactly |n| bytes (RFC 8017 8.1.2, 8.2.2); OpenSSL also takes one with its leading zero byte stripped
STRICT_SIG = 'short signature'
rows = []
def add_pss(kid, sig, msg, h, salt, why):
    if sig is None: return
    rows.append({'kind': 'pss', 'key': kid, 'hash': h, 'msg': msg.hex(), 'sig': sig.hex(), 'salt': salt, 'ok': pss_ok(keys[kid], sig, msg, h, salt), 'why': why, 'strict': why == STRICT_SIG})
def add_pkcs(kid, sig, msg, h, why):
    if sig is None: return
    rows.append({'kind': 'pkcs1', 'key': kid, 'hash': h, 'msg': msg.hex(), 'sig': sig.hex(), 'ok': pkcs_ok(keys[kid], sig, msg, h), 'why': why, 'strict': why == STRICT_SIG})

MSG = b'atlas pca differential'
for kid, k in keys.items():
    nb = k['n'].bit_length(); kl = (nb + 7) // 8; em_bits = nb - 1
    for h in (['sha1', 'sha256', 'sha384', 'sha512'] if kid in ('1032', '2048') else ['sha256']):
        hl = HS[h][1]().digest_size; em_len = (em_bits + 7) // 8; mx = em_len - hl - 2
        if mx < hl: continue  # a salt of hash length does not fit this key
        pad = b'\0' * (kl - em_len)
        def sign(em): return raw_sign(k, pad + em)
        salt = bytes(range(1, hl + 1))
        for L in sorted({0, 1, hl - 1, hl, hl + 1, mx - 1, mx}):
            s = (bytes(range(256)) * 2)[:L]
            add_pss(kid, sign(pss_em(MSG, h, s, em_bits)), MSG, h, L, f'valid salt {L}')
        good = sign(pss_em(MSG, h, salt, em_bits))
        add_pss(kid, good, MSG + b'x', h, hl, 'other message')
        for L in sorted({0, hl - 1, hl + 1, mx, mx + 1, mx + 2}): add_pss(kid, good, MSG, h, L, f'salt length {L} declared')
        for t in (0xbd, 0x00, 0x3c): add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, trailer=t)), MSG, h, hl, f'trailer {t}')
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, h_flip=True)), MSG, h, hl, 'H flipped')
        tb = 8 * em_len - em_bits
        for b in range(tb): add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, top_or=0x80 >> b)), MSG, h, hl, f'top bit {b} set')
        if kl != em_len: add_pss(kid, raw_sign(k, b'\x01' + pss_em(MSG, h, salt, em_bits)), MSG, h, hl, 'non-zero byte before EM')
        ps = em_len - hl - hl - 2
        def edit(i, v):
            def f(db): db[i] = v
            return f
        low = 0xff >> tb
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, db_edit=edit(0, 1 & low))), MSG, h, hl, 'first PS byte non-zero')
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, db_edit=edit(ps - 1, 1))), MSG, h, hl, 'last PS byte non-zero')
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, db_edit=edit(ps, 0))), MSG, h, hl, 'separator 0')
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, db_edit=edit(ps, 2))), MSG, h, hl, 'separator 2')
        add_pss(kid, sign(pss_em(MSG, h, salt, em_bits, db_edit=edit(ps + 1, salt[0] ^ 1))), MSG, h, hl, 'salt flipped after hashing')
        n = k['n']
        for why, v in (('s=0', 0), ('s=1', 1), ('s=n-1', n - 1), ('s=n', n), ('s=n+1', n + 1)):
            if v < 1 << (8 * kl): add_pss(kid, i2b(v, kl), MSG, h, hl, why)
        add_pss(kid, good[1:], MSG, h, hl, 'short signature')
        add_pss(kid, b'\0' + good, MSG, h, hl, 'long signature')
        add_pss(kid, b'\xff' * kl, MSG, h, hl, 'all ones')
        if h != 'sha1' and kl * 8 >= 1024:
            mh = HS[h][1](MSG).digest(); di = DI[h] + mh
            def block(prefix=b'\0\1', fill=None, sep=b'\0', body=di, n_fill=None):
                nf = n_fill if n_fill is not None else kl - len(prefix) - len(sep) - len(body)
                return prefix + (fill if fill is not None else b'\xff' * nf) + sep + body
            add_pkcs(kid, raw_sign(k, block()), MSG, h, 'valid')
            add_pkcs(kid, raw_sign(k, block()), MSG + b'x', h, 'other message')
            add_pkcs(kid, raw_sign(k, block(prefix=b'\0\2')), MSG, h, 'block type 2')
            add_pkcs(kid, raw_sign(k, block(prefix=b'\1\1')), MSG, h, 'first byte 1')
            nf = kl - 3 - len(di)
            add_pkcs(kid, raw_sign(k, block(fill=b'\xfe' + b'\xff' * (nf - 1))), MSG, h, 'PS starts fe')
            add_pkcs(kid, raw_sign(k, block(fill=b'\xff' * (nf - 1) + b'\xfe')), MSG, h, 'PS ends fe')
            add_pkcs(kid, raw_sign(k, b'\0\1' + b'\xff' * (kl - 2 - len(di)) + di), MSG, h, 'no separator')
            add_pkcs(kid, raw_sign(k, block(body=di[:-1] + bytes([di[-1] ^ 1]))), MSG, h, 'digest flipped')
            add_pkcs(kid, raw_sign(k, block(fill=b'\xff' * (nf - 1), body=di + b'\0')), MSG, h, 'trailing byte after digest')
            nonull = bytes([DI[h][0], DI[h][1] - 2, DI[h][2], DI[h][3] - 2]) + DI[h][4:15] + DI[h][17:] + mh
            add_pkcs(kid, raw_sign(k, block(body=nonull)), MSG, h, 'DigestInfo without NULL')
            add_pkcs(kid, i2b(1, kl), MSG, h, 's=1')
            add_pkcs(kid, i2b(k['n'], kl), MSG, h, 's=n')
            add_pkcs(kid, raw_sign(k, block())[1:], MSG, h, 'short signature')

evenk = {'n': keys['2048']['n'] - 1, 'e': 65537, 'd': 3}
keys['even'] = evenk
add_pss('even', i2b(2, 256), MSG, 'sha256', 32, 'even modulus')
add_pkcs('even', i2b(2, 256), MSG, 'sha256', 'even modulus')

# modular powers: limb-boundary moduli, carries and borrows
mods = [3, 5, 65537, 2**31 + 1, 2**32 - 1, 2**32 + 1, 2**32 + 15, 2**63 + 1, 2**64 - 1, 2**64 + 1, 2**64 - 2**32 + 1, 2**96 - 1, 2**96 + 2**32 + 1,
        2**127 - 1, 2**128 - 1, 2**128 - 159, 2**255 - 19, 2**521 - 1, 2**1024 - 1, 2**1024 + 1, 2**1023 + 1,
        keys['1024']['n'], keys['1025']['n'], keys['2048']['n'], (2**512 - 1) * (2**32) + 1, (1 << 1024) - (1 << 512) + 1]
mp = []
for m in mods:
    if m % 2 == 0: raise SystemExit('even modulus in the table')
    bases = {0, 1, 2, 3, m - 1, m - 2, (m + 1) // 2, min(2**32, m - 1), min(2**31, m - 1), min(2**32 - 1, m - 1), random.randrange(m), random.randrange(m)}
    exps = [0, 1, 2, 3, 17, 65537, 2**31, 2**32 - 1, random.getrandbits(32) | 1]
    for b in sorted(x for x in bases if 0 <= x < m):
        for e in exps[:9 if m.bit_length() <= 128 else 4] + [exps[5], exps[7]]:
            mp.append({'b': format(b, 'x'), 'e': format(e, 'x'), 'm': format(m, 'x'), 'r': format(pow(b, e, m), 'x')})

# certificates: RSASSA-PSS parameters as OpenSSL reads them
def tlv(tag, c):
    n = len(c)
    if n < 0x80: return bytes([tag, n]) + c
    l = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(l)]) + l + c
def seq(c): return tlv(0x30, c)
def oid(hex_): return tlv(6, bytes.fromhex(hex_))
NULL = b'\5\0'; OID_RSA = '2a864886f70d010101'; OID_PKCS256 = '2a864886f70d01010b'; OID_PSS = '2a864886f70d01010a'; OID_MGF1 = '2a864886f70d010108'; CN = '550403'
def name(cn): return seq(tlv(0x31, seq(oid(CN) + tlv(0x0c, cn.encode()))))
def alg_hash(h): return seq(oid(OID[h]) + NULL)
def int_(v): return tlv(2, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big'))
def spki(k): return seq(seq(oid(OID_RSA) + NULL) + tlv(3, b'\0' + seq(tlv(2, b'\0' + i2b(k['n'], (k['n'].bit_length() + 7) // 8)) + int_(k['e']))))
def tbs(alg, issuer, subject, k, serial, exts):
    v = seq(tlv(0x17, b'250101000000Z') + tlv(0x17, b'350101000000Z'))
    return seq(tlv(0xa0, tlv(2, b'\2')) + tlv(2, bytes([serial])) + alg + name(issuer) + v + name(subject) + spki(k) + tlv(0xa3, seq(b''.join(exts))))
def ext(o, crit, v): return seq(oid(o) + (b'\1\1\xff' if crit else b'') + tlv(4, v))
BC_CA = ext('551d13', True, seq(b'\1\1\xff')); KU_CA = ext('551d0f', True, tlv(3, b'\1\6')); BC_EE = ext('551d13', True, seq(b''))
ca, ee = keys['2048'], keys['1032']
ca_alg = seq(oid(OID_PKCS256) + NULL)
ca_tbs = tbs(ca_alg, 'differential root', 'differential root', ca, 1, [BC_CA, KU_CA])
ca_block = b'\0\1' + b'\xff' * (256 - 3 - 51) + b'\0' + DI['sha256'] + hashlib.sha256(ca_tbs).digest()
root = seq(ca_tbs + ca_alg + tlv(3, b'\0' + raw_sign(ca, ca_block)))
def pss_alg(params): return seq(oid(OID_PSS) + (params if params is not None else b''))
def params(h='sha256', salt=32, mgf=None, extra=b''):
    return seq(tlv(0xa0, alg_hash(h)) + tlv(0xa1, seq(oid(OID_MGF1) + alg_hash(mgf or h))) + tlv(0xa2, int_(salt)) + extra)
A0 = tlv(0xa0, alg_hash('sha256')); A1 = tlv(0xa1, seq(oid(OID_MGF1) + alg_hash('sha256'))); A2 = tlv(0xa2, int_(32))
CASES = [
    ('sha256 salt 32', params(), 'sha256', 32, False), ('sha256 salt 0', params(salt=0), 'sha256', 0, False), ('sha256 salt 20', params(salt=20), 'sha256', 20, False),
    ('sha256 salt 64', params(salt=64), 'sha256', 64, False), ('sha384 salt 48', params('sha384', 48), 'sha384', 48, False), ('sha512 salt 64', params('sha512', 64), 'sha512', 64, False),
    ('declared salt differs', params(salt=31), 'sha256', 32, False), ('declared hash differs', params('sha384', 32), 'sha256', 32, False),
    ('absent parameters', None, 'sha256', 32, False), ('NULL parameters', NULL, 'sha256', 32, False),
    ('default parameters', seq(b''), 'sha1', 20, False), ('default parameters, sha256 signature', seq(b''), 'sha256', 32, False),
    ('fields out of order', seq(A1 + A0 + A2), 'sha256', 32, False), ('duplicate salt', seq(A0 + A1 + A2 + A2), 'sha256', 32, False),
    ('hash field not a SEQUENCE', seq(tlv(0xa0, tlv(4, bytes.fromhex(OID['sha256']))) + A1 + A2), 'sha256', 32, False),
    ('salt with illegal padding', seq(A0 + A1 + tlv(0xa2, tlv(2, b'\0\x20'))), 'sha256', 32, False), ('empty salt', seq(A0 + A1 + tlv(0xa2, tlv(2, b''))), 'sha256', 32, False),
    ('hash without NULL parameters', seq(tlv(0xa0, seq(oid(OID['sha256']))) + tlv(0xa1, seq(oid(OID_MGF1) + seq(oid(OID['sha256'])))) + A2), 'sha256', 32, False),
    ('trailer field 1', params(extra=tlv(0xa3, int_(1))), 'sha256', 32, False), ('trailer field 2', params(extra=tlv(0xa3, int_(2))), 'sha256', 32, False),
    # Swift's profile: MGF1 over the signature hash only; OpenSSL allows another hash
    ('MGF1 over another hash', params(mgf='sha384'), 'sha256', 32, True),
]
certs = []
with tempfile.TemporaryDirectory() as d:
    def pem(der, f):
        import base64
        open(f, 'w').write('-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(der).decode() + '-----END CERTIFICATE-----\n')
    pem(root, d + '/root.pem')
    for why, ps, h, L, strict in CASES:
        alg = pss_alg(ps)
        t = tbs(alg, 'differential root', 'differential leaf', ee, 7, [BC_EE])
        hl = HS[h][1]().digest_size
        mg = 'sha384' if why.startswith('MGF1') else h
        salt = bytes(range(1, L + 1))
        emh = HS[h][1](b'\0' * 8 + HS[h][1](t).digest() + salt).digest()
        em_bits = ca['n'].bit_length() - 1
        em_len = (em_bits + 7) // 8
        db = b'\0' * (em_len - L - hl - 2) + b'\1' + salt
        m = bytearray(xor(db, mgf1(emh, len(db), mg)))
        m[0] &= 0xff >> (8 * em_len - em_bits)
        sig = raw_sign(ca, bytes(m) + emh + b'\xbc')
        der = seq(t + alg + tlv(3, b'\0' + sig))
        pem(der, d + '/leaf.pem')
        r = subprocess.run(['openssl', 'verify', '-auth_level', '0', '-CAfile', d + '/root.pem', d + '/leaf.pem'], capture_output=True, text=True)
        certs.append({'why': why, 'der': der.hex(), 'openssl': r.returncode == 0, 'strict': strict, 'detail': (r.stderr or r.stdout).strip().split('\n')[-1][:160]})
    # outer and tbs algorithm differ, the signature is the good one
    good = next(c for c in certs if c['why'] == 'sha256 salt 32')
    t = tbs(pss_alg(params()), 'differential root', 'differential leaf', ee, 7, [BC_EE])
    sig_start = bytes.fromhex(good['der'])[-(256 + 1):]
    der = seq(t + pss_alg(params(salt=33)) + tlv(3, sig_start))
    pem(der, d + '/leaf.pem')
    r = subprocess.run(['openssl', 'verify', '-auth_level', '0', '-CAfile', d + '/root.pem', d + '/leaf.pem'], capture_output=True, text=True)
    certs.append({'why': 'outer algorithm differs from tbs', 'der': der.hex(), 'openssl': r.returncode == 0, 'strict': False, 'detail': (r.stderr or r.stdout).strip().split('\n')[-1][:160]})
    # a certificate can carry an even modulus: refused before any modular arithmetic
    even_root = seq(tbs(ca_alg, 'differential root', 'differential root', keys['even'], 1, [BC_CA, KU_CA]) + ca_alg + tlv(3, b'\0' + i2b(2, 256)))
    pem(even_root, d + '/even.pem')
    pem(bytes.fromhex(good['der']), d + '/leaf.pem')
    r = subprocess.run(['openssl', 'verify', '-auth_level', '0', '-CAfile', d + '/even.pem', d + '/leaf.pem'], capture_output=True, text=True)
    certs.append({'why': 'issuer with an even modulus', 'root': even_root.hex(), 'der': good['der'], 'openssl': r.returncode == 0, 'strict': False, 'detail': (r.stderr or r.stdout).strip().split('\n')[-1][:160]})

# P-224 ECDSA: OpenSSL verdicts over DER forms and range edges
from cryptography.hazmat.primitives.asymmetric import ec, utils
N224 = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
P224P = 2**224 - 2**96 + 1
def der_int(v, pad=b''):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(2, pad + b)
def der_sig(r, s): return seq(der_int(r) + der_int(s))
p224 = []
def p224_row(point, h, msg, sig, why):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), point).verify(sig, msg, ec.ECDSA(HS[h][0]()))
        ok = True
    except (InvalidSignature, ValueError): ok = False
    p224.append({'point': point.hex(), 'hash': h, 'msg': msg.hex(), 'sig': sig.hex(), 'ok': ok, 'why': why, 'strict': why == 'compressed point'})  # Swift's profile: uncompressed points only
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
UNC = lambda k: k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
for d in (1, 2, N224 - 1, 0x1234567890abcdef1234567890abcdef1234567890abcdef12345678):
    k = ec.derive_private_key(d, ec.SECP224R1()); pt = UNC(k)
    for h in ('sha1', 'sha256', 'sha384', 'sha512'):
        for i in range(4):
            sig = k.sign(MSG + bytes([i]), ec.ECDSA(HS[h][0]()))
            r, s = utils.decode_dss_signature(sig)
            p224_row(pt, h, MSG + bytes([i]), sig, 'valid')
        p224_row(pt, h, MSG + b'x', sig, 'other message')
        m = MSG + bytes([3])
        p224_row(pt, h, m, der_sig(r, N224 - s), 'high s')
        for why, a, b in (('r=0', 0, s), ('s=0', r, 0), ('r=n', N224, s), ('s=n', r, N224), ('r+n', r + N224, s), ('s+n', r, s + N224), ('r^1', r ^ 1, s), ('s^1', r, s ^ 1), ('swapped', s, r)):
            p224_row(pt, h, m, der_sig(a, b), why)
    good = der_sig(r, s); body = good[2:]
    p224_row(pt, h, m, good + b'\0', 'trailing byte')
    p224_row(pt, h, m, bytes([0x30, len(body) + 1]) + body, 'length too long')
    p224_row(pt, h, m, bytes([0x30, len(body) - 1]) + body, 'length too short')
    p224_row(pt, h, m, bytes([0x30, 0x81, len(body)]) + body, 'long-form length')
    p224_row(pt, h, m, bytes([0x31]) + good[1:], 'not a SEQUENCE')
    p224_row(pt, h, m, seq(der_int(r, b'\0') + der_int(s)), 'r with illegal padding')
    p224_row(pt, h, m, seq(der_int(r) + der_int(s, b'\0')), 's with illegal padding')
    p224_row(pt, h, m, seq(tlv(2, b'\x80' + r.to_bytes(28, 'big')) + der_int(s)), 'negative r')
    p224_row(pt, h, m, seq(der_int(r)), 'one INTEGER')
    p224_row(pt, h, m, seq(der_int(r) + der_int(s) + der_int(1)), 'three INTEGERs')
    p224_row(pt, h, m, b'', 'empty')
    p224_row(pt, h, m, good[:7], 'seven bytes')
    x, y = pt[1:29], pt[29:]
    p224_row(bytes([4]) + x + bytes([y[0] ^ 1]) + y[1:], h, m, good, 'point off the curve')
    p224_row(bytes([4]) + P224P.to_bytes(28, 'big') + y, h, m, good, 'x = p')
    p224_row(pt[:-1], h, m, good, 'short point')
    p224_row(bytes([2]) + x, h, m, good, 'compressed point')

# X509_check_issued as Node reports it. The signatures are never read by checkIssued, so they stay dummies.
SKID = '551d0e'; AKID = '551d23'; K1 = bytes(range(20)); K2 = bytes(range(1, 21))
def cert(subject='root', issuer='root', serial=b'\5', exts=(), key=None):
    a = seq(oid(OID_PKCS256) + NULL)
    v = seq(tlv(0x17, b'250101000000Z') + tlv(0x17, b'350101000000Z'))
    extb = tlv(0xa3, seq(b''.join(exts))) if exts else b''
    t = seq(tlv(0xa0, tlv(2, b'\2')) + tlv(2, serial) + a + name(issuer) + v + name(subject) + spki(key or ca) + extb)
    return seq(t + a + tlv(3, b'\0' + b'\1' * 256))
def skid_ext(k=K1): return ext(SKID, False, tlv(4, k))
def akid(*fields): return ext(AKID, False, seq(b''.join(fields)))
def kid(k=K1): return tlv(0x80, k)
def ser(b=b'\5'): return tlv(0x82, b)
def dn(n='granddad'): return tlv(0xa1, tlv(0xa4, name(n)))
KU = lambda bits: ext('551d0f', True, tlv(3, bits))
ISS = cert('root', 'granddad', b'\5', [skid_ext(), BC_CA, KU_CA])
NOSKID = cert('root', 'granddad', b'\5', [BC_CA, KU_CA])
KID = lambda *f, issuer=ISS: (issuer, cert('leaf', 'root', b'\7', [akid(*f)], ee), False)
NOK = lambda why, i, c, strict=False: (why, i, c, strict)
ISSUED = [
    ('no AKID', ISS, cert('leaf', 'root', b'\7', [], ee), False),
    ('key id matches', *KID(kid())), ('key id differs', *KID(kid(K2))), ('key id, issuer without SKID', *KID(kid(K2), issuer=NOSKID)),
    ('serial matches', *KID(ser())), ('serial differs', *KID(ser(b'\6'))), ('serial non-minimal', *KID(ser(b'\0\5'))), ('serial empty', *KID(ser(b''))),
    ('serial 0xff padded', *KID(ser(b'\xff\xfb'))),
    ('directory name matches', *KID(dn())), ('directory name differs', *KID(dn('other'))), ('directory name is the subject, not the issuer', *KID(dn('root'))),
    ('another general name only', *KID(tlv(0xa1, tlv(0x82, b'a.example')))),
    ('another general name then a differing directory name', *KID(tlv(0xa1, tlv(0x82, b'a.example') + tlv(0xa4, name('other'))))),
    ('all three match', *KID(kid(), dn(), ser())), ('key id matches, serial differs', *KID(kid(), ser(b'\6'))), ('key id matches, name differs', *KID(kid(), dn('other'))),
    ('key id differs, serial matches', *KID(kid(K2), ser())),
    ('no SKID, serial differs', *KID(kid(), ser(b'\6'), issuer=NOSKID)),
    ('serial before key id', *KID(ser(), kid())), ('duplicate key id', *KID(kid(), kid())), ('unknown field', *KID(tlv(0x83, b'\1'))), ('constructed key id', *KID(tlv(0xa0, tlv(4, K1)))[:2], True),
    ('empty general names', *KID(tlv(0xa1, b''))), ('empty AKID', *KID()),
    ('AKID not a SEQUENCE', ISS, cert('leaf', 'root', b'\7', [ext(AKID, False, tlv(4, K1))], ee), False),
    ('names differ', ISS, cert('leaf', 'other', b'\7', [], ee), False),
    ('name differs only in case', ISS, cert('leaf', 'ROOT', b'\7', [], ee), True),
    ('issuer keyUsage without keyCertSign', cert('root', 'granddad', b'\5', [skid_ext(), BC_CA, KU(b'\7\x80')]), cert('leaf', 'root', b'\7', [], ee), False),
    ('issuer without keyUsage', cert('root', 'granddad', b'\5', [skid_ext(), BC_CA]), cert('leaf', 'root', b'\7', [], ee), False),
    ('issuer SKID malformed', cert('root', 'granddad', b'\5', [ext(SKID, False, tlv(2, b'\1')), BC_CA, KU_CA]), cert('leaf', 'root', b'\7', [], ee), False),
    ('child SKID malformed', ISS, cert('leaf', 'root', b'\7', [ext(SKID, False, tlv(2, b'\1'))], ee), False),
    ('proxy child, issuer keyCertSign only', ISS, cert('leaf', 'root', b'\7', [ext('2b06010505070 10e'.replace(' ', ''), True, seq(seq(oid('2b06010505071501'))))], ee), False),
    ('proxy child, issuer digitalSignature too', cert('root', 'granddad', b'\5', [skid_ext(), BC_CA, KU(b'\1\x84')]), cert('leaf', 'root', b'\7', [ext('2b06010505070 10e'.replace(' ', ''), True, seq(seq(oid('2b06010505071501'))))], ee), True),
]
PARSE = [('serial 5', b'\5', False), ('serial non-minimal', b'\0\5', False), ('serial 0xff padded', b'\xff\xfb', False), ('serial empty', b'', False), ('serial negative', b'\xfb', True), ('serial zero', b'\0', True), ('serial high bit, padded', b'\0\x80', False)]
nodejs = '''
const { X509Certificate } = require('node:crypto');
const rows = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const mk = (h) => { try { return new X509Certificate(Buffer.from(h, 'hex')); } catch { return null; } };
console.log(JSON.stringify(rows.map((r) => { const c = mk(r.child); if (!c) return false; if (!r.issuer) return true; const i = mk(r.issuer); try { return !!i && c.checkIssued(i); } catch { return false; } })));
'''
issued_in = [{'why': w, 'issuer': i.hex(), 'child': c.hex(), 'strict': s} for w, i, c, s in ISSUED]
parse_in = [{'why': w, 'child': cert('leaf', 'root', b, [], ee).hex(), 'strict': s} for w, b, s in PARSE]
out = json.loads(subprocess.run(['node', '-e', nodejs], input=json.dumps(issued_in + parse_in), capture_output=True, text=True, check=True).stdout)
for r, ok in zip(issued_in + parse_in, out): r['node'] = ok

doc = {'source': 'tools/pca-audit/swift-mutate/gen-attest-crypto-differential.py', 'keys': {k: {'n': format(v['n'], 'x'), 'e': format(v['e'], 'x')} for k, v in keys.items()},
       'rsa': rows, 'modpow': mp, 'p224': p224, 'issued': issued_in, 'parse': parse_in, 'root': root.hex(), 'certs': [{k: v for k, v in c.items() if k != 'detail'} for c in certs]}
json.dump(doc, open(OUT, 'w'), separators=(',', ':'))
from collections import Counter
print(len(p224), Counter(r['ok'] for r in p224), sorted({r['why'] for r in p224 if r['ok']}))
for r in issued_in + parse_in: print(r['node'], r['strict'], r['why'])
print(len(rows), Counter((r['kind'], r['ok']) for r in rows), len(mp), os.path.getsize(OUT))
for c in certs: print(c['openssl'], c['why'], '|', c['detail'][:90])
for r in rows:
    if r['ok'] and 'valid' not in r['why'] and 'salt length' not in r['why']: print('accepted edge:', r['key'], r['hash'], r['why'])
