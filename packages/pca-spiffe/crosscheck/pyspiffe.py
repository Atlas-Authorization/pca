"""Differential test against the independent Python implementation py-spiffe (PyPI `spiffe`).
Run: uv run --with spiffe==0.3.2 --with pyjwt==2.10.1 --with cryptography python crosscheck/pyspiffe.py
Writes fixtures/pyspiffe.json:
  ids  - SPIFFE ID strings with py-spiffe's accept/reject verdict
  jwt  - JWT-SVIDs signed with PyJWT (tamper variants included) with py-spiffe's verdict and the signer's JWK
The TypeScript tests require this package to agree, except where documented in the test (py-spiffe lower-cases an
upper-case trust domain; the current SPIFFE-ID standard and go-spiffe reject it)."""
import base64, importlib.metadata as md, json, pathlib, time
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from spiffe import JwtBundle, JwtSvid, SpiffeId, TrustDomain

fx = pathlib.Path(__file__).parent.parent / 'fixtures'

def py_id_ok(s):
    try:
        SpiffeId(s)
        return True
    except Exception:
        return False

candidates = ['', 'spiffe://', 'spiffe:///', 'spiffe://td', 'spiffe://td/', 'spiffe://td//a', 'spiffe://td/a/', 'spiffe://td/a/./b', 'spiffe://td/a/../b',
              'spiffe://td/.', 'spiffe://td/..', 'spiffe://td/...', 'spiffe://td/.a', 'spiffe://td/..a', 'spiffe://Td/a', 'SPIFFE://td/a', 'spiffe:/td/a',
              'http://td/a', 'spiffe://td:80/a', 'spiffe://user@td/a', 'spiffe://td/a?x=1', 'spiffe://td/a#f', 'spiffe://td/a b', 'spiffe://td/%41', 'spiffe://%74d/a',
              'spiffe://example.org/ns/prod/sa/agent-7', 'spiffe://example.org/a_b-c.d', 'spiffe://a.b-c_d.e/x', 'spiffe://td/' + 'a' * 2100, 'spiffe://' + 'a' * 300 + '/x',
              'spiffe://td/é', 'spiffe://té/a', 'spiffe://td/a\n', ' spiffe://td/a', 'spiffe://td/a ']
for i in range(256):
    c = chr(i)
    if c == '/': continue
    candidates += [f'spiffe://trustdomain{c}/path', f'spiffe://trustdomain/path{c}']
ids = [{'id': s, 'py_valid': py_id_ok(s)} for s in candidates]

# ---- JWT-SVIDs signed by PyJWT, verified by py-spiffe ----
now = int(time.time())
ec_key = ec.generate_private_key(ec.SECP256R1())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
other_key = ec.generate_private_key(ec.SECP256R1())
def b64(i): return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
def jwk_ec(k):
    n = k.public_key().public_numbers()
    return {'kty': 'EC', 'crv': 'P-256', 'x': base64.urlsafe_b64encode(n.x.to_bytes(32, 'big')).rstrip(b'=').decode(), 'y': base64.urlsafe_b64encode(n.y.to_bytes(32, 'big')).rstrip(b'=').decode(), 'kid': 'k1'}
def jwk_rsa(k):
    n = k.public_key().public_numbers()
    return {'kty': 'RSA', 'n': b64(n.n), 'e': b64(n.e), 'kid': 'k1'}
td = TrustDomain('example.org')
SUB = 'spiffe://example.org/workload/db'
base = {'sub': SUB, 'aud': ['rs'], 'exp': now + 3600, 'iat': now}
cases = []
def add(name, claims, key, alg, headers=None, jwk=None, aud='rs'):
    h = {'kid': 'k1', 'typ': 'JWT', **(headers or {})}
    tok = jwt.encode(claims, key, algorithm=alg, headers=h)
    pub = (key.public_key() if hasattr(key, 'public_key') else None)
    verdict, why = True, ''
    try:
        bundle = JwtBundle(td, {'k1': (jwt_pub[name] if name in jwt_pub else (ec_key if alg.startswith('ES') else rsa_key).public_key())})
        JwtSvid.parse_and_validate(tok, bundle, {aud})
    except Exception as e:
        verdict, why = False, f'{type(e).__name__}: {e}'
    cases.append({'name': name, 'token': tok, 'audience': aud, 'alg': alg, 'jwk': jwk or (jwk_ec(ec_key) if alg.startswith('ES') else jwk_rsa(rsa_key)), 'py_valid': verdict, 'py_reason': why})
jwt_pub = {}
add('valid ES256', base, ec_key, 'ES256')
add('valid RS256', base, rsa_key, 'RS256')
add('valid PS256', base, rsa_key, 'PS256')
add('wrong audience', {**base, 'aud': ['other']}, ec_key, 'ES256')
add('expired', {**base, 'exp': now - 3600}, ec_key, 'ES256')
add('missing exp', {k: v for k, v in base.items() if k != 'exp'}, ec_key, 'ES256')
add('missing aud', {k: v for k, v in base.items() if k != 'aud'}, ec_key, 'ES256')
add('sub is not a SPIFFE ID', {**base, 'sub': 'not-a-spiffe-id'}, ec_key, 'ES256')
add('sub with trailing slash', {**base, 'sub': 'spiffe://example.org/a/'}, ec_key, 'ES256')
add('signed by another key', base, other_key, 'ES256', jwk=jwk_ec(ec_key))
add('typ is not JWT', base, ec_key, 'ES256', headers={'typ': 'at+jwt'})
cases[-1]['note'] = 'JWT-SVID section 3 requires typ JWT or JOSE when present'
add('trust domain of another bundle', {**base, 'sub': 'spiffe://evil.example/x'}, ec_key, 'ES256')
(fx / 'pyspiffe.json').write_text(json.dumps({'generator': f"py-spiffe {md.version('spiffe')}, PyJWT {md.version('pyjwt')}, crosscheck/pyspiffe.py", 'ids': ids, 'jwt': cases}, indent=1))
print('ids', len(ids), 'valid', sum(i['py_valid'] for i in ids)); [print(' ', c['py_valid'], c['name'], c['py_reason'][:80]) for c in cases]
