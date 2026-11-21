"""Independent DPoP resource-server check of @atlasauth/pca-dpop (RFC 9449 s4.3), written without jose or any shared code.
Run (package dir):  npx tsx crosscheck/gen-matrix.mts > "$OUT/matrix.json" && \
  uv run --with cryptography python crosscheck/server_crosscheck.py "$OUT/matrix.json"
Every case: this server and pca-dpop must agree on accept/reject AND on the rejection reason; any disagreement exits 1."""
import base64, hashlib, json, sys
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

def b64d(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def thumbprint(jwk):  # RFC 7638: required members, lexicographic order, no whitespace
    members = {'EC': ['crv', 'kty', 'x', 'y'], 'OKP': ['crv', 'kty', 'x']}[jwk['kty']]
    return b64e(hashlib.sha256(json.dumps({k: jwk[k] for k in members}, separators=(',', ':')).encode()).digest())

def htu_of(url):
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}{u.path}"

CURVES = {'ES256': (ec.SECP256R1(), hashes.SHA256(), 32), 'ES384': (ec.SECP384R1(), hashes.SHA384(), 48)}

def server(proof, req):
    """Return None when accepted, else the rejection reason (named like pca-dpop's codes)."""
    h, p, s = proof.split('.')
    header, payload = json.loads(b64d(h)), json.loads(b64d(p))
    if header.get('typ') != 'dpop+jwt': return 'typ'
    jwk = header.get('jwk')
    if not jwk: return 'no_jwk'
    if any(k in jwk for k in 'd p q dp dq qi k'.split()): return 'private_jwk'
    alg, sig, signing_input = header.get('alg'), b64d(s), f'{h}.{p}'.encode()
    try:
        if alg == 'EdDSA':
            Ed25519PublicKey.from_public_bytes(b64d(jwk['x'])).verify(sig, signing_input)
        elif alg in CURVES:
            curve, hsh, n = CURVES[alg]
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(jwk['x']), 'big'), int.from_bytes(b64d(jwk['y']), 'big'), curve).public_key()
            pub.verify(encode_dss_signature(int.from_bytes(sig[:n], 'big'), int.from_bytes(sig[n:], 'big')), signing_input, ec.ECDSA(hsh))
        else:
            return 'signature'
    except (InvalidSignature, ValueError, KeyError):
        return 'signature'
    if payload.get('htm') != req['method'].upper(): return 'htm'
    if payload.get('htu') != htu_of(req['url']): return 'htu'
    now, iat = req['now'], payload['iat']
    if iat > now + 5: return 'iat_future'
    if now - iat > req['maxAgeSec']: return 'iat_stale'
    if req.get('expectedJkt') is not None and thumbprint(jwk) != req['expectedJkt']: return 'jkt'
    if req.get('accessToken') is not None and payload.get('ath') != b64e(hashlib.sha256(req['accessToken'].encode()).digest()): return 'ath'
    return None

bad = 0
cases = json.load(open(sys.argv[1]))
for c in cases:
    reason = server(c['proof'], c['request'])
    theirs = {'ok': True} if reason is None else {'ok': False, 'code': reason}
    # a tampered signature must be refused as `signature` by both sides
    if theirs != c['ours']:
        bad += 1
        print('DISAGREE', c['name'], 'server:', theirs, 'pca-dpop:', c['ours'])
print(f'{len(cases)} cases, {bad} disagreements')
sys.exit(1 if bad else 0)
