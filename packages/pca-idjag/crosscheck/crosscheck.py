"""Independent cross-check of @atlasauth/pca-idjag (strict draft mode).

Uses only the `cryptography` package; no JOSE library, so the JWS is assembled by hand.

  python3 crosscheck/crosscheck.py
      Regenerates fixtures/python-vectors.json: ID-JAGs built and signed here (deterministic Ed25519, key seed =
      SHA-256 of a fixed label) plus negative variants. src/crosscheck.test.ts verifies them with the package.
  python3 crosscheck/crosscheck.py --verify-ours <file>
      Verifies the ID-JAGs the package-side test minted (written when PCA_CROSSCHECK_OUT is set): Ed25519 signature,
      header typ/alg, a single string audience, and the required claims.
"""
import base64, hashlib, json, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = pathlib.Path(__file__).resolve().parent.parent
ISS, AUD, CLIENT = 'https://idp.example.com', 'https://resource.example.com', 'resource-app-client'
TYP = 'oauth-id-jag+jwt'


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode()


def keypair(label: str):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    x = b64u(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return sk, x


def sign(sk, header, payload) -> str:
    signing_input = b64u(compact(header)) + '.' + b64u(compact(payload))
    return signing_input + '.' + b64u(sk.sign(signing_input.encode()))


def claims(**over):
    c = {'iss': ISS, 'sub': 'user-123', 'aud': AUD, 'client_id': CLIENT, 'jti': 'jag-py-0001', 'iat': 1700000000,
         'exp': 4102444800, 'scope': 'calendar.read mail.send', 'act': {'sub': 'agent-app-7'}}
    c.update(over)
    return c


def generate():
    sk, x = keypair('pca-idjag crosscheck key v1')
    hdr = {'alg': 'EdDSA', 'typ': TYP, 'kid': 'idjag-py-1'}
    vectors = []

    def add(name, token, expect, **extra):
        vectors.append({'name': name, 'token': token, 'expect': expect, **extra})

    add('conforming grant', sign(sk, hdr, claims()), 'ok',
        grant={'iss': ISS, 'sub': 'user-123', 'agent': 'agent-app-7', 'audience': AUD,
               'scopes': ['calendar.read', 'mail.send'], 'iat': 1700000000, 'exp': 4102444800, 'jti': 'jag-py-0001'})
    good = sign(sk, hdr, claims())
    h, p, s = good.split('.')
    add('payload edited after signing', h + '.' + b64u(compact(claims(scope='admin'))) + '.' + s, 'refuse', code='signature')
    add('plain JWT typ', sign(sk, {**hdr, 'typ': 'JWT'}, claims()), 'refuse', code='grant')
    add('no typ', sign(sk, {'alg': 'EdDSA', 'kid': 'k'}, claims()), 'refuse', code='grant')
    add('two audiences', sign(sk, hdr, claims(aud=[AUD, 'https://other.example.com'], azp=CLIENT)), 'refuse')
    add('other audience', sign(sk, hdr, claims(aud='https://other.example.com')), 'refuse')
    no_act = claims()
    del no_act['act']
    add('missing act', sign(sk, hdr, no_act), 'refuse', code='actor')
    no_scope = claims()
    del no_scope['scope']
    add('missing scope', sign(sk, hdr, no_scope), 'refuse', code='scope')
    no_client = claims()
    del no_client['client_id']
    add('missing client_id', sign(sk, hdr, no_client), 'refuse', code='grant')
    add('other client_id', sign(sk, hdr, claims(client_id='someone-else')), 'refuse', code='grant')
    no_jti = claims()
    del no_jti['jti']
    add('missing jti', sign(sk, hdr, no_jti), 'refuse', code='grant')
    add('expired', sign(sk, hdr, claims(exp=1700000100)), 'refuse')
    add('other issuer', sign(sk, hdr, claims(iss='https://evil.example.com')), 'refuse')
    add('alg none, no signature', b64u(compact({'alg': 'none', 'typ': TYP})) + '.' + b64u(compact(claims())) + '.', 'refuse')
    other_sk, _ = keypair('pca-idjag crosscheck other key')
    add('signed by another key', sign(other_sk, hdr, claims()), 'refuse', code='signature')
    out = {'generator': 'crosscheck/crosscheck.py (hand-assembled JWS, pyca/cryptography Ed25519; key seed = SHA-256 of a fixed label)',
           'issuer': ISS, 'audience': AUD, 'clientId': CLIENT, 'publicKey': x, 'vectors': vectors}
    path = HERE / 'fixtures' / 'python-vectors.json'
    path.write_text(json.dumps(out, indent=2) + '\n')
    print('wrote', path.relative_to(HERE), len(vectors), 'vectors')


def verify_ours(path):
    data = json.loads(pathlib.Path(path).read_text())
    pub = Ed25519PublicKey.from_public_bytes(unb64u(data['publicKey']))
    for tok in data['tokens']:
        h, p, s = tok.split('.')
        try:
            pub.verify(unb64u(s), (h + '.' + p).encode())
        except InvalidSignature:
            raise SystemExit('signature does not verify: ' + tok[:20])
        header, c = json.loads(unb64u(h)), json.loads(unb64u(p))
        assert header['typ'] == TYP and header['alg'] == 'EdDSA', header
        assert isinstance(c['aud'], str), 'audience must be a single string'
        for k in ('iss', 'sub', 'client_id', 'jti', 'scope'):
            assert isinstance(c[k], str) and c[k], k
        assert isinstance(c['act']['sub'], str) and c['exp'] > c['iat']
    assert len(data['tokens']) > 0
    print('verified', len(data['tokens']), 'package-minted tokens')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--verify-ours':
        verify_ours(sys.argv[2])
    elif len(sys.argv) == 1:
        generate()
    else:
        raise SystemExit(__doc__)
