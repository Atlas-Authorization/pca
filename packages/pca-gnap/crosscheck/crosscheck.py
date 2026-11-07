"""Independent cross-check of @atlasauth/pca-gnap (jwsd key proof, RFC 9635 section 7.3.4 profile).

Uses only the `cryptography` package; the detached JWS is assembled by hand. The JWS payload is the SHA-256 digest of the content. Bodies are limited to strings, integers,
arrays and objects so that json.dumps(sort_keys=True, separators=(',', ':')) is the same byte string as the
package's canonical form.

  python3 crosscheck/crosscheck.py
      Regenerates fixtures/python-vectors.json (deterministic Ed25519, key seed = SHA-256 of a fixed label).
  python3 crosscheck/crosscheck.py --verify-ours <file>
      Verifies the detached JWS values the package-side test wrote (when PCA_CROSSCHECK_OUT is set).
"""
import base64, hashlib, json, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = pathlib.Path(__file__).resolve().parent.parent
URI, NOW = 'https://as.example/gnap', 1700000000


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def payload_of(body) -> bytes:
    """RFC 9635 7.3.3: the JWS payload is the SHA-256 digest of the request content (here its canonical JSON)."""
    return hashlib.sha256(canon(body)).digest()


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode()


def keypair(label):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    return sk, b64u(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def detached(sk, header, body) -> str:
    h = b64u(compact(header))
    sig = sk.sign((h + '.' + b64u(payload_of(body))).encode())
    return h + '..' + b64u(sig)


BODY = {'access_token': {'access': [{'type': 'repo', 'actions': ['read', 'write'], 'locations': ['main']}]},
        'client': {'key': {'proof': 'jwsd'}}, 'n': 7}


def hdr(**over):
    h = {'alg': 'EdDSA', 'typ': 'gnap-binding-jwsd', 'htm': 'POST', 'uri': URI, 'created': NOW}
    h.update(over)
    return h


def generate():
    sk, x = keypair('pca-gnap crosscheck key v1')
    other, _ = keypair('pca-gnap crosscheck other key')
    token_value = 'token-value-1'
    ath = b64u(hashlib.sha256(token_value.encode()).digest())
    v = []

    def add(name, jws, expect, body=BODY, **extra):
        v.append({'name': name, 'detachedJws': jws, 'body': body, 'expect': expect, **extra})

    add('plain request', detached(sk, hdr(), BODY), 'ok')
    add('request bound to an access token', detached(sk, hdr(ath=ath), BODY), 'ok', accessTokenValue=token_value)
    add('lower-case method accepted', detached(sk, hdr(htm='post'), BODY), 'ok')
    add('kid header kept', detached(sk, hdr(kid='k1'), BODY), 'ok')
    add('wrong access token', detached(sk, hdr(ath=ath), BODY), 'refuse', accessTokenValue='another-token')
    add('missing ath when a token is named', detached(sk, hdr(), BODY), 'refuse', accessTokenValue=token_value)
    add('body edited', detached(sk, hdr(), BODY), 'refuse', body={**BODY, 'n': 8})
    add('signed by another key', detached(other, hdr(), BODY), 'refuse')
    add('wrong typ', detached(sk, hdr(typ='JWT'), BODY), 'refuse')
    add('wrong alg label', detached(sk, hdr(alg='Ed25519'), BODY), 'refuse')
    add('wrong method', detached(sk, hdr(htm='GET'), BODY), 'refuse')
    add('wrong uri', detached(sk, hdr(uri='https://as.example/other'), BODY), 'refuse')
    add('stale', detached(sk, hdr(created=NOW - 301), BODY), 'refuse')
    add('from the future', detached(sk, hdr(created=NOW + 61), BODY), 'refuse')
    add('created is a string', detached(sk, hdr(created=str(NOW)), BODY), 'refuse')
    full = detached(sk, hdr(), BODY)
    h, _, s = full.split('.')
    add('content (not its digest) in the middle segment', h + '.' + b64u(canon(BODY)) + '.' + s, 'refuse')
    add('digest spelled out in the middle segment (as RFC 9635 prints its example)', h + '.' + b64u(payload_of(BODY)) + '.' + s, 'ok')
    add('digest of another content in the middle segment', h + '.' + b64u(payload_of({**BODY, 'n': 8})) + '.' + s, 'refuse')
    out = {'generator': 'crosscheck/crosscheck.py (hand-assembled detached JWS, pyca/cryptography Ed25519; key seed = SHA-256 of a fixed label)',
           'now': NOW, 'uri': URI, 'htm': 'POST', 'publicKey': x, 'vectors': v}
    path = HERE / 'fixtures' / 'python-vectors.json'
    path.write_text(json.dumps(out, indent=2) + '\n')
    print('wrote', path.relative_to(HERE), len(v), 'vectors')


def verify_ours(path):
    data = json.loads(pathlib.Path(path).read_text())
    pub = Ed25519PublicKey.from_public_bytes(unb64u(data['publicKey']))
    for item in data['items']:
        h, mid, s = item['detachedJws'].split('.')
        assert mid == '', 'not detached'
        try:
            pub.verify(unb64u(s), (h + '.' + b64u(payload_of(item['body']))).encode())
        except InvalidSignature:
            raise SystemExit('signature does not verify: ' + item['detachedJws'][:20])
        header = json.loads(unb64u(h))
        assert header['typ'] == 'gnap-binding-jwsd' and header['alg'] == 'EdDSA', header
        assert isinstance(header['created'], int) and header['htm'] == header['htm'].upper()
    assert len(data['items']) > 0
    print('verified', len(data['items']), 'package-signed requests')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--verify-ours':
        verify_ours(sys.argv[2])
    elif len(sys.argv) == 1:
        generate()
    else:
        raise SystemExit(__doc__)
