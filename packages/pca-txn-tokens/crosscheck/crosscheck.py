"""Independent cross-check of @atlasauth/pca-txn-tokens (draft-11 profile).

Uses only the `cryptography` package; no JOSE library, so the JWS is assembled by hand.

  python3 crosscheck/crosscheck.py
      Regenerates fixtures/python-vectors.json: Transaction Tokens built and signed here (deterministic Ed25519,
      key seed = SHA-256 of a fixed label), plus negative variants. src/crosscheck.test.ts verifies them with the package.
  python3 crosscheck/crosscheck.py --verify-ours <file>
      Verifies the tokens the package minted (written by src/crosscheck.test.ts when PCA_CROSSCHECK_OUT is set):
      Ed25519 signature, header typ/alg, required draft-11 claims, and the sub/act and tctx shape.
"""
import base64, hashlib, json, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = pathlib.Path(__file__).resolve().parent.parent
TD = 'trust-domain.example'


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


DRAFT = {'alg': 'EdDSA', 'typ': 'txntoken+jwt'}
LEGACY = {'alg': 'EdDSA', 'typ': 'txn_token+jwt'}
NOW = 1686536300


def base_claims(**over):
    c = {'iat': 1686536226, 'aud': TD, 'exp': 1686536586, 'txn': '97053963-771d-49cc-a4e3-20aad399c312',
         'sub': 'd084sdrt234fsaw34tr23t', 'req_wl': 'apigateway.trust-domain.example', 'scope': 'trade.stocks',
         'tctx': {'action': 'BUY', 'ticker': 'MSFT', 'quantity': '100', 'customer_type': {'geo': 'US', 'level': 'VIP'}},
         'rctx': {'authn': 'face', 'device': 'kiosk'}}
    c.update(over)
    return c


def generate():
    sk, x = keypair('pca-txn-tokens crosscheck key v1')
    vectors = []

    def add(name, token, expect, **extra):
        vectors.append({'name': name, 'token': token, 'expect': expect, **extra})

    fig4 = base_claims(act={'sub': 'agent-a', 'act': {'sub': 'agent-b'}})
    add('free-form tctx with rctx and nested act', sign(sk, DRAFT, fig4), 'ok',
        tctx=fig4['tctx'], action=None, chain={'sub': fig4['sub'], 'act': fig4['act']})
    pca = base_claims(tctx={'verb': 'stripe.refund', 'resource': 'charge:ch_1', 'aud': TD})
    add('PCA action tctx', sign(sk, DRAFT, pca), 'ok', tctx=pca['tctx'], action=pca['tctx'], chain={'sub': pca['sub']})
    good = sign(sk, DRAFT, base_claims())
    h, p, s = good.split('.')
    tampered = base_claims(scope='admin')
    add('payload edited after signing', h + '.' + b64u(compact(tampered)) + '.' + s, 'refuse')
    add('legacy typ under the draft profile', sign(sk, LEGACY, base_claims()), 'refuse')
    add('expired', sign(sk, DRAFT, base_claims(exp=NOW - 1)), 'refuse')
    add('other trust domain', sign(sk, DRAFT, base_claims(aud='other.example')), 'refuse')
    add('alg none, no signature', b64u(compact({'alg': 'none', 'typ': 'txntoken+jwt'})) + '.' + b64u(compact(base_claims())) + '.', 'refuse')
    add('tctx is an array', sign(sk, DRAFT, base_claims(tctx=[{'action': 'BUY'}])), 'refuse')
    add('half a PCA action in tctx', sign(sk, DRAFT, base_claims(tctx={'verb': 'v'})), 'refuse')
    add('rctx is a string', sign(sk, DRAFT, base_claims(rctx='free text')), 'refuse')
    no_txn = base_claims()
    del no_txn['txn']
    add('missing txn', sign(sk, DRAFT, no_txn), 'refuse')
    other_sk, _ = keypair('pca-txn-tokens crosscheck other key')
    add('signed by another key', sign(other_sk, DRAFT, base_claims()), 'refuse')
    out = {'generator': 'crosscheck/crosscheck.py (hand-assembled JWS, pyca/cryptography Ed25519; key seed = SHA-256 of a fixed label)',
           'now': NOW, 'trustDomain': TD, 'publicKey': x, 'vectors': vectors}
    path = HERE / 'fixtures' / 'python-vectors.json'
    path.write_text(json.dumps(out, indent=2) + '\n')
    print('wrote', path.relative_to(HERE), len(vectors), 'vectors')


def verify_ours(path):
    data = json.loads(pathlib.Path(path).read_text())
    pub = Ed25519PublicKey.from_public_bytes(unb64u(data['publicKey']))
    n = 0
    for tok in data['tokens']:
        h, p, s = tok.split('.')
        try:
            pub.verify(unb64u(s), (h + '.' + p).encode())
        except InvalidSignature:
            raise SystemExit('signature does not verify: ' + tok[:20])
        header, claims = json.loads(unb64u(h)), json.loads(unb64u(p))
        assert header == DRAFT, header
        for k in ('iat', 'aud', 'exp', 'txn', 'sub', 'scope', 'req_wl', 'tctx'):
            assert k in claims, k
        assert 'jti' not in claims
        assert isinstance(claims['tctx'], dict) and isinstance(claims['txn'], str) and claims['exp'] > claims['iat']
        node = claims.get('act')
        while node is not None:
            assert isinstance(node['sub'], str) and node['sub']
            node = node.get('act')
        n += 1
    assert n == len(data['tokens']) and n > 0
    print('verified', n, 'package-minted tokens')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--verify-ours':
        verify_ours(sys.argv[2])
    elif len(sys.argv) == 1:
        generate()
    else:
        raise SystemExit(__doc__)
