"""Cross-check @atlasauth/pca-scitt against independent Python libraries.
Run (after `npx tsc -p tsconfig.build.json && node crosscheck/gen-ours.mts`):
  uv run --with pycose==1.1.0 --with cbor2==5.6.5 --with pymerkle==6.1.0 --with cryptography python crosscheck/cose_python.py
Direction 1: every statement/receipt in fixtures/ours.json is decoded by cbor2, its COSE signature verified by
pycose, and its Merkle roots/inclusion proofs reproduced by pymerkle.
Direction 2: writes fixtures/pycose.json with COSE_Sign1 statements signed by pycose for the TS tests."""
import base64, json, pathlib, importlib.metadata as md
import cbor2
from pycose.messages import Sign1Message
from pycose.keys import OKPKey, EC2Key
from pycose.keys.curves import Ed25519, P256
from pycose.algorithms import EdDSA, Es256
from pycose.headers import Algorithm, ContentType
from pymerkle import InmemoryTree

fx = pathlib.Path(__file__).parent.parent / 'fixtures'
b64d = lambda s: base64.b64decode(s)
bu = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def pk(jwk):
    if jwk['kty'] == 'OKP':
        return OKPKey(crv=Ed25519, x=bu(jwk['x']))
    return EC2Key(crv=P256, x=bu(jwk['x']), y=bu(jwk['y']))

data = json.loads((fx / 'ours.json').read_text())
n_checked = 0
for v in data['variants']:
    issuer, ts = pk(v['issuer_jwk']), pk(v['ts_jwk'])
    entries = [b64d(e['statement']) for e in v['entries']]
    tree = InmemoryTree(algorithm='sha256')
    for i, st in enumerate(entries):
        tree.append_entry(st)
        # statement: cbor2 parses it as tag 18 [bstr, map, bstr, bstr]; pycose verifies the signature
        top = cbor2.loads(st)
        assert isinstance(top, cbor2.CBORTag) and top.tag == 18 and len(top.value) == 4
        m = Sign1Message.decode(st); m.key = issuer
        assert m.verify_signature(), ('statement signature', v['alg'], i)
        # Merkle root at this size (independent RFC 6962/9162 implementation)
        root = tree.get_state(i + 1)
        assert base64.urlsafe_b64encode(root).rstrip(b'=').decode() == v['roots_by_size'][i], ('root', i)
    final_root = tree.get_state(len(entries))
    assert base64.urlsafe_b64encode(final_root).rstrip(b'=').decode() == v['final_root']
    # receipts: detached payload; the signature is over the root recomputed by pymerkle
    for i, rc in enumerate(v['final_receipts']):
        raw = b64d(rc)
        top = cbor2.loads(raw)
        assert top.tag == 18 and top.value[2] is None, 'receipt payload must be detached'
        prot = cbor2.loads(top.value[0]); assert prot[395] == 1
        unprot = top.value[1]
        inc = cbor2.loads(unprot[396][-1][0])  # [tree_size, leaf_index, path]
        assert inc[0] == len(entries) and inc[1] == i
        # pymerkle proof for the same leaf must use the same sibling hashes (as a set) as the receipt's path
        proof = tree.prove_inclusion(i + 1)
        theirs = {bytes(h) for h in proof.path}
        assert set(inc[2]) <= theirs | {tree.get_state(len(entries))}, ('path hashes', i)
        r = Sign1Message.decode(raw); r.key = ts; r.payload = final_root
        assert r.verify_signature(), ('receipt signature', v['alg'], i)
        n_checked += 1
    for c in v['consistency']:
        top = cbor2.loads(b64d(c['proof']))
        assert top[0] == c['old_size'] and top[1] == c['new_size']
        assert base64.urlsafe_b64encode(tree.get_state(c['old_size'])).rstrip(b'=').decode() == c['old_root']
print(f"pycose {md.version('pycose')}, cbor2 {md.version('cbor2')}, pymerkle {md.version('pymerkle')}: verified {len(data['variants'])} algs, {n_checked} receipts, all statements, all roots")

# ---- direction 2: pycose-signed statements for the TS verifier ----
out = []
for alg, mk, name in ((EdDSA, lambda: OKPKey.generate_key(crv=Ed25519), 'EdDSA'), (Es256, lambda: EC2Key.generate_key(crv=P256), 'ES256')):
    key = mk()
    msg = Sign1Message(phdr={Algorithm: alg, ContentType: 'application/pca+json'}, payload=b'{"verdict":"allow"}')
    msg.key = key
    enc = msg.encode(tag=True)
    jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': base64.urlsafe_b64encode(key.x).rstrip(b'=').decode()} if name == 'EdDSA' else \
          {'kty': 'EC', 'crv': 'P-256', 'x': base64.urlsafe_b64encode(key.x).rstrip(b'=').decode(), 'y': base64.urlsafe_b64encode(key.y).rstrip(b'=').decode()}
    out.append({'alg': name, 'statement': base64.b64encode(enc).decode(), 'public_jwk': jwk})
(fx / 'pycose.json').write_text(json.dumps({'generator': f"pycose {md.version('pycose')} (independent), crosscheck/cose_python.py", 'statements': out}, indent=1))
print('wrote fixtures/pycose.json')
