"""Cross-check RFC 9421 signing against the independent Python `http-message-signatures` library.
Run (after crosscheck/gen-ours.mts):
  uv run --with http-message-signatures==2.0.1 --with requests python crosscheck/hms_python.py
1. Verifies every request signed by @atlasauth/pca-vc (fixtures/ours-9421.json) with the Python library.
2. Writes fixtures/hms-python.json: requests signed by the Python library for the TS tests to verify."""
import json, pathlib, importlib.metadata as md
import requests, datetime
OLD = datetime.timedelta(days=36500)
from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

fx = pathlib.Path(__file__).parent.parent / 'fixtures'
ours = json.loads((fx / 'ours-9421.json').read_text())
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ours['public_key_hex']))
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))

class R(HTTPSignatureKeyResolver):
    def resolve_public_key(self, key_id): return pub
    def resolve_private_key(self, key_id): return sk

def prepared(case, extra=None):
    host = case['url'].split('/')[2]
    headers = {**case['headers'], 'host': host}
    if case.get('signatureAgent'): headers['signature-agent'] = case['signatureAgent']
    if extra: headers.update(extra)
    return requests.Request(case['method'], case['url'], headers=headers).prepare()

verifier = HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=R())
for c in ours['cases']:
    req = prepared(c, {'Signature-Input': c['signatureInput'], 'Signature': c['signature']})
    res = verifier.verify(req, max_age=OLD)
    assert res and res[0].parameters['keyid'] == 'k1', c
    # tamper: a different method must fail in the independent library as well
    bad = prepared({**c, 'method': 'DELETE'}, {'Signature-Input': c['signatureInput'], 'Signature': c['signature']})
    try:
        verifier.verify(bad, max_age=OLD); raise SystemExit('python accepted a tampered request')
    except Exception as e:
        if isinstance(e, SystemExit): raise
print('python http-message-signatures', md.version('http-message-signatures'), 'verified', len(ours['cases']), 'pca-vc requests and rejected tampering')

signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=R())
cases = []
for method, url, hdr in [('POST', 'https://api.acme.com/v1/orders?x=1', {'content-type': 'application/json'}), ('GET', 'https://bot.example/a', {'accept': 'text/html'})]:
    c = {'method': method, 'url': url, 'headers': hdr}
    comps = ('@method', '@target-uri', 'host') + tuple(hdr.keys())
    req = prepared(c)
    signer.sign(req, key_id='k1', covered_component_ids=comps, label='sig1', include_alg=True)
    c['signatureInput'] = req.headers['Signature-Input']; c['signature'] = req.headers['Signature']
    cases.append(c)
(fx / 'hms-python.json').write_text(json.dumps({
    'generator': f"http-message-signatures {md.version('http-message-signatures')} (independent), crosscheck/hms_python.py; key = RFC 8032 test vector 1",
    'public_key_hex': ours['public_key_hex'], 'cases': cases}, indent=1))
print('wrote fixtures/hms-python.json')
