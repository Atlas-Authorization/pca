"""Generate did:key vectors with the independent Python `multiformats` + `base58` libraries.
Run: uv run --with multiformats==0.3.1.post4 --with base58==2.1.1 python crosscheck/didkey_python.py
(exact versions are recorded in the output fixture)."""
import hashlib, json, pathlib, importlib.metadata as md
import base58
from multiformats import multibase, multicodec

rng_seed = b'pca-vc-crosscheck'
keys = []
for i in range(40):
    raw = hashlib.sha256(rng_seed + bytes([i])).digest()  # deterministic 32-byte values (not claimed to be valid curve points)
    keys.append(raw)
keys.append(bytes(32))                      # all-zero: leading-zero base58 handling
keys.append(bytes([0] * 2 + [7] * 30))
keys.append(bytes([255] * 32))
out = []
for raw in keys:
    mc = multicodec.wrap('ed25519-pub', raw)
    did = 'did:key:' + multibase.encode(mc, 'base58btc')
    assert base58.b58encode(mc).decode() == did[len('did:key:z'):]
    out.append({'public_key_hex': raw.hex(), 'did': did})
fixture = {
    'generator': f"multiformats {md.version('multiformats')} + base58 {md.version('base58')} (independent), crosscheck/didkey_python.py",
    'vectors': out,
}
pathlib.Path(__file__).parent.parent.joinpath('fixtures', 'didkey-python.json').write_text(json.dumps(fixture, indent=1))
print('wrote', len(out), 'vectors;', fixture['generator'])
