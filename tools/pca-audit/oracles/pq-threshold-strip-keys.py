#!/usr/bin/env python3
"""Copy a pq-threshold oracle corpus for a native lane without private key material: every seed ({"$bytes": ...} authority seed, ML-DSA keygen
seed, FROST dealer secret / coefficient) becomes {"$seed": "<label>"}; the replay derives the 32 bytes as sha256("atlas-pca-conformance/" + label).
Usage: pq-threshold-strip-keys.py in.json.gz out.json.gz"""
import base64, gzip, hashlib, re, sys

SIGN = ['2of3-ok', '2of3-all', '3of5', '1of1', 'pqT-lower', 'pqT-higher-than-signers', 'group-as-b64u', 'action-2', 'pq-outsider-signer', 'below-threshold',
        'no-quorum', 'no-pq-signers', 't-0', 'signT-above-quorum', 'dup-quorum-member', 'unknown-member', 'signT-below-real-t']
labels = ['ref-pqt/auth', 'ref-pqt/auth2', 'ref-pqx/auth', 'ref-pqx/auth2'] + ['ref-pqx/pq%d' % i for i in range(1, 5)]
for n, nm in enumerate(SIGN, 1):
    labels.append('ref-pqx/sign-%s%d/s' % (nm, n))
    labels += ['ref-pqx/sign-%s%d/c%d' % (nm, n, i) for i in range(4)]
table = {}
for l in labels:
    d = hashlib.sha256(('atlas-pca-conformance/' + l).encode()).digest()
    table[base64.urlsafe_b64encode(d).rstrip(b'=').decode()] = l

text = gzip.open(sys.argv[1]).read().decode()
n = 0
def sub(m):
    global n
    l = table.get(m.group(1))
    if l is None:
        return m.group(0)
    n += 1
    return '{"$seed":"%s"}' % l
text = re.sub(r'\{"\$bytes":"([A-Za-z0-9_-]{43})"\}', sub, text)
for m in re.finditer(r'"(?:authoritySeed|authSeed|secret)":\{"\$bytes":"([^"]*)"\}|"(?:coefficients|pqSeeds)":\[\{"\$bytes":"([^"]*)"\}', text):
    v = m.group(1) or m.group(2)
    # only the all-zero hostile placeholders (e.g. a 31-byte seed) may stay
    assert set(base64.urlsafe_b64decode(v + '=' * (-len(v) % 4))) <= {0}, "a seed member remains"
with open(sys.argv[2], 'wb') as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print('replaced', n, 'seed members')
