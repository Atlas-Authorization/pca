#!/usr/bin/env python3
"""Rewrite ref-action-schema.json.gz in place: every secret the generator derived from a seed label becomes {"$bytes":{"$seed":label}}, so the
committed corpus carries no private key material. Usage: action-schema-strip.py <corpus.json.gz>...  Exit 1 if a raw $bytes value remains."""
import gzip, hashlib, base64, sys
LABELS = ['as/site', 'as/site2', 'as/pq']  # the seed() labels in action-schema.mts
M = {base64.urlsafe_b64encode(hashlib.sha256(("atlas-pca-conformance/" + l).encode()).digest()).rstrip(b"=").decode(): l for l in LABELS}
bad = 0
for p in sys.argv[1:]:
    t = gzip.decompress(open(p, "rb").read()).decode()
    for v, l in M.items():
        t = t.replace('{"$bytes":"%s"}' % v, '{"$bytes":{"$seed":"%s"}}' % l)
    open(p, "wb").write(gzip.compress(t.encode(), compresslevel=9, mtime=0))
    if '"$bytes":"' in t:
        print(p, "still carries a raw $bytes value"); bad = 1
sys.exit(bad)
