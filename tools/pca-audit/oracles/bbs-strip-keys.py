#!/usr/bin/env python3
"""Copy the BBS oracle corpus for a native lane without secret keys: the three signing keys (BBS KeyGen over 32 bytes of 0x01, 0x02,
0x03 with empty key info) are replaced by {"$bbssk": n}; the replay derives them with its own KeyGen. Usage: bbs-strip-keys.py in.json.gz out.json.gz"""
import gzip, json, re, sys

doc = json.loads(gzip.open(sys.argv[1]).read())
sks = {c["name"]: c["args"][0] for c in doc["cases"] if c["fn"] == "skToPk"}
assert sorted(sks) == ["skToPk/k0", "skToPk/k1", "skToPk/k2"], sks
text = gzip.open(sys.argv[1]).read().decode()
n = 0
for i, key in enumerate(("skToPk/k0", "skToPk/k1", "skToPk/k2"), 1):
    text, k = re.subn(r'"%s"' % re.escape(sks[key]), '{"$bbssk":%d}' % i, text)
    n += k
text = text.replace(doc["generator"], "bbs oracle (secret keys replaced by labels)")
for v in sks.values():
    assert v not in text, "a secret key remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "secret key values")
