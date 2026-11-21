#!/usr/bin/env python3
"""Copy the notary oracle corpus for a native lane without private key material: a test key pair's `secretKey` bytes (a repeated-byte
Ed25519 seed) become {"$seed": "fill:<n>"}; the replay derives the seed from the label itself. Usage: notary-strip-keys.py in.json.gz out.json.gz"""
import base64, gzip, re, sys

text = gzip.open(sys.argv[1]).read().decode()
n = 0
for fill in (1, 2):
    b = base64.urlsafe_b64encode(bytes([fill]) * 32).rstrip(b"=").decode()
    text, k = re.subn(r'"secretKey":\{"\$bytes":"%s"\}' % re.escape(b), '"secretKey":{"$seed":"fill:%d"}' % fill, text)
    n += k
assert not re.search(r'"secretKey":\{"\$bytes"', text), "a private key member remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "private key members")
