#!/usr/bin/env python3
"""Copy an ACP oracle corpus for a native lane without private key material: the test signing key's `d` member (a seed-derived Ed25519
key) is replaced by {"$seed": label}; the replay derives the key from the label itself. Usage: acp-strip-keys.py in.json.gz out.json.gz"""
import base64, gzip, hashlib, re, sys

def d_of(label):
    seed = hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()
    return base64.urlsafe_b64encode(seed).rstrip(b"=").decode()

text = gzip.open(sys.argv[1]).read().decode()
n = 0
for label in ("acp/signer", "acp/other"):
    text, k = re.subn(r'"d":"%s"' % re.escape(d_of(label)), '"d":{"$seed":"%s"}' % label, text)
    n += k
assert not re.search(r'"d":"[A-Za-z0-9_-]{40,}"', text), "a private key member remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "private key members")
