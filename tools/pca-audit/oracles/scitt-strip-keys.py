#!/usr/bin/env python3
"""Copy the SCITT oracle corpus for a native lane without private key material: a test signing key's Ed25519 `seed` and ES256 `d` become
{"$seed": label}; the replay derives the key from the label itself (d = seed with its top bit cleared). Usage: scitt-strip-keys.py in.json.gz out.json.gz"""
import base64, gzip, hashlib, re, sys

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

text = gzip.open(sys.argv[1]).read().decode()
n = 0
for label in ("scitt/issuer", "scitt/ts", "scitt/other", "scitt/es-issuer", "scitt/es-ts", "scitt/es-other"):
    seed = hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()
    d = bytes([seed[0] & 0x7F]) + seed[1:]
    for key, val in (("seed", seed), ("d", d)):
        text, k = re.subn(r'"%s":"%s"' % (key, re.escape(b64(val))), '"%s":{"$seed":"%s"}' % (key, label), text)
        n += k
assert not re.search(r'"(seed|d)":"[A-Za-z0-9_-]{40,}"', text), "a private key member remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "private key members")
