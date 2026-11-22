#!/usr/bin/env python3
"""Copy the attest-eat oracle corpus for a native lane without private key material: every signing seed (the Ed25519 attester and
discharge-issuer keys, the ML-DSA and SLH-DSA co-signing seeds, the hybrid Ed25519 seed) is replaced by {"$seed": label}; the replay
derives the key from the label itself (SHA-256 of "atlas-pca-conformance/" + label, the 32-byte seed of every Ed25519 / ML-DSA key).
The two SLH-DSA seeds are longer than 32 bytes (48 / 96, built from labelled parts); their label names the parts.
Usage: attest-eat-swift-strip.py in.json.gz out.json.gz"""
import base64, gzip, hashlib, re, sys

def seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

labels = {b64u(seed(l)): l for l in ["eat/a", "eat/b", "eat/es-a", "eat/discharge-issuer", "eat/pq/ml65", "eat/pq/ml87"] + ["eat/pq-ed/%d" % i for i in range(8)]}
labels[b64u((seed("eat/pq/slh128/a") + seed("eat/pq/slh128/b"))[:48])] = "eat/pq/slh128/a+b"
labels[b64u((seed("eat/pq/slh256/a") + seed("eat/pq/slh256/b") + seed("eat/pq/slh256/c"))[:96])] = "eat/pq/slh256/a+b+c"

text = gzip.open(sys.argv[1]).read().decode()
n = 0
for val, label in labels.items():
    text, k = re.subn(r'"(seed|ed)":(\s?)"%s"' % re.escape(val), lambda m: '"%s":%s{"$seed":"%s"}' % (m.group(1), m.group(2), label), text)
    n += k
assert not re.search(r'"seed":\s?"', text), "a signing seed remains"
assert not re.search(r'"d":\s?"[A-Za-z0-9_-]{40,}"', text), "a private key member remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "seed members")
