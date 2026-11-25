#!/usr/bin/env python3
"""Copy the wallet oracle corpus for the Swift lane without private key material. A test signing key's `d` member (a seed-derived
Ed25519 key) would be replaced by {"$seed": label}; the replay derives keys from the label itself. The wallet corpus carries only
public keys (JWK `x`, base64url public members) and `{"$seed": label}` references, so the script verifies that no private member
remains and writes a deterministic gzip. Usage: wallet-swift-strip.py in.json.gz out.json.gz"""
import base64, gzip, hashlib, re, sys

def d_of(label):
    seed = hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()
    return base64.urlsafe_b64encode(seed).rstrip(b"=").decode()

text = gzip.open(sys.argv[1]).read().decode()
n = 0
for label in ("wallet/principal", "wallet/pricing", "wallet/other", "wallet/site", "wallet/device"):
    text, k = re.subn(r'"d":"%s"' % re.escape(d_of(label)), '"d":{"$seed":"%s"}' % label, text)
    n += k
assert not re.search(r'"d":"[A-Za-z0-9_-]{40,}"', text), "a private key member remains"
assert not re.search(r'"(privateKey|secretKey|secret|seed)":"', text), "a secret member remains"
with open(sys.argv[2], "wb") as f:
    f.write(gzip.compress(text.encode(), 9, mtime=0))
print("replaced", n, "private key members")
