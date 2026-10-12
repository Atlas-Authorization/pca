#!/usr/bin/env python3
"""Python voter: hashlib/hmac (OpenSSL), PyNaCl (libsodium), `cryptography` (OpenSSL). argv[1] = ed25519 variant: nacl|cryptography.
Same line protocol as rust-voter."""
import sys, hashlib, hmac as hm

variant = sys.argv[1] if len(sys.argv) > 1 else "nacl"
if variant == "nacl":
    import nacl.bindings as nb
    import nacl.signing as ns
else:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature

H = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512, "sha3-256": hashlib.sha3_256, "sha3-512": hashlib.sha3_512}

def h(s): return bytes.fromhex(s)

def handle(f):
    op = f[0]
    if op == "FLUSH": return "FLUSHED"
    if op == "H":
        a = f[1]
        if a in H: return H[a](h(f[2])).hexdigest()
        if a.startswith("shake128:"): return hashlib.shake_128(h(f[2])).hexdigest(int(a.split(":")[1]))
        if a.startswith("shake256:"): return hashlib.shake_256(h(f[2])).hexdigest(int(a.split(":")[1]))
        return "ERR algo"
    if op == "M":
        if f[1] not in ("sha256", "sha512"): return "ERR algo"
        return hm.new(h(f[2]), h(f[3]), H[f[1]]).hexdigest()
    if op == "EP":
        if variant == "nacl": return ns.SigningKey(h(f[1])).verify_key.encode().hex()
        from cryptography.hazmat.primitives import serialization as s
        return Ed25519PrivateKey.from_private_bytes(h(f[1])).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
    if op == "ES":
        if variant == "nacl": return ns.SigningKey(h(f[1])).sign(h(f[2])).signature.hex()
        return Ed25519PrivateKey.from_private_bytes(h(f[1])).sign(h(f[2])).hex()
    if op == "EV":
        pk, m, sg = h(f[2]), h(f[3]), h(f[4])
        if len(pk) != 32 or len(sg) != 64: return "0"
        try:
            if variant == "nacl":
                nb.crypto_sign_open(sg + m, pk); return "1"
            Ed25519PublicKey.from_public_bytes(pk).verify(sg, m); return "1"
        except Exception:
            return "0"
    return "ERR op"

out = sys.stdout
for line in sys.stdin:
    line = line.rstrip("\n")
    try: r = handle(line.split("\t"))
    except Exception as e: r = "ERR " + type(e).__name__
    out.write(r + "\n")
    if line.startswith("FLUSH"): out.flush()
out.flush()
