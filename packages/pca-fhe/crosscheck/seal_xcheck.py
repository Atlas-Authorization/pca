"""Independent cross-check helper for @atlasauth/pca-fhe (needs: tenseal==0.3.18, zstandard==0.25.0).

Uses the raw Microsoft SEAL bindings that ship inside TenSEAL (`tenseal.sealapi`,
a separate pybind11 build of SEAL, NOT node-seal) to encrypt, evaluate and
decrypt the PCA risk gate, so the TypeScript implementation is checked against a
second, independently-built SEAL and an independently written circuit.

Usage: seal_xcheck.py <command> <in.json> <out.json>
Commands: gen | encrypt | eval | decrypt | params
All key/ciphertext blobs are base64 of SEAL's own `save()` output.
"""
import base64
import json
import os
import sys
import tempfile
import zlib

import tenseal
import zstandard
import tenseal.sealapi as s

N = 8192
PLAIN_BITS = 30


def context():
    parms = s.EncryptionParameters(s.SCHEME_TYPE.BFV)
    parms.set_poly_modulus_degree(N)
    parms.set_coeff_modulus(s.CoeffModulus.BFVDefault(N, s.SEC_LEVEL_TYPE.TC128))
    parms.set_plain_modulus(s.PlainModulus.Batching(N, PLAIN_BITS))
    return parms, s.SEALContext(parms, True, s.SEC_LEVEL_TYPE.TC128)


# Interop shim. TenSEAL's bundled SEAL and node-seal's SEAL stamp different (major.minor) values into the
# 16-byte stream header: magic(2) header_size(1) version_major(1) version_minor(1) compr_mode(1)
# reserved(2) size(8), and each build refuses the other's minor. Nested objects (a PublicKey wraps a
# Ciphertext, a SecretKey a Plaintext, ...) carry their own header INSIDE the compressed payload, so a
# one-byte patch of the outer header is not enough. This shim therefore decompresses the payload,
# rewrites the minor byte of every header it contains, and re-emits the stream UNCOMPRESSED. Only
# version stamps and the compression envelope change; the ring coefficients are never touched, and
# correctness is established by exact decryption results, not by trusting the rewrite.
_MAGIC = b"\x5e\xa1\x10\x04"


def _local_minor():
    pt = s.Plaintext()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "blob")
        pt.save(path)
        with open(path, "rb") as f:
            return f.read()[4]


NODE_MINOR = 1  # SEAL 4.1.x as bundled in node-seal 5.1.x


def _retarget(raw, minor):
    if raw[:4] != _MAGIC:
        raise ValueError("not a SEAL stream")
    compr = raw[5]
    payload = bytes(raw[16:])
    if compr == 2:
        payload = zstandard.ZstdDecompressor().decompressobj().decompress(payload)
    elif compr == 1:
        payload = zlib.decompress(payload)
    elif compr != 0:
        raise ValueError("unknown compression mode")
    body = bytearray(payload)
    old = raw[4]
    i = body.find(_MAGIC + bytes([old]))
    while i != -1:
        body[i + 4] = minor
        i = body.find(_MAGIC + bytes([old]), i + 5)
    header = bytearray(raw[:16])
    header[4] = minor
    header[5] = 0
    header[6:8] = b"\x00\x00"
    header[8:16] = (16 + len(body)).to_bytes(8, "little")
    return bytes(header) + bytes(body)


def b64(obj):
    """Serialize `obj` in the form node-seal can load (uncompressed, node's version stamp)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "blob")
        obj.save(path)
        with open(path, "rb") as f:
            return base64.b64encode(_retarget(f.read(), NODE_MINOR)).decode()


def load(cls, ctx, data):
    o = cls()
    raw = _retarget(base64.b64decode(data), _local_minor())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "blob")
        with open(path, "wb") as f:
            f.write(raw)
        o.load(ctx, path)
    return o


def pack(values):
    arr = [0] * N
    for i, v in enumerate(values):
        arr[i] = int(v)
    return arr


def encode(ctx, values):
    pt = s.Plaintext()
    s.BatchEncoder(ctx).encode(pack(values), pt)
    return pt


def encrypt(ctx, pk_b64, values):
    pk = load(s.PublicKey, ctx, pk_b64)
    ct = s.Ciphertext()
    s.Encryptor(ctx, pk).encrypt(encode(ctx, values), ct)
    return b64(ct)


def decode0(ctx, sk_b64, ct_b64):
    sk = load(s.SecretKey, ctx, sk_b64)
    ct = load(s.Ciphertext, ctx, ct_b64)
    pt = s.Plaintext()
    s.Decryptor(ctx, sk).decrypt(ct, pt)
    return int(s.BatchEncoder(ctx).decode_int64(pt)[0])


def add(ev, a, b):
    out = s.Ciphertext()
    ev.add(a, b, out)
    return out


def sum_slots(ev, ct, gk):
    # Independent slot-sum: fold rows with power-of-two rotations, then swap columns.
    step = 1
    while step < N // 2:
        rot = s.Ciphertext()
        ev.rotate_rows(ct, step, gk, rot)
        ct = add(ev, ct, rot)
        step *= 2
    col = s.Ciphertext()
    ev.rotate_columns(ct, gk, col)
    return add(ev, ct, col)


def dot(ctx, ev, ct, weights, gk):
    prod = s.Ciphertext()
    ev.multiply_plain(ct, encode(ctx, weights), prod)
    return sum_slots(ev, prod, gk)


def evaluate(ctx, gk_b64, enc_b64, weights, kappa_weights, budget):
    gk = load(s.GaloisKeys, ctx, gk_b64)
    ct = load(s.Ciphertext, ctx, enc_b64)
    ev = s.Evaluator(ctx)
    risk = dot(ctx, ev, ct, weights, gk)
    kr = dot(ctx, ev, ct, kappa_weights, gk)
    neg = s.Ciphertext()
    ev.negate(kr, neg)
    slack = s.Ciphertext()
    ev.add_plain(neg, encode(ctx, [budget]), slack)
    return b64(risk), b64(slack)


def main():
    cmd, src, dst = sys.argv[1:4]
    with open(src) as f:
        req = json.load(f)
    parms, ctx = context()
    if cmd == "params":
        out = {
            "tenseal": tenseal.__version__,
            "coeffModulusBits": [m.bit_count() for m in parms.coeff_modulus()],
            "plainModulus": parms.plain_modulus().value(),
            "polyModulusDegree": parms.poly_modulus_degree(),
            "slotCount": s.BatchEncoder(ctx).slot_count(),
        }
    elif cmd == "gen":
        kg = s.KeyGenerator(ctx)
        sk, pk = kg.secret_key(), s.PublicKey()
        kg.create_public_key(pk)
        gk = s.GaloisKeys()
        kg.create_galois_keys(gk)
        enc_inputs = encrypt(ctx, b64(pk), req["inputs"])
        risk, slack = evaluate(ctx, b64(gk), enc_inputs, req["weights"], req["kappaWeights"], req["budget"])
        out = {
            "tenseal": tenseal.__version__,
            "secretKey": b64(sk),
            "publicKey": b64(pk),
            "galoisKeys": b64(gk) if req.get("withGalois") else None,
            "encInputs": enc_inputs,
            "encRiskRaw": risk,
            "encSlack": slack,
            "riskRaw": decode0(ctx, b64(sk), risk),
            "slack": decode0(ctx, b64(sk), slack),
        }
    elif cmd == "encrypt":
        out = {"enc": encrypt(ctx, req["publicKey"], req["inputs"])}
    elif cmd == "eval":
        r, sl = evaluate(ctx, req["galoisKeys"], req["encInputs"], req["weights"], req["kappaWeights"], req["budget"])
        out = {"encRiskRaw": r, "encSlack": sl}
    elif cmd == "decrypt":
        out = {k: decode0(ctx, req["secretKey"], v) for k, v in req["cts"].items()}
    else:
        raise SystemExit("unknown command")
    with open(dst, "w") as f:
        json.dump(out, f)


main()
