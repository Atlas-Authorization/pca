"""Independent ML-KEM (FIPS 203) implementation (kyber-py) used to cross-check the K-PKE core.

Reads JSON on stdin, writes JSON (last line of stdout) for crosscheck-ml-kem-768.json:
  * K-PKE.Encrypt (deterministic given coins) and K-PKE.Decrypt must agree byte-for-byte with the wasm
  * keys made by kyber-py (FIPS 203 K-PKE.KeyGen) drive the wasm, and vice versa
  * SampleNTT stream sampler (hashToRing): first polynomial via kyber-py itself, all three via a
    straight transcription of FIPS 203 Algorithm 7 over hashlib's SHAKE128.
"""
import json, sys, hashlib
from importlib.metadata import version
from kyber_py.ml_kem import ML_KEM_768 as K

req = json.load(sys.stdin)
out = {"versions": {"kyber-py": version("kyber-py")}}

# A) wasm-generated K-PKE keys: kyber-py encrypts to them, kyber-py decrypts wasm ciphertexts.
a = []
for c in req["wasm_keys"]:
    pk, sk, m, r = (bytes.fromhex(c[k]) for k in ("pk", "sk", "m", "coins"))
    ct_py = K._k_pke_encrypt(pk, m, r)
    a.append({"ct_kyber_py": ct_py.hex(), "kyber_py_decrypts_wasm_ct": K._k_pke_decrypt(sk, bytes.fromhex(c["ct_wasm"])) == m,
              "kyber_py_decrypts_own_ct_under_wasm_sk": K._k_pke_decrypt(sk, ct_py) == m})
out["wasm_keys_checked"] = a

# B) kyber-py-generated (FIPS 203 KeyGen) keys: ciphertexts for wasm to decrypt.
b = []
for c in req["py_keys"]:
    d, m, r = (bytes.fromhex(c[k]) for k in ("d", "m", "coins"))
    ek, dk = K._k_pke_keygen(d)
    b.append({"d": c["d"], "ek": ek.hex(), "dk": dk.hex(), "m": c["m"], "coins": c["coins"], "ct": K._k_pke_encrypt(ek, m, r).hex()})
out["py_keys"] = b

# C) "uniform" public keys (hashToRing output || rho): the endemic OT's non-chosen branch.
u = []
for c in req["uniform_keys"]:
    pk, m, r = (bytes.fromhex(c[k]) for k in ("pk", "m", "coins"))
    u.append({"ct": K._k_pke_encrypt(pk, m, r).hex()})
out["uniform_checked"] = u

def sample_ntt_stream(data, ncoef):
    xof = hashlib.shake_128(data).digest(8192)
    i, coefs = 0, []
    while len(coefs) < ncoef:
        b0, b1, b2 = xof[i], xof[i + 1], xof[i + 2]; i += 3
        d1 = b0 + 256 * (b1 % 16); d2 = (b1 // 16) + 16 * b2
        if d1 < 3329: coefs.append(d1)
        if d2 < 3329 and len(coefs) < ncoef: coefs.append(d2)
    return coefs
def pack(coefs):
    o = bytearray()
    for i in range(0, len(coefs), 2):
        x, y = coefs[i], coefs[i + 1]
        o += bytes([x & 255, (x >> 8) | ((y & 15) << 4), y >> 4])
    return bytes(o)
h = []
for c in req["ring_inputs"]:
    data = bytes.fromhex(c)
    coefs = sample_ntt_stream(data, 768)
    first = K.R.ntt_sample(hashlib.shake_128(data).digest(2048)).coeffs
    assert list(first) == coefs[:256], "own Alg.7 transcription disagrees with kyber-py"
    h.append({"input": c, "out": pack(coefs).hex()})
out["hash_to_ring"] = h
json.dump(out, sys.stdout)
