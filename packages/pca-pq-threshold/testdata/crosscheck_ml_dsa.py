"""Independent ML-DSA-65 implementations used to cross-check the ML-DSA that PCA uses.

  * dilithium-py (pure-Python reference-style FIPS 204 implementation)
  * liboqs-python / liboqs (C, Open Quantum Safe)

stdin JSON: {"noble": [{"seed","msg"}]}.  stdout JSON: results the Node generator folds into
crosscheck-ml-dsa-65.json. Run with `python -I` inside a venv containing the pinned packages.
"""
import json, sys, hashlib
from importlib.metadata import version
from dilithium_py.ml_dsa import ML_DSA_65
import oqs

req = json.load(sys.stdin)
out = {"versions": {"dilithium-py": version("dilithium-py"), "liboqs-python": version("liboqs-python"), "liboqs": oqs.oqs_version()}}

# 1) signatures made by PCA's ML-DSA must verify in both independent libraries (and tampering must not).
noble = []
for c in req["noble"]:
    pk, msg, sig = bytes.fromhex(c["pk"]), bytes.fromhex(c["msg"]), bytes.fromhex(c["sig"])
    with oqs.Signature("ML-DSA-65") as v:
        lo = v.verify(msg, sig, pk)
        lo_bad_msg = v.verify(msg + b"\x00", sig, pk)
        bad = bytearray(sig); bad[100] ^= 1
        lo_bad_sig = v.verify(msg, bytes(bad), pk)
    dp = ML_DSA_65.verify(pk, msg, sig)
    dp_bad_msg = ML_DSA_65.verify(pk, msg + b"\x00", sig)
    dp_bad_sig = ML_DSA_65.verify(pk, msg, bytes(bad))
    noble.append({"dilithium_py_verifies": dp, "liboqs_verifies": lo, "tampered_rejected": not (dp_bad_msg or dp_bad_sig or lo_bad_msg or lo_bad_sig)})
out["noble_checked"] = noble

# 2) keys + deterministic signatures from dilithium-py (FIPS 204 KeyGen_internal from seed; rnd = 0^32).
dil = []
for c in req["noble"]:
    seed = bytes.fromhex(c["seed"]); msg = bytes.fromhex(c["msg"])
    pk, sk = ML_DSA_65.key_derive(seed)
    sig = ML_DSA_65.sign(sk, msg, deterministic=True)
    dil.append({"seed": c["seed"], "pk": pk.hex(), "sk": sk.hex(), "msg": c["msg"], "sig_deterministic": sig.hex()})
out["dilithium_py"] = dil

# 3) fresh liboqs keypairs + (hedged-randomized) signatures.
lo = []
for c in req["noble"][:4]:
    msg = bytes.fromhex(c["msg"])
    with oqs.Signature("ML-DSA-65") as s:
        pk = s.generate_keypair()
        sig = s.sign(msg)
    lo.append({"pk": pk.hex(), "msg": c["msg"], "sig": sig.hex()})
out["liboqs"] = lo
json.dump(out, sys.stdout)
