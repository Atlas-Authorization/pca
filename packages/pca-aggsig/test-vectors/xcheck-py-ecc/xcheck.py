"""Cross-implementation runner for @atlasauth/pca-aggsig using py_ecc 8.0.0 (Ethereum Foundation,
pure-Python BLS12-381; G2ProofOfPossession = BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_).

  python xcheck.py gen            -> deterministic corpus on stdout
  python xcheck.py verify < in    -> check TypeScript-produced artifacts
"""
import json
import sys

from py_ecc.bls import G2ProofOfPossession as bls


def sk_from_int(n: int) -> int:
    return n


def b(x: bytes) -> str:
    return x.hex()


def gen() -> dict:
    sks = [0x263DBD792F5B1BE47ED85F8938C0F29586AF0D3AC7B977F21C278FE1462040E3,
           0x47B8192D77BF871B62E87859D653922725724A5C031AFEABC60BCEF5FF665138,
           0x328388AFF0D4A5B7DC9205ABD374E7E98F3CD9F3418EDB4EAFDA5FB16473D216,
           0x0000000000000000000000000000000000000000000000000000000000000001,
           0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000]  # r - 1
    msgs = [b"", b"\x00", b"agent capability 1", bytes(range(256)), b"\x41" * 1000]
    keys = []
    for sk in sks:
        pk = bls.SkToPk(sk)
        keys.append({"sk": sk.to_bytes(32, "big").hex(), "pk": b(pk), "pop": b(bls.PopProve(sk))})
    sigs = []
    for i, sk in enumerate(sks):
        for j, m in enumerate(msgs):
            if (i + j) % 2 == 0:
                sigs.append({"key": i, "msg": b(m), "sig": b(bls.Sign(sk, m))})
    # distinct-message aggregate (one message per key)
    distinct = [msgs[i] for i in range(len(sks))]
    agg_sigs = [bls.Sign(sk, m) for sk, m in zip(sks, distinct)]
    aggregate_distinct = {
        "keys": list(range(len(sks))),
        "msgs": [b(m) for m in distinct],
        "aggregate": b(bls.Aggregate(agg_sigs)),
        "valid": bls.AggregateVerify([bls.SkToPk(s) for s in sks], distinct, bls.Aggregate(agg_sigs)),
    }
    # same-message aggregate (FastAggregateVerify)
    same = b"witness tree head"
    fa_sigs = [bls.Sign(sk, same) for sk in sks]
    fast = {
        "keys": list(range(len(sks))),
        "msg": b(same),
        "aggregate": b(bls.Aggregate(fa_sigs)),
        "valid": bls.FastAggregateVerify([bls.SkToPk(s) for s in sks], same, bls.Aggregate(fa_sigs)),
    }
    assert aggregate_distinct["valid"] and fast["valid"]
    return {"library": "py_ecc 8.0.0", "keys": keys, "sigs": sigs,
            "aggregateDistinct": aggregate_distinct, "fastAggregate": fast}


def verify(doc: dict) -> dict:
    out = []
    for c in doc["cases"]:
        r = {}
        pk = bytes.fromhex(c["pk"])
        try:
            r["sig"] = bool(bls.Verify(pk, bytes.fromhex(c["msg"]), bytes.fromhex(c["sig"])))
        except Exception as e:  # noqa: BLE001 - report the library's rejection
            r["sig"] = f"error:{type(e).__name__}"
        try:
            r["pop"] = bool(bls.PopVerify(pk, bytes.fromhex(c["pop"])))
        except Exception as e:  # noqa: BLE001
            r["pop"] = f"error:{type(e).__name__}"
        out.append(r)
    ag = doc.get("aggregateDistinct")
    res = {"results": out}
    if ag:
        res["aggregateDistinct"] = bool(bls.AggregateVerify(
            [bytes.fromhex(k) for k in ag["pks"]], [bytes.fromhex(m) for m in ag["msgs"]], bytes.fromhex(ag["aggregate"])))
    fa = doc.get("fastAggregate")
    if fa:
        res["fastAggregate"] = bool(bls.FastAggregateVerify(
            [bytes.fromhex(k) for k in fa["pks"]], bytes.fromhex(fa["msg"]), bytes.fromhex(fa["aggregate"])))
    return res


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "gen":
        print(json.dumps(gen(), indent=2))
    elif mode == "verify":
        print(json.dumps(verify(json.load(sys.stdin)), indent=2))
    else:
        sys.exit("usage: xcheck.py gen|verify")
