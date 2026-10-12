import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "sdks", "python-pca"))
sys.setrecursionlimit(1000)
from atlas_pca import canonicalize_strict, hash_canonical, strict_parse, verify_chain, verify_pcactn_core

inp, outp = sys.argv[1], sys.argv[2]
with open(inp, encoding="utf-8") as f, open(outp, "w", encoding="utf-8") as o:
    for line in f:
        c = json.loads(line)
        r = {"id": c["id"]}
        try:
            if c["kind"] == "verify":
                grant = json.loads(c["grant"])
                g = verify_pcactn_core(c["raw"], grant, now=c["now"], audience=c["aud"], allowed_suites=c.get("allowed_suites"))
                r["allow"] = bool(g.allow)
                r["checks"] = {k: bool(v) for k, v in g.checks.items()}
            elif c["kind"] == "chain":
                # R4-01: standalone verify_chain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                o_ = json.loads(c["raw"])
                ok, _why = verify_chain(o_["chain"], o_.get("expected_root_issuer"), o_.get("allowed_suites"),
                                        pq_pins=o_.get("pq_pins"), trusted_root=o_.get("trusted_root"))
                r["allow"] = bool(ok)
                r["checks"] = {"chain": bool(ok)}
            else:
                try:
                    v = strict_parse(c["raw"])
                    s = canonicalize_strict(v)
                except Exception:
                    r["error"] = "parse"
                else:
                    r["canon"] = s
                    r["hash"] = hash_canonical(v)
        except BaseException as e:
            r = {"id": c["id"], "error": "exception:" + type(e).__name__}
        o.write(json.dumps(r) + "\n")
