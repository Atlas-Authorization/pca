import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "sdks", "python-pca"))
sys.setrecursionlimit(1000)
from atlas_pca import UNSUPPORTED_SUITE, canonicalize_strict, evaluate_caveats, policy_caveats, hash_canonical, strict_parse, supported_suites, verify_chain, verify_pcactn_core
from atlas_pca import intent_v2 as V2, intent_wb as WB
from atlas_pca.intent_map import commit_leaves, decide_map_primitive


def _schema(i):
    sig = V2.verify_action_schema(i["schema"], i["keys"])["ok"]
    c = V2.conform_action(i["schema"], i["verb"], i["params"])
    out = {"sig": sig}
    if sig:
        out["digest"] = V2.action_schema_digest(i["schema"])
    out["conform"] = {"ok": True} if c["ok"] else dict({"ok": False, "code": c["code"]}, **({"path": c["path"]} if "path" in c else {}))
    return out


def _revocation(i):
    # the EVIDENCE is the input without the check parameters (so an extra input member makes it malformed)
    ev = {k: v for k, v in i.items() if k not in ("session", "scope", "authority", "ids", "now", "max_age_ms", "last")}
    kw = {"last": i["last"]} if "last" in i else {}
    if "scope" in i:
        kw["scope"] = i["scope"]
    return {"ok": V2.check_session_revocation(ev, session=i.get("session"), authority=i.get("authority"), ids=i.get("ids"),
                                              now=i.get("now"), max_age_ms=i.get("max_age_ms"), **kw)["ok"]}


def _world(i):
    g = WB.decide_intent_world(i)
    return {"ok": True, "world": g["world"], "single_source": g["single_source"]} if g["ok"] else {"ok": False}


def _provenance(i):
    g = WB.decide_param_provenance(i)
    out = {"outcome": g["outcome"]}
    if g["outcome"] != "deny":
        out.update(labels=g["labels"], classes=g["classes"])
    if g["outcome"] == "question":
        out["friction"] = g["friction"]
    return out


def _classifier(i):
    g = WB.decide_classifier_dimensions(i)
    return {"ok": True, "classes": g["classes"]} if g["ok"] else {"ok": False}


def _map(i):
    g = decide_map_primitive(i)
    return {"ok": True, "cell": g["cell"], "p_ppm": g["p_ppm"]} if g["ok"] else {"ok": False}


# Intent Layer v2 primitive kinds: raw = JSON text of the primitive's `input`; the response is {id, result: <exactly the
# expect shape of that primitive>} (reasons are never part of it).
V2_PRIMITIVES = {
    "intent_schema": _schema,
    "intent_revocation": _revocation,
    "intent_world": _world,
    "intent_provenance": _provenance,
    "intent_classifier": _classifier,
    "intent_wb_active": lambda i: {k: v for k, v in WB.intent_wb_active(i).items() if k in ("facts", "provenance", "classes")},
    "intent_read_purpose": lambda i: {k: v for k, v in WB.decide_read_purpose(i).items() if k in ("outcome", "minimise", "uncovered")},
    "intent_map_commit": lambda i: {"map_commit": commit_leaves(i["leaves"])},
    "intent_map": _map,
}

inp, outp = sys.argv[1], sys.argv[2]
with open(inp, encoding="utf-8") as f, open(outp, "w", encoding="utf-8") as o:
    for line in f:
        c = json.loads(line)
        r = {"id": c["id"]}
        try:
            if c["kind"] == "suites":
                # Suite-capability manifest (packages/pca/conformance/SUITES.md).
                r["suites"] = supported_suites()
            elif c["kind"] == "verify":
                grant = json.loads(c["grant"])
                # Intent Layer M2: optional `intent_policy_json` (raw JSON text, parsed with the platform parser; wins) or
                # `intent_policy` (a JSON object, or a JSON-encoded string). A bare `-0` parses as -0.0 like JSON.parse.
                ip = c.get("intent_policy")
                if "intent_policy_json" in c:
                    ip = c["intent_policy_json"]
                if isinstance(ip, str):
                    ip = json.loads(ip, parse_int=lambda t: -0.0 if t == "-0" else int(t))
                # Intent Layer v2: optional `intent_v2` verifier state (a JSON object, or a JSON-encoded string).
                iv2 = c.get("intent_v2")
                if isinstance(iv2, str):
                    iv2 = json.loads(iv2)
                g = verify_pcactn_core(c["raw"], grant, now=c["now"], audience=c["aud"], allowed_suites=c.get("allowed_suites"),
                                       intent_policy=ip, intent_v2=iv2)
                r["allow"] = bool(g.allow)
                r["checks"] = {k: bool(v) for k, v in g.checks.items()}
                if UNSUPPORTED_SUITE in (g.reason or ""):
                    r["unsupported_suite"] = g.reason
            elif c["kind"] == "policy":
                # Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
                # evaluate_caveats(policy_caveats(grant, chain), context) as {allow, failed}
                o_ = json.loads(c["raw"])
                ok, failed = evaluate_caveats(policy_caveats(o_["grant"], o_["chain"]), o_["context"])
                r["allow"] = bool(ok)
                r["failed"] = list(failed)
            elif c["kind"] in V2_PRIMITIVES:
                # raw = the primitive's input as raw JSON text (README "Raw JSON text members": a bare -0 stays -0.0)
                r["result"] = V2_PRIMITIVES[c["kind"]](json.loads(c["raw"], parse_int=lambda t: -0.0 if t == "-0" else int(t)))
            elif c["kind"] == "chain":
                # R4-01: standalone verify_chain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                o_ = json.loads(c["raw"])
                ok, why = verify_chain(o_["chain"], o_.get("expected_root_issuer"), o_.get("allowed_suites"),
                                        pq_pins=o_.get("pq_pins"), trusted_root=o_.get("trusted_root"))
                r["allow"] = bool(ok)
                r["checks"] = {"chain": bool(ok)}
                if isinstance(why, str) and UNSUPPORTED_SUITE in why:
                    r["unsupported_suite"] = why
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
