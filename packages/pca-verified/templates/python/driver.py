"""PCA Verified driver (Python), a working reference driver over the Atlas Python verifier (`pip install atlas-pca`).

Protocol (see docs/pca/reference/pca-verified-protocol.md): `python3 driver.py <in.jsonl> <out.jsonl>`. Read one JSON object per
line from <in.jsonl>; write exactly one JSON object per line to <out.jsonl>, in any order, each carrying the `id` it answers.

To drive YOUR implementation instead: keep the framing at the bottom, and replace the calls inside the branches of `answer()`
with calls into your own verifier / canonicalizer / producer. A kind you do not implement: leave it out and answer
{"id": ..., "error": "unsupported"}; the runner then reports that layer as unsupported, never as passed.
"""
import json, sys

from atlas_pca import UNSUPPORTED_SUITE, canonicalize_strict, evaluate_agent_caveats, hash_canonical, policy_caveats, strict_parse, supported_suites, verify_chain, verify_pcactn_core

sys.setrecursionlimit(1000)

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
                # optional `intent_v2` verifier state (a JSON object, or a JSON-encoded string).
                iv2 = c.get("intent_v2")
                if isinstance(iv2, str):
                    iv2 = json.loads(iv2)
                g = verify_pcactn_core(c["raw"], grant, now=c["now"], audience=c["aud"], allowed_suites=c.get("allowed_suites"),
                                       intent_policy=ip, intent_v2=iv2, insecure_skip_plan_root_check=True)
                r["allow"] = bool(g.allow)
                r["checks"] = {k: bool(v) for k, v in g.checks.items()}
                if UNSUPPORTED_SUITE in (g.reason or ""):
                    r["unsupported_suite"] = g.reason
            elif c["kind"] == "policy":
                # Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
                # the agent-native evaluator (predicates + tool_schema) over policy_caveats(grant, chain), as {allow, failed}:
                # the action context is {action}, the tool call the signed verb + params (the reference's toolCallOf)
                o_ = json.loads(c["raw"])
                act = o_["context"].get("action")
                params = act.get("params") if isinstance(act, dict) else None
                call = {"tool": act["verb"] if isinstance(act, dict) and isinstance(act.get("verb"), str) else "",
                        "args": params if isinstance(params, dict) else {}}
                ok, failed = evaluate_agent_caveats(policy_caveats(o_["grant"], o_["chain"]), o_["context"], {"action": act}, call)
                r["allow"] = bool(ok)
                r["failed"] = list(failed)
            elif c["kind"] == "produce":
                # This template does not sign. Answer unsupported_op (not an error of the signer): the runner reports the
                # producer layer as unsupported. To implement it, run the named `op` over `args` and answer {"out": <artifact>}.
                r["error"] = "unsupported_op: " + json.loads(c["raw"]).get("op", "")
            elif c["kind"] == "chain":
                # R4-01: standalone verify_chain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                o_ = json.loads(c["raw"])
                ok, why = verify_chain(o_["chain"], o_.get("expected_root_issuer"), o_.get("allowed_suites"),
                                        pq_pins=o_.get("pq_pins"), trusted_root=o_.get("trusted_root"))
                r["allow"] = bool(ok)
                r["checks"] = {"chain": bool(ok)}
                if isinstance(why, str) and UNSUPPORTED_SUITE in why:
                    r["unsupported_suite"] = why
            elif c["kind"] != "canon":
                r["error"] = "unsupported"  # e.g. `stateful`: this template does not run sequences
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
