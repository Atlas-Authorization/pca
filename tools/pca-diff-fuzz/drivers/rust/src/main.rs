// Rust differential driver (wire format v2). NOT EXECUTED in the authoring environment (no cargo); CI builds it.
//   pcadriver <corpus.jsonl> <out.jsonl>
use atlas_pca::*;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn one(c: &Value) -> Value {
    let kind = c["kind"].as_str().unwrap_or("");
    let raw = c["raw"].as_str().unwrap_or("").to_string();
    if kind == "suites" {
        // Suite-capability manifest (packages/pca/conformance/SUITES.md).
        return json!({"suites": supported_suites()});
    }
    if kind == "verify" {
        let grant: Value = match serde_json::from_str(c["grant"].as_str().unwrap_or("")) { Ok(v) => v, Err(_) => return json!({"error": "exception:grant"}) };
        let allowed: Option<Vec<String>> = c["allowed_suites"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        // Intent Layer M2: optional intent_policy object (lenient; a misconfigured threshold fails the check closed).
        // intent_policy_json (raw JSON text, keeps 950000.0 / 1e6 / -0.0) wins over intent_policy.
        let intent = match c.get("intent_policy_json").and_then(Value::as_str) {
            Some(text) => match IntentPolicy::from_json_text(text) {
                Ok(p) => Some(p),
                Err(_) => return json!({"error": "exception:intent_policy_json"}),
            },
            None => c.get("intent_policy").and_then(IntentPolicy::from_json),
        };
        // Intent Layer v2: optional intent_v2 object (the verifier state: params, schemas, session root / grants /
        // revocation, layers, W-B artifacts and policy, accumulator state, receipts, sequencer key sets).
        // absent = no v2 state; a null (or non-object) intent_v2 is malformed
        let intent_v2 = match c.get("intent_v2") {
            None => None,
            Some(v) => match IntentV2Context::from_json(v) {
                Some(x) => Some(x),
                None => return json!({"error": "exception:intent_v2"}),
            },
        };
        let opts = VerifyOptions { allowed: allowed.as_deref(), intent: intent.as_ref(), intent_v2: intent_v2.as_ref() };
        let g = verify_pcactn_json_with(&raw, &grant, c["now"].as_i64().unwrap_or(0), c["aud"].as_str().unwrap_or(""), &opts);
        let mut r = json!({"allow": g.allow, "checks": serde_json::to_value(&g.checks).unwrap()});
        if g.reason.contains(UNSUPPORTED_SUITE_REASON) {
            r["unsupported_suite"] = json!(g.reason);
        }
        r
    } else if kind == "chain" {
        // R4-01: standalone chain verify with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
        let o: Value = match serde_json::from_str(&raw) { Ok(v) => v, Err(_) => return json!({"error": "exception:chain"}) };
        let chain: Vec<Value> = o["chain"].as_array().cloned().unwrap_or_default();
        let allowed: Option<Vec<String>> = o["allowed_suites"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        let pins: Option<std::collections::HashMap<String, String>> = o["pq_pins"].as_object().map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect());
        let trusted = if o["trusted_root"].is_null() { None } else { Some(&o["trusted_root"]) };
        let res = verify_chain_policy(&chain, o["expected_root_issuer"].as_str(), allowed.as_deref(), pins.as_ref(), trusted);
        let ok = res.is_ok();
        let mut r = json!({"allow": ok, "checks": {"chain": ok}});
        if let Err(why) = res {
            if why.contains(UNSUPPORTED_SUITE_REASON) {
                r["unsupported_suite"] = json!(why);
            }
        }
        r
    } else if kind == "policy" {
        // Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
        // evaluate_caveats(policy_caveats(grant, chain), context) as {allow, failed}
        let o: Value = match serde_json::from_str(&raw) { Ok(v) => v, Err(_) => return json!({"error": "exception:policy"}) };
        let (ok, failed) = evaluate_caveats(&policy_caveats(&o["grant"], &o["chain"]), &o["context"]);
        json!({"allow": ok, "failed": failed})
    } else if kind.starts_with("intent_") {
        // Intent Layer v2 primitives: raw = JSON text of the primitive's `input`; result = that primitive's `expect` shape.
        let i: Value = match serde_json::from_str(&raw) { Ok(v) => v, Err(_) => return json!({"error": format!("exception:{kind}")}) };
        match intent_primitive(kind, &i) {
            Some(r) => json!({"result": r}),
            None => json!({"error": format!("exception:{kind}")}),
        }
    } else {
        match strict_parse(&raw) {
            Ok(v) => match canonicalize_strict(&v) {
                Ok(s) => json!({"canon": s, "hash": hash_canonical(&v)}),
                Err(_) => json!({"error": "parse"}),
            },
            Err(_) => json!({"error": "parse"}),
        }
    }
}

/// One Intent Layer v2 primitive, reported in exactly the shape of its conformance `expect`.
fn intent_primitive(kind: &str, i: &Value) -> Option<Value> {
    Some(match kind {
        "intent_schema" => {
            let sig = verify_action_schema(&i["schema"], &i["keys"]).is_ok();
            let c = conform_action(&i["schema"], i["verb"].as_str().unwrap_or(""), &i["params"]);
            let mut conform = json!({"ok": c.ok});
            if let Some(code) = c.code { conform["code"] = json!(code); }
            if let Some(path) = c.path { conform["path"] = json!(path); }
            let mut out = json!({"sig": sig, "conform": conform});
            if sig {
                out["digest"] = json!(action_schema_digest(&i["schema"]));
            }
            out
        }
        "intent_revocation" => {
            let ids: Option<Vec<String>> = i["ids"].as_array().and_then(|a| a.iter().map(|x| x.as_str().map(String::from)).collect());
            // the evidence is the input without the parameters (README rule 13; closed: any other member is malformed)
            let mut ev = i.as_object().cloned().unwrap_or_default();
            for k in ["session", "scope", "authority", "ids", "now", "max_age_ms", "last"] {
                ev.remove(k);
            }
            let ev = Value::Object(ev);
            let ok = match (ids, i["authority"].as_str()) {
                (Some(ids), Some(authority)) => check_session_revocation(
                    Some(&ev),
                    i["session"].as_str().unwrap_or(""),
                    authority,
                    &ids,
                    i["now"].as_f64().unwrap_or(f64::NAN),
                    i["max_age_ms"].as_f64().unwrap_or(f64::NAN),
                    i.get("scope").and_then(Value::as_str),
                    None,
                    i.get("last"),
                )
                .is_ok(),
                _ => false,
            };
            json!({"ok": ok})
        }
        "intent_map_commit" => json!({"map_commit": map_commit_of_leaves(&i["leaves"])}),
        "intent_map" => {
            let eps = i.get("max_residual_risk_ppm").and_then(Value::as_i64);
            let d = decide_map_disclosure(i.get("map_commit"), &i["action"], i.get("params"), i.get("disclosure"), eps);
            if d.ok { json!({"ok": true, "cell": d.cell, "p_ppm": d.p_ppm}) } else { json!({"ok": false}) }
        }
        "intent_world" => {
            let d = decide_intent_world(i);
            if d.ok { json!({"ok": true, "world": d.world, "single_source": d.single_source}) } else { json!({"ok": false}) }
        }
        "intent_provenance" => {
            let d = decide_param_provenance(i);
            match d.outcome.as_str() {
                "deny" => json!({"outcome": "deny"}),
                "question" => json!({"outcome": "question", "friction": d.friction, "labels": d.labels, "classes": d.classes}),
                o => json!({"outcome": o, "labels": d.labels, "classes": d.classes}),
            }
        }
        "intent_wb_active" => {
            let (facts, provenance, classes) = intent_wb_active(i);
            json!({"facts": facts, "provenance": provenance, "classes": classes})
        }
        "intent_read_purpose" => {
            let d = decide_read_purpose(i);
            json!({"outcome": d.outcome, "minimise": d.minimise, "uncovered": d.uncovered})
        }
        "intent_classifier" => {
            let d = decide_classifier_dimensions(i);
            if d.ok { json!({"ok": true, "classes": d.classes}) } else { json!({"ok": false}) }
        }
        _ => return None,
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let f = std::io::BufReader::new(std::fs::File::open(&a[1]).unwrap());
    let mut o = std::io::BufWriter::new(std::fs::File::create(&a[2]).unwrap());
    for line in f.lines() {
        let line = line.unwrap();
        if line.is_empty() { continue; }
        let c: Value = serde_json::from_str(&line).unwrap();
        let id = c["id"].clone();
        let r = std::panic::catch_unwind(|| one(&c));
        let mut m = match r { Ok(v) => v, Err(_) => json!({"error": "exception:panic"}) };
        m["id"] = id;
        writeln!(o, "{}", m).unwrap();
        o.flush().unwrap();
    }
}
