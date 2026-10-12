// Rust differential driver (wire format v2). NOT EXECUTED in the authoring environment (no cargo); CI builds it.
//   pcadriver <corpus.jsonl> <out.jsonl>
use atlas_pca::*;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn one(c: &Value) -> Value {
    let kind = c["kind"].as_str().unwrap_or("");
    let raw = c["raw"].as_str().unwrap_or("").to_string();
    if kind == "verify" {
        let grant: Value = match serde_json::from_str(c["grant"].as_str().unwrap_or("")) { Ok(v) => v, Err(_) => return json!({"error": "exception:grant"}) };
        let allowed: Option<Vec<String>> = c["allowed_suites"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        let g = verify_pcactn_json_policy(&raw, &grant, c["now"].as_i64().unwrap_or(0), c["aud"].as_str().unwrap_or(""), allowed.as_deref());
        json!({"allow": g.allow, "checks": serde_json::to_value(&g.checks).unwrap()})
    } else if kind == "chain" {
        // R4-01: standalone chain verify with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
        let o: Value = match serde_json::from_str(&raw) { Ok(v) => v, Err(_) => return json!({"error": "exception:chain"}) };
        let chain: Vec<Value> = o["chain"].as_array().cloned().unwrap_or_default();
        let allowed: Option<Vec<String>> = o["allowed_suites"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        let pins: Option<std::collections::HashMap<String, String>> = o["pq_pins"].as_object().map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect());
        let trusted = if o["trusted_root"].is_null() { None } else { Some(&o["trusted_root"]) };
        let ok = verify_chain_policy(&chain, o["expected_root_issuer"].as_str(), allowed.as_deref(), pins.as_ref(), trusted).is_ok();
        json!({"allow": ok, "checks": {"chain": ok}})
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
