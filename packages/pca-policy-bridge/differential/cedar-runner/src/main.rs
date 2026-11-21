// Reads JSON lines {id, policies, entities, requests:[{principal, action, resource, context}]} on stdin and
// writes {id, decisions:["Allow"|"Deny"|"Error: ..."]} per line, using the real Cedar authorizer.
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::str::FromStr;

fn main() {
    let auth = Authorizer::new();
    let out = std::io::stdout();
    let mut out = out.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line).unwrap();
        let id = v["id"].clone();
        let policies = PolicySet::from_str(v["policies"].as_str().unwrap());
        let entities = Entities::from_json_value(v["entities"].clone(), None);
        let decisions: Vec<String> = match (&policies, &entities) {
            (Ok(ps), Ok(es)) => v["requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    let p = EntityUid::from_str(r["principal"].as_str().unwrap()).unwrap();
                    let a = EntityUid::from_str(r["action"].as_str().unwrap()).unwrap();
                    let res = EntityUid::from_str(r["resource"].as_str().unwrap()).unwrap();
                    let ctx = Context::from_json_value(r["context"].clone(), None).unwrap();
                    let req = Request::new(p, a, res, ctx, None).unwrap();
                    match auth.is_authorized(&req, ps, es).decision() {
                        Decision::Allow => "Allow".to_string(),
                        Decision::Deny => "Deny".to_string(),
                    }
                })
                .collect(),
            (Err(e), _) => vec![format!("Error: policy parse: {e}")],
            (_, Err(e)) => vec![format!("Error: entities: {e}")],
        };
        writeln!(out, "{}", json!({ "id": id, "decisions": decisions })).unwrap();
    }
}
