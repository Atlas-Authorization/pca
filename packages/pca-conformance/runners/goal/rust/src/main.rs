// Rust runner for the pca-goal vectors (independent port of the reference semantics, written from formal/dafny/GoalIr.dfy). Usage: pca-goal-runner <vectors-dir>
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value as V;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;

fn canon(v: &V) -> String {
    match v {
        V::Null => "null".into(),
        V::Bool(b) => b.to_string(),
        V::Number(n) => n.to_string(),
        V::String(s) => cstr(s),
        V::Array(a) => format!("[{}]", a.iter().map(canon).collect::<Vec<_>>().join(",")),
        V::Object(m) => {
            let mut ks: Vec<&String> = m.keys().collect();
            ks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            format!("{{{}}}", ks.iter().map(|k| format!("{}:{}", cstr(k), canon(&m[*k]))).collect::<Vec<_>>().join(","))
        }
    }
}
fn cstr(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\u{8}' => o.push_str("\\b"),
            '\t' => o.push_str("\\t"),
            '\n' => o.push_str("\\n"),
            '\u{c}' => o.push_str("\\f"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
fn b64(s: &str) -> String { URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes())) }
fn goal_digest(g: &V) -> String { b64(&canon(&serde_json::json!({"d":"atlas-pca/goal-ir/v1","goal":g}))) }
fn s<'a>(v: &'a V) -> &'a str { v.as_str().unwrap_or("") }
fn i(v: &V) -> i64 { v.as_i64().unwrap_or(0) }
fn arr(v: &V) -> &[V] { v.as_array().map(|a| a.as_slice()).unwrap_or(&[]) }
// Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow); meet = min, join = max
fn k_not(a: i32) -> i32 { 2 - a }
fn b2k(b: bool) -> i32 { if b { 2 } else { 0 } }
fn eq_v(x: &V, y: &V) -> i32 {
    match s(&x["k"]) {
        "q" if s(&y["k"]) == "q" && x["q"]["u"] == y["q"]["u"] => b2k(i(&x["q"]["n"]) == i(&y["q"]["n"])),
        "s" if s(&y["k"]) == "s" => b2k(x["s"] == y["s"]),
        _ => 1,
    }
}
fn lt_v(x: &V, y: &V) -> i32 { if s(&x["k"]) == "q" && s(&y["k"]) == "q" && x["q"]["u"] == y["q"]["u"] { b2k(i(&x["q"]["n"]) < i(&y["q"]["n"])) } else { 1 } }
fn cmp_op(op: &str, x: Option<&V>, y: Option<&V>) -> i32 {
    let (Some(x), Some(y)) = (x, y) else { return 1 };
    match op {
        "eq" => eq_v(x, y),
        "ne" => k_not(eq_v(x, y)),
        "lt" => lt_v(x, y),
        "gte" => k_not(lt_v(x, y)),
        "gt" => lt_v(y, x),
        "lte" => k_not(lt_v(y, x)),
        _ => {
            let t = if s(&y["k"]) == "set" { arr(&y["items"]).iter().fold(0, |acc, it| acc.max(eq_v(x, it))) } else { 1 };
            if op == "in" { t } else { k_not(t) }
        }
    }
}
fn term(t: &V, a: &V, h: &V) -> Option<V> {
    match s(&t["k"]) {
        "param" => a["params"].get(s(&t["path"])).cloned(),
        "lit" => Some(t["v"].clone()),
        _ => h["aggs"].get(s(&t["bid"])).map(|q| serde_json::json!({"k":"q","q":q})),
    }
}
fn cond(c: &V, a: &V, h: &V) -> i32 {
    match s(&c["k"]) {
        "true" => 2,
        "cmp" => cmp_op(s(&c["op"]), term(&c["l"], a, h).as_ref(), term(&c["r"], a, h).as_ref()),
        "and" => cond(&c["a"], a, h).min(cond(&c["b"], a, h)),
        "or" => cond(&c["a"], a, h).max(cond(&c["b"], a, h)),
        _ => k_not(cond(&c["c"], a, h)),
    }
}
fn strs(v: &V) -> Vec<String> { arr(v).iter().map(|x| s(x).to_string()).collect() }
fn part_ids(o: &V, p: &V) -> Vec<String> {
    match s(&p["k"]) {
        "exact" => vec![s(&p["id"]).to_string()],
        "oneof" => strs(&p["ids"]),
        _ => arr(&o["rels"]).iter().find(|r| r["rel"] == p["rel"] && r["anchor"] == p["anchor"]).map(|r| strs(&r["members"])).unwrap_or_default(),
    }
}
// pattern: None = every resource
fn resolve(o: &V, sel: &V) -> Option<Vec<String>> {
    match s(&sel["k"]) {
        "any" => None,
        "all_of" => arr(&sel["parts"]).iter().rev().fold(None, |acc: Option<Vec<String>>, p| {
            let ids = part_ids(o, p);
            Some(match acc { None => ids, Some(rest) => ids.into_iter().filter(|x| rest.contains(x)).collect() })
        }),
        _ => Some(part_ids(o, sel)),
    }
}
fn res_ok(p: &Option<Vec<String>>, r: &str) -> bool { p.as_ref().map_or(true, |ids| ids.iter().any(|x| x == r)) }
fn verbs_of_class(o: &V, cls: &str) -> Vec<String> { arr(&o["verbs"]).iter().filter(|v| s(&v["cls"]) == cls).map(|v| s(&v["verb"]).to_string()).collect() }
fn proh_verbs(o: &V, p: &V) -> Vec<String> { let t = &p["target"]; if s(&t["k"]) == "verb" { vec![s(&t["verb"]).to_string()] } else { verbs_of_class(o, s(&t["cls"])) } }
fn lsel(o: &V, b: &V) -> (Vec<String>, Vec<String>) { let sl = &b["sel"]; if s(&sl["k"]) == "gids" { (strs(&sl["gids"]), vec![]) } else { (vec![], verbs_of_class(o, s(&sl["cls"]))) } }
fn applies(sl: &(Vec<String>, Vec<String>), gid: &str, verb: &str) -> bool { sl.0.iter().any(|x| x == gid) || sl.1.iter().any(|x| x == verb) }
fn exceeded(b: &V, sl: &(Vec<String>, Vec<String>), a: &V, h: &V) -> i32 {
    let at = i(&a["t"]);
    let in_scope = |x: &V| match s(&b["scope"]["k"]) {
        "session" => x["sess"] == a["sess"],
        "principal" => x["prin"] == a["prin"],
        "org" => x["org"] == a["org"],
        _ => { let ag = arr(&b["scope"]["agents"]); ag.contains(&a["agent"]) && ag.contains(&x["agent"]) }
    };
    let in_win = |x: &V| { let w = &b["window"]; let xt = i(&x["t"]); match s(&w["k"]) {
        "sliding" => xt > at - i(&w["ms"]) && xt <= at,
        "period" => i(&w["ms"]) > 0 && (xt - i(&w["t0"])).div_euclid(i(&w["ms"])) == (at - i(&w["t0"])).div_euclid(i(&w["ms"])),
        _ => true } };
    let mut items: Vec<&V> = arr(&h["adms"]).iter().filter(|m| applies(sl, s(&m["gid"]), s(&m["act"]["verb"])) && in_scope(&m["act"]) && in_win(&m["act"])).map(|m| &m["act"]).collect();
    items.push(a);
    let cap = i(&b["cap"]["n"]);
    match s(&b["agg"]) {
        "count" => return b2k(items.len() as i64 > cap),
        "distinct" => {
            let mut ks = BTreeSet::new();
            for x in &items {
                match x["params"].get(s(&b["key"])) { Some(v) => { ks.insert(canon(v)); } None => return 1 }
            }
            return b2k(ks.len() as i64 > cap);
        }
        _ => {}
    }
    let mut vals = vec![];
    for x in &items {
        match term(&b["value"], x, h) { Some(t) if s(&t["k"]) == "q" && t["q"]["u"] == b["cap"]["u"] => vals.push(i(&t["q"]["n"])), _ => return 1 }
    }
    let r: i64 = if s(&b["agg"]) == "sum" { vals.iter().sum() } else { *vals.iter().max().unwrap() };
    b2k(r > cap)
}
fn bound_dec(b: &V, sl: &(Vec<String>, Vec<String>), a: &V, h: &V) -> i32 {
    match exceeded(b, sl, a, h) { 2 => if s(&b["onExceed"]) == "deny" { 0 } else { 1 }, 1 => 1, _ => 2 }
}
fn strip(g: &V) -> V {
    let hs = arr(&g["holes"]);
    let mut out = g.clone();
    out["grants"] = V::Array(arr(&g["grants"]).iter().filter(|x| !hs.iter().any(|h| h["global"] == true || arr(&h["affects"]).contains(&x["gid"]))).cloned().collect());
    out["holes"] = V::Array(vec![]);
    out
}
fn decide(goal: &V, o: &V, a: &V, h: &V) -> V {
    let g = strip(goal);
    let v = &g["validity"];
    let at = i(&a["t"]);
    let depth = i(&a["depth"]);
    let mut d = 2;
    if at < i(&v["notBefore"]) || at > i(&v["notAfter"]) { d = 0; }
    else if i(&v["maxIdle"]) > 0 && i(&h["last"]) >= 0 && at - i(&h["last"]) > i(&v["maxIdle"]) { d = 0; }
    else if depth < 0 || depth > i(&g["deleg"]["maxDepth"]) { d = 0; }
    let verb = s(&a["verb"]);
    let res = s(&a["res"]);
    for p in arr(&g["prohibits"]) {
        let m = b2k(proh_verbs(o, p).iter().any(|x| x == verb)).min(b2k(res_ok(&resolve(o, &p["res"]), res)).min(cond(&p["cond"], a, h)));
        d = d.min(match m { 2 => 0, 1 => 1, _ => 2 });
    }
    for c in arr(&g["escalateOn"]) { d = d.min(if cond(c, a, h) == 0 { 2 } else { 1 }); }
    let mut per = vec![];
    for gr in arr(&g["grants"]) {
        let deleg_ok = depth == 0 || arr(&g["deleg"]["mayTouch"]).contains(&gr["gid"]);
        let mut m = b2k(verb == s(&gr["verb"]) && deleg_ok).min(b2k(res_ok(&resolve(o, &gr["res"]), res)).min(cond(&gr["cond"], a, h)));
        for b in arr(&g["bounds"]) { let sl = lsel(o, b); if applies(&sl, s(&gr["gid"]), verb) { m = m.min(bound_dec(b, &sl, a, h)); } }
        per.push(m);
    }
    d = d.min(per.iter().copied().max().unwrap_or(0));
    if d != 2 { return serde_json::json!({"decision": if d == 1 { "escalate" } else { "deny" }, "witness": null}); }
    let gid = s(&arr(&g["grants"])[per.iter().position(|x| *x == 2).unwrap()]["gid"]).to_string();
    let bids: Vec<V> = arr(&g["bounds"]).iter().filter(|b| applies(&lsel(o, b), &gid, verb)).map(|b| b["bid"].clone()).collect();
    serde_json::json!({"decision":"allow","witness":{"gid":gid,"bids":bids}})
}
// lowering (GoalCompile.dfy Lower) for the policy digest
fn neg(op: &str) -> &str { match op { "eq" => "ne", "ne" => "eq", "lt" => "gte", "gte" => "lt", "gt" => "lte", "lte" => "gt", "in" => "nin", _ => "in" } }
fn nnf(c: &V, pos: bool) -> V {
    match s(&c["k"]) {
        "true" => serde_json::json!({"k": if pos { "true" } else { "false" }}),
        "cmp" => serde_json::json!({"k":"atom","op": if pos { s(&c["op"]) } else { neg(s(&c["op"])) },"l":c["l"],"r":c["r"]}),
        k @ ("and" | "or") => { let k2 = if pos { k } else if k == "and" { "or" } else { "and" }; serde_json::json!({"k":k2,"a":nnf(&c["a"], pos),"b":nnf(&c["b"], pos)}) }
        _ => nnf(&c["c"], !pos),
    }
}
fn pat(p: Option<Vec<String>>) -> V { match p { None => serde_json::json!({"k":"star"}), Some(ids) => serde_json::json!({"k":"set","ids":ids}) } }
fn lower(o: &V, goal: &V) -> V {
    let g = strip(goal);
    serde_json::json!({
        "preds": arr(&g["grants"]).iter().map(|x| serde_json::json!({"gid":x["gid"],"verb":x["verb"],"res":pat(resolve(o,&x["res"])),"cond":nnf(&x["cond"],true)})).collect::<Vec<_>>(),
        "prohs": arr(&g["prohibits"]).iter().map(|p| serde_json::json!({"pid":p["pid"],"verbs":proh_verbs(o,p),"res":pat(resolve(o,&p["res"])),"cond":nnf(&p["cond"],true)})).collect::<Vec<_>>(),
        "ceils": arr(&g["bounds"]).iter().map(|b| { let sl = lsel(o, b); serde_json::json!({"bid":b["bid"],"selGids":sl.0,"selVerbs":sl.1,"agg":b["agg"],"value":b["value"],"key":b["key"],"window":b["window"],"scope":b["scope"],"cap":b["cap"],"onExceed":b["onExceed"]}) }).collect::<Vec<_>>(),
        "escs": arr(&g["escalateOn"]).iter().map(|c| nnf(c, true)).collect::<Vec<_>>(),
        "validity": g["validity"], "deleg": g["deleg"],
    })
}
fn rank(d: &str) -> Option<u8> { match d { "deny" => Some(0), "escalate" => Some(1), "allow" => Some(2), _ => None } }
fn meet<'a>(d: &'a str, sg: &'a str) -> &'a str { match rank(sg) { Some(r) if r < rank(d).unwrap() => sg, _ => d } }
fn walk(c: &V, out: &mut BTreeSet<String>) {
    match s(&c["k"]) {
        "and" | "or" => { walk(&c["a"], out); walk(&c["b"], out) }
        "not" => walk(&c["c"], out),
        "cmp" => for k in ["l", "r"] { let t = &c[k]; if s(&t["k"]) == "param" && ["env.class.", "env.prov.", "env.judge.", "env.world."].iter().any(|p| s(&t["path"]).starts_with(p)) { out.insert(s(&t["path"]).to_string()); } },
        _ => {}
    }
}
fn run_fn(v: &V) -> V {
    let inp = &v["input"];
    match s(&v["fn"]) {
        "canon" => serde_json::json!({"canon": canon(inp), "digest": goal_digest(inp)}),
        "units" => { let sc = &inp["schema"]; let mut ks: Vec<&String> = inp["terms"].as_object().unwrap().keys().filter(|k| sc.get(k.as_str()).map_or(true, |x| canon(x) != canon(&inp["terms"][k.as_str()]))).collect(); ks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes())); serde_json::json!(ks) }
        "polarity" => { let mut o = BTreeSet::new(); arr(inp).iter().for_each(|w| walk(w, &mut o)); serde_json::json!(o) }
        "meet" => serde_json::json!(meet(s(&inp["decision"]), s(&inp["signal"]))),
        "pep" => serde_json::json!(match s(&inp["decision"]) { "allow" => true, "deny" => false, _ => { let a = &inp["answer"]; !a.is_null() && a["valid"] == true && ["policy_digest", "action_digest", "history_head"].iter().all(|k| a[*k] == inp["ctx"][*k]) } }),
        "commit" => serde_json::json!({"commit": b64(&format!("pca-goal:v3:commit:{}:{}:{}", s(&inp["goal_digest"]), s(&inp["policy_digest"]), s(&inp["salt"]))), "opens_other_goal": false}),
        "claim" => serde_json::json!(if !inp["replayed_ppm"].is_null() && i(&inp["replayed_ppm"]) < i(&inp["min_ppm"]) { meet(s(&inp["base"]), "escalate") } else { s(&inp["base"]) }),
        f => panic!("unknown fn {f}"),
    }
}
fn main() {
    let dir = std::env::args().nth(1).expect("vectors dir");
    let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).filter(|n| n.ends_with(".json") && n != "index.json").collect();
    names.sort();
    let (mut bad, mut probes) = (vec![], 0);
    for n in &names {
        let v: V = serde_json::from_str(&fs::read_to_string(format!("{dir}/{n}")).unwrap()).unwrap();
        if s(&v["kind"]) == "fn" { if canon(&run_fn(&v)) != canon(&v["expect"]) { bad.push(s(&v["id"]).to_string()); } continue; }
        if goal_digest(&v["goal"]) != s(&v["goal_digest"]) { bad.push(format!("{}:goal_digest", s(&v["id"]))); }
        if v["compile"]["ok"] != true { continue; }
        if b64(&canon(&lower(&v["ontology"], &v["goal"]))) != s(&v["policy_digest"]) { bad.push(format!("{}:policy_digest", s(&v["id"]))); }
        for (k, p) in arr(&v["probes"]).iter().enumerate() {
            probes += 1;
            if canon(&decide(&v["goal"], &v["ontology"], &p["action"], &p["history"])) != canon(&p["expect"]) { bad.push(format!("{}#{}", s(&v["id"]), k)); }
        }
    }
    println!("rust: {} vectors, {} probes, {} disagreements", names.len(), probes, bad.len());
    bad.iter().take(20).for_each(|b| println!("   {b}"));
    if !bad.is_empty() || names.is_empty() { std::process::exit(1); }
}
