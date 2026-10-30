//! pca-wasmtime-host <component.wasm|.wat> <fuel>
//!
//! Runs a WebAssembly component through wasmtime's canonical ABI. The only import it defines is the `pca:act/invoke@0.1.0`
//! interface (see wit/pca-act.wit); a component that imports anything else is refused before it is instantiated, so it has no
//! filesystem, network, clock, random or environment access. Execution is metered: every instruction costs fuel and the run
//! traps when the budget is spent.
//!
//! The handle table lives in the parent process. The host speaks JSON lines on stdin/stdout:
//!   host -> parent  {"op":"count"} | {"op":"verb","h":N} | {"op":"invoke","h":N}
//!   parent -> host  {"n":N} | {"ok":"<string>"} or {"err":CODE} | {"ok":[bytes]} or {"err":CODE}
//!   host -> parent (last line)  {"done":RUN_RESULT,"fuel_used":N} | {"fail":"<reason>"}
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, Trap};

const IFACE: &str = "pca:act/invoke@0.1.0";

fn ask(req: Value) -> Value {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{req}");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    serde_json::from_str(&line).unwrap_or(Value::Null)
}

fn run(path: &str, fuel: u64) -> Value {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    let Ok(engine) = Engine::new(&cfg) else { return json!({"fail": "engine"}) };
    let Ok(bytes) = std::fs::read(path) else { return json!({"fail": "unreadable"}) };
    let Ok(component) = Component::new(&engine, &bytes) else { return json!({"fail": "malformed_component"}) };
    for (name, _) in component.component_type().imports(&engine) {
        if name != IFACE {
            return json!({"fail": format!("ambient_import:{name}")});
        }
    }
    let mut linker: Linker<()> = Linker::new(&engine);
    let Ok(mut inst) = linker.instance(IFACE) else { return json!({"fail": "linker"}) };
    let ok = inst
        .func_wrap("handle-count", |_cx, (): ()| Ok((ask(json!({"op": "count"}))["n"].as_u64().unwrap_or(0) as u32,)))
        .and_then(|_| {
            inst.func_wrap("handle-verb", |_cx, (h,): (u32,)| {
                let r = ask(json!({"op": "verb", "h": h}));
                Ok((match r.get("ok").and_then(Value::as_str) {
                    Some(s) => Ok::<String, i32>(s.to_string()),
                    None => Err(r["err"].as_i64().unwrap_or(-5) as i32),
                },))
            })
        })
        .and_then(|_| {
            inst.func_wrap("invoke", |_cx, (h,): (u32,)| {
                let r = ask(json!({"op": "invoke", "h": h}));
                Ok((match r.get("ok").and_then(Value::as_array) {
                    Some(a) => Ok::<Vec<u8>, i32>(a.iter().map(|x| x.as_u64().unwrap_or(0) as u8).collect()),
                    None => Err(r["err"].as_i64().unwrap_or(-5) as i32),
                },))
            })
        });
    if ok.is_err() {
        return json!({"fail": "linker"});
    }
    let mut store = Store::new(&engine, ());
    if store.set_fuel(fuel).is_err() {
        return json!({"fail": "fuel"});
    }
    let classify = |e: wasmtime::Error| -> Value {
        if matches!(e.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
            json!({"fail": "fuel_exhausted"})
        } else {
            json!({"fail": "trap"})
        }
    };
    let instance = match linker.instantiate(&mut store, &component) {
        Ok(i) => i,
        Err(e) => return classify(e),
    };
    let Ok(f) = instance.get_typed_func::<(), (i32,)>(&mut store, "run") else { return json!({"fail": "no_entry"}) };
    match f.call(&mut store, ()) {
        Ok((v,)) => {
            let _ = f.post_return(&mut store);
            let used = fuel - store.get_fuel().unwrap_or(0);
            json!({"done": v, "fuel_used": used})
        }
        Err(e) => classify(e),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let out = match (a.get(1), a.get(2).and_then(|f| f.parse::<u64>().ok())) {
        (Some(p), Some(f)) => run(p, f),
        _ => json!({"fail": "usage"}),
    };
    println!("{out}");
}
