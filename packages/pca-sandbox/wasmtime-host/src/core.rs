//! Core-module mode: `pca-wasmtime-host core <module.wasm> <fuel> <max_pages> <timeout_ms> [entry]`.
//!
//! The same contract as the TypeScript core-module host (`createSandbox`): the module may import only `pca:act.{invoke,
//! handle_count,handle_verb}`, declares at most one memory with a maximum within `max_pages`, and runs under an instruction
//! budget (fuel), a wall-clock deadline (epoch interruption) and a hard memory cap. The handle table lives in the parent; the
//! JSON-lines protocol is the component mode's (`count` / `verb` / `invoke`), and the last line is `{"done":N,"fuel_used":N}`
//! or `{"fail":"<reason>"}`. Reasons: bad_fuel, bad_limits, unreadable, module_size, malformed_module, memory_limits,
//! ambient_import:<module>.<name>, no_entry, fuel_exhausted, timeout, trap:RuntimeError, trap:LinkError.
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use wasmtime::{Caller, Config, Engine, ExternType, Linker, Module, ResourceLimiter, Store, Trap, Val};

const IMPORT_MODULE: &str = "pca:act";
const ALLOWED: [&str; 3] = ["invoke", "handle_count", "handle_verb"];
const MAX_MODULE_BYTES: usize = 1 << 20;
const MAX_RESULT_BYTES: usize = 1 << 20;
const E_UNKNOWN: i32 = -1;
const E_TOO_SMALL: i32 = -3;
const E_BAD_MEMORY: i32 = -4;

fn ask(req: Value) -> Value {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{req}");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    serde_json::from_str(&line).unwrap_or(Value::Null)
}

struct Limits {
    max_bytes: usize,
    refused: bool,
}

impl ResourceLimiter for Limits {
    fn memory_growing(&mut self, _current: usize, desired: usize, maximum: Option<usize>) -> wasmtime::Result<bool> {
        // like the reference (a JS WebAssembly.Memory): a grow past the cap or the declared maximum is a quiet -1, not a trap.
        // The static checks (declared maximum within the cap) refuse everything else before a single instruction runs.
        Ok(maximum.is_some() && desired <= self.max_bytes)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= 100_000)
    }
}

/// Parse only the memory section like the reference: Err = unparseable; Ok(None) = no memory; Ok(Some((count, min, max, shared))).
fn memory_limits(b: &[u8]) -> Result<Option<(u64, u64, Option<u64>, bool)>, ()> {
    if b.len() < 8 || b[0] != 0 || b[1] != 0x61 || b[2] != 0x73 || b[3] != 0x6d {
        return Err(());
    }
    let mut o = 8usize;
    fn leb(b: &[u8], o: &mut usize) -> Result<u64, ()> {
        let mut r: u64 = 0;
        for shift in (0..35).step_by(7) {
            let x = *b.get(*o).ok_or(())?;
            *o += 1;
            r += ((x & 0x7f) as u64) << shift;
            if x & 0x80 == 0 {
                return Ok(r);
            }
        }
        Err(())
    }
    while o < b.len() {
        let id = b[o];
        o += 1;
        let size = leb(b, &mut o)? as usize;
        let end = o.checked_add(size).ok_or(())?;
        if end > b.len() {
            return Err(());
        }
        if id == 5 {
            let count = leb(b, &mut o)?;
            if count == 0 {
                return Ok(None);
            }
            let flag = *b.get(o).ok_or(())?;
            o += 1;
            if flag > 3 {
                return Ok(Some((count, u64::MAX, None, true))); // memory64 and anything newer: refused
            }
            let min = leb(b, &mut o)?;
            let max = if flag & 1 != 0 { Some(leb(b, &mut o)?) } else { None };
            return Ok(Some((count, min, max, flag & 2 != 0)));
        }
        o = end;
    }
    Ok(None)
}

fn view(caller: &mut Caller<'_, Limits>, ptr: i32, len: i32) -> Option<(wasmtime::Memory, usize, usize)> {
    let mem = caller.get_export("memory")?.into_memory()?;
    let (p, l) = (ptr as u32 as usize, len as u32 as usize);
    (p.checked_add(l)? <= mem.data_size(&*caller)).then_some((mem, p, l))
}

fn classify(e: wasmtime::Error, lim: &Limits, instantiating: bool) -> Value {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => json!({"fail": "fuel_exhausted"}),
        Some(Trap::Interrupt) => json!({"fail": "timeout"}),
        _ if lim.refused => json!({"fail": "memory_limits"}),
        Some(_) => json!({"fail": "trap:RuntimeError"}),
        None if instantiating => json!({"fail": "trap:LinkError"}),
        None => json!({"fail": "trap:RuntimeError"}),
    }
}

pub fn run(path: &str, fuel: u64, max_pages: u64, timeout_ms: u64, entry: &str) -> Value {
    if fuel < 1 {
        return json!({"fail": "bad_fuel"});
    }
    if max_pages < 1 || max_pages > 65536 || timeout_ms < 1 {
        return json!({"fail": "bad_limits"});
    }
    let Ok(bytes) = std::fs::read(path) else { return json!({"fail": "unreadable"}) };
    if bytes.is_empty() || bytes.len() > MAX_MODULE_BYTES {
        return json!({"fail": "module_size"});
    }
    match memory_limits(&bytes) {
        Err(()) => return json!({"fail": "malformed_module"}),
        Ok(Some((count, min, max, shared))) => {
            if count > 1 || shared || max.is_none() || min > max_pages || max.unwrap_or(u64::MAX) > max_pages {
                return json!({"fail": "memory_limits"});
            }
        }
        Ok(None) => {}
    }
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.wasm_multi_memory(false);
    cfg.wasm_memory64(false);
    cfg.wasm_threads(false);
    cfg.wasm_component_model(false);
    let Ok(engine) = Engine::new(&cfg) else { return json!({"fail": "engine"}) };
    let Ok(module) = Module::new(&engine, &bytes) else { return json!({"fail": "malformed_module"}) };
    for i in module.imports() {
        if i.module() != IMPORT_MODULE || !matches!(i.ty(), ExternType::Func(_)) || !ALLOWED.contains(&i.name()) {
            return json!({"fail": format!("ambient_import:{}.{}", i.module(), i.name())});
        }
    }
    let mut linker: Linker<Limits> = Linker::new(&engine);
    let wired = linker
        .func_wrap(IMPORT_MODULE, "handle_count", |_c: Caller<'_, Limits>| -> i32 { ask(json!({"op": "count"}))["n"].as_i64().unwrap_or(0) as i32 })
        .and_then(|l| {
            l.func_wrap(IMPORT_MODULE, "handle_verb", |mut c: Caller<'_, Limits>, h: i32, ptr: i32, cap: i32| -> i32 {
                let r = ask(json!({"op": "verb", "h": h}));
                let Some(verb) = r.get("ok").and_then(Value::as_str) else { return r["err"].as_i64().unwrap_or(E_UNKNOWN as i64) as i32 };
                let Some((mem, p, l)) = view(&mut c, ptr, cap) else { return E_BAD_MEMORY };
                let enc = verb.as_bytes();
                if enc.len() > l {
                    return E_TOO_SMALL;
                }
                mem.data_mut(&mut c)[p..p + enc.len()].copy_from_slice(enc);
                enc.len() as i32
            })
        })
        .and_then(|l| {
            l.func_wrap(IMPORT_MODULE, "invoke", |mut c: Caller<'_, Limits>, h: i32, ptr: i32, cap: i32| -> i32 {
                // validate the guest's output window before spending the use
                let Some((mem, p, l)) = view(&mut c, ptr, cap) else { return E_BAD_MEMORY };
                let r = ask(json!({"op": "invoke", "h": h}));
                let Some(a) = r.get("ok").and_then(Value::as_array) else { return r["err"].as_i64().unwrap_or(-5) as i32 };
                if a.len() > MAX_RESULT_BYTES || a.len() > l {
                    return E_TOO_SMALL;
                }
                let out = &mut mem.data_mut(&mut c)[p..p + a.len()];
                for (d, x) in out.iter_mut().zip(a) {
                    *d = x.as_u64().unwrap_or(0) as u8;
                }
                a.len() as i32
            })
        });
    if wired.is_err() {
        return json!({"fail": "linker"});
    }
    let mut store = Store::new(&engine, Limits { max_bytes: (max_pages as usize) * 65536, refused: false });
    store.limiter(|s| s);
    if store.set_fuel(fuel).is_err() {
        return json!({"fail": "fuel"});
    }
    store.set_epoch_deadline(1);
    let ticker = engine.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms));
        ticker.increment_epoch();
    });
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => return classify(e, store.data(), true),
    };
    let Some(f) = instance.get_func(&mut store, entry) else { return json!({"fail": "no_entry"}) };
    let ty = f.ty(&store);
    if ty.params().len() != 0 {
        return json!({"fail": "no_entry"});
    }
    let mut results = vec![Val::I32(0); ty.results().len()];
    match f.call(&mut store, &[], &mut results) {
        Ok(()) => {
            let v = match results.first() {
                Some(Val::I32(v)) => *v as i64,
                _ => 0,
            };
            json!({"done": v, "fuel_used": fuel - store.get_fuel().unwrap_or(0)})
        }
        Err(e) => classify(e, store.data(), false),
    }
}
