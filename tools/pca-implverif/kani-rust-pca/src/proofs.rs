//! Kani proofs over the REAL atlas-pca code (copied byte-for-byte; see ../build.sh).
//! Every harness states its scope. "FULL" = the entire input range the verifier can reach (not an unwinding cap).
use super::*;

const MAXS: u64 = MAX_SAFE as u64;

// `format!` is only used to build human-readable reasons/errors. Its CBMC encoding (Display for f64/u128) is what exhausted memory in the
// first runs. The stub returns a fixed NON-EMPTY string: every `format!` template in lib.rs has a non-empty literal part, so this is
// faithful for every property asserted below (none inspects message text beyond non-emptiness).
fn stub_fmt_nonempty(_a: core::fmt::Arguments<'_>) -> String { String::from("<fmt>") }

// ---- split(): RFC 6962 split point. FULL range: n is a safe integer (verify_inclusion bounds size by safe_int) ----
#[kani::proof]
#[kani::unwind(58)]
fn split_full_range() {
    let n: u64 = kani::any();
    kani::assume(n >= 2 && n <= MAXS);
    let k = split(n);
    assert!(k.is_power_of_two());
    assert!(k < n && n <= 2 * k);
}

// ---- path_shape(): FULL range index < size <= 2^53-1, no panic / underflow, depth bound ----
#[kani::proof]
#[kani::unwind(58)]
fn path_shape_full_range() {
    let size: u64 = kani::any();
    let index: u64 = kani::any();
    kani::assume(size >= 1 && size <= MAXS && index < size);
    let s = path_shape(index, size);
    assert!(s.len() <= 53);
    assert!(s.iter().all(|c| *c == b'L' || *c == b'R'));
    if size == 1 {
        assert!(s.is_empty());
    }
}

// ---- safe_int / number_error on every integer-backed JSON number (i64 and u64 FULL range) ----
#[kani::proof]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
fn safe_int_i64_full_range() {
    let i: i64 = kani::any();
    let v = Value::Number(Number::from(i));
    let r = safe_int(&v);
    if i.unsigned_abs() <= MAXS {
        assert_eq!(r, Some(i));
    } else {
        assert_eq!(r, None);
    }
}

#[kani::proof]
fn safe_int_u64_full_range() {
    let u: u64 = kani::any();
    let v = Value::Number(Number::from(u));
    let r = safe_int(&v);
    if u <= MAXS {
        assert_eq!(r, Some(u as i64));
    } else {
        assert_eq!(r, None);
    }
}

// ---- decode_b64u_strict: public API with `len: Option<usize>`; the `n * 4` is UNCHECKED arithmetic ----
// Every in-tree caller passes a small constant; this harness asks whether the public function can panic for ANY n.
#[kani::proof]
#[kani::unwind(6)]
fn decode_b64u_len_arith_any_n() {
    let n: usize = kani::any();
    // exact expression from decode_b64u_strict
    let _ = (n * 4).div_ceil(3);
}

// Same expression, restricted to the domain where `n * 4` cannot overflow: UNBOUNDED proof that the arithmetic is total there.
// (decode_b64u_len_arith_any_n above is EXPECTED TO FAIL: it documents that the unchecked `n * 4` overflows for n > usize::MAX/4.)
#[kani::proof]
fn decode_b64u_len_arith_guarded() {
    let n: usize = kani::any();
    kani::assume(n <= usize::MAX / 4);
    let m = (n * 4).div_ceil(3);
    assert!(m >= n); // 4n/3 >= n
}

// The REAL public function with a symbolic `len`. Expected to FAIL for n > usize::MAX/4 in a checked-arithmetic build
// (panic: attempt to multiply with overflow). No in-tree caller passes an untrusted n; in a release build the product wraps and the
// later `bytes.len() != n` check still rejects, so the failure is a debug-build panic on a caller-controlled argument only.
#[kani::proof]
#[kani::unwind(3)]
fn decode_b64u_real_fn_any_n() {
    let n: usize = kani::any();
    let _ = decode_b64u_strict("", Some(n));
}

// bounded-4 variant: the bounded-6 harness exhausts 24 GB inside the base64 crate. 4 bytes covers every length class mod 4
// (0, 2, 3; 1 is rejected before decoding) and one full quantum. The unbounded algorithmic statement is verus/b64u_strict.rs.
#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
fn decode_b64u_no_panic_bounded4() {
    let raw: [u8; 4] = kani::any();
    let l: usize = kani::any();
    kani::assume(l <= 4);
    kani::assume(raw[..l].iter().all(|b| *b < 128));
    let s = unsafe { std::str::from_utf8_unchecked(&raw[..l]) };
    if let Some(b) = decode_b64u_strict(s, None) {
        assert_eq!(b64_encode(&b), s);
    }
}

// ---- decode_b64u_strict on all strings up to 6 bytes (bounded: base64 crate is opaque-heavy) ----
#[kani::proof]
#[kani::unwind(10)]
fn decode_b64u_no_panic_bounded() {
    let raw: [u8; 6] = kani::any();
    let l: usize = kani::any();
    kani::assume(l <= 6);
    let s = match std::str::from_utf8(&raw[..l]) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Some(b) = decode_b64u_strict(s, None) {
        assert_eq!(b64_encode(&b), s); // canonical: re-encoding reproduces the input
    }
}

// =====================================================================================================
// Decision procedure: verify_pcactn_core_policy with the cryptographic / structural leaves STUBBED by
// nondeterministic oracles (assume-guarantee). What this proves is the AGGREGATION logic of the real function
// (check set, order-independence of allow, time comparisons, grant_ref binding, chain-length cap, counter, reason),
// for every nondeterministic oracle outcome. It does NOT prove the oracles (wire validation, Merkle, signatures,
// chain verification), which are covered by the other harnesses, Verus/Lean models and the conformance corpus.
// =====================================================================================================
static mut G_CHAIN_OK: bool = false;
static mut G_INCL_OK: bool = false;
static mut G_SIG_OK: bool = false;
static mut G_CHAIN_CALLED: bool = false;

fn stub_validate_wire(_p: &Value) -> Result<(), String> { Ok(()) }
fn stub_cap_hash(_c: &Value) -> String { if kani::any() { "h1".to_string() } else { "h2".to_string() } }
fn stub_verify_chain_policy(_c: &[Value], _r: Option<&str>, _a: Option<&[String]>, _pins: Option<&std::collections::HashMap<String, String>>, _t: Option<&Value>) -> Result<(), String> {
    let ok: bool = kani::any();
    unsafe { G_CHAIN_OK = ok; G_CHAIN_CALLED = true; }
    if ok { Ok(()) } else { Err("chain".to_string()) }
}
fn stub_plan_leaf(_n: Option<&Value>, _a: Option<&Map<String, Value>>, _c: &str) -> Option<Value> {
    if kani::any() { Some(Value::Null) } else { None }
}
fn stub_verify_inclusion(_r: &str, _p: Option<&Map<String, Value>>, _l: &Value) -> bool {
    let ok: bool = kani::any(); unsafe { G_INCL_OK = ok; } ok
}
fn stub_suite_allowed(_a: Option<&Value>, _al: Option<&[String]>) -> bool { kani::any() }
fn stub_pq_binding_ok(_a: Option<&Value>, _p: Option<&Value>, _c: Option<&Value>) -> bool { kani::any() }
fn stub_threshold_message(_p: &Map<String, Value>) -> Result<Vec<u8>, String> { if kani::any() { Ok(Vec::new()) } else { Err("m".to_string()) } }
fn stub_verify_suite(_a: Option<&Value>, _h: &str, _pq: Option<&pinned::PinnedPq>, _m: &[u8], _s: Option<&Value>, _ps: Option<&Value>) -> bool {
    let ok: bool = kani::any(); unsafe { G_SIG_OK = ok; } ok
}

const CHECKS: [&str; 9] = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"];

fn decision_aggregation_body(lens: &[usize], concrete_ints: bool) {
    unsafe { G_CHAIN_OK = false; G_INCL_OK = false; G_SIG_OK = false; G_CHAIN_CALLED = false; }
    // ---- inputs: every integer field is ANY i64 (safe_int() inside the code filters to the safe range) ----
    let (ver, iat, exp, counter, now): (i64, i64, i64, i64, i64) =
        if concrete_ints { (PCACTN_WIRE_VERSION, 1_000, 2_000, 0, 1_500) } else { (kani::any(), kani::any(), kani::any(), kani::any(), kani::any()) };
    let aud_match: bool = kani::any();
    let gref_sel: u8 = kani::any(); kani::assume(gref_sel < 3);   // "" | "r" | "q"
    let root_sel: u8 = kani::any(); kani::assume(root_sel < 3);   // id "r" | "q" | absent
    let chain_len_sel: usize = kani::any(); kani::assume(chain_len_sel < lens.len());
    let n = lens[chain_len_sel];

    let mut cap = Map::new();
    match root_sel { 0 => { cap.insert("id".to_string(), Value::String("r".to_string())); }
                     1 => { cap.insert("id".to_string(), Value::String("q".to_string())); } _ => {} }
    let mut p = Map::new();
    p.insert("ver".to_string(), Value::Number(Number::from(ver)));
    p.insert("aud".to_string(), Value::String(if aud_match { "A".to_string() } else { "B".to_string() }));
    p.insert("iat".to_string(), Value::Number(Number::from(iat)));
    p.insert("exp".to_string(), Value::Number(Number::from(exp)));
    p.insert("counter".to_string(), Value::Number(Number::from(counter)));
    p.insert("grant_ref".to_string(), Value::String(["", "r", "q"][gref_sel as usize].to_string()));
    p.insert("cap_chain".to_string(), Value::Array((0..n).map(|_| Value::Object(cap.clone())).collect()));
    let pc = Value::Object(p);
    let grant = Value::Object(Map::new());

    let v = verify_pcactn_core_policy(&pc, &grant, now, "A", None);

    // (A) allow => the verdict carries EXACTLY the 9 named checks and every one is true
    if v.allow {
        assert_eq!(v.checks.len(), 9);
        for c in CHECKS { assert_eq!(v.checks.get(c), Some(&true)); }
    }
    // (B) allow <=> every recorded check is true (no other path to Allow)
    assert_eq!(v.allow, v.checks.values().all(|x| *x));
    // (C) deny => a human-readable reason
    if !v.allow { assert!(!v.reason.is_empty()); }
    // (D) the individual checks' exact meaning (safe-int domain: |x| <= 2^53-1)
    let safe = |x: i64| x.unsigned_abs() <= MAXS;
    let (siat, sexp) = (if safe(iat) { iat } else { 0 }, if safe(exp) { exp } else { 0 });
    let validity_expected = sexp > siat && sexp - siat <= MAX_LIFETIME_MS && siat <= now.saturating_add(MAX_SKEW_MS) && now <= sexp;
    assert_eq!(v.checks.get("validity"), Some(&validity_expected));
    assert_eq!(v.checks.get("version"), Some(&(safe(ver) && ver == PCACTN_WIRE_VERSION)));
    assert_eq!(v.checks.get("audience"), Some(&aud_match));
    assert_eq!(v.checks.get("counter"), Some(&(safe(counter) && counter >= 0)));
    let gref_ok = gref_sel != 0 && root_sel < 2 && n >= 1 && ((gref_sel == 1 && root_sel == 0) || (gref_sel == 2 && root_sel == 1));
    assert_eq!(v.checks.get("grant_ref_bound"), Some(&gref_ok));
    // (E) the 16-hop cap and non-empty chain are enforced; the chain verifier is only consulted within them
    if v.checks.get("chain") == Some(&true) {
        assert!(n >= 1 && n <= MAX_CHAIN_DEPTH);
        unsafe { assert!(G_CHAIN_CALLED && G_CHAIN_OK); }
    }
    // (F) allow => each oracle returned success
    if v.allow { unsafe { assert!(G_CHAIN_OK && G_INCL_OK && G_SIG_OK); } }
}

#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(verify_chain_policy, stub_verify_chain_policy)]
#[kani::stub(plan_leaf, stub_plan_leaf)]
#[kani::stub(verify_inclusion, stub_verify_inclusion)]
#[kani::stub(suite_allowed, stub_suite_allowed)]
#[kani::stub(pq_binding_ok, stub_pq_binding_ok)]
#[kani::stub(threshold_message, stub_threshold_message)]
#[kani::stub(verify_suite, stub_verify_suite)]
fn decision_aggregation() { decision_aggregation_body(&[0, 1, 16, 17], false); }

// Split of decision_aggregation (the combined harness exhausted 24 GB): (I) every integer field ANY i64, chain length 0 or 1;
// (C) the chain-length cap boundary (16 / 17 hops) with fixed in-range integers. Together they cover the combined statement:
// no asserted property couples the integer fields to the chain length except through the oracles, which are nondeterministic.
#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(verify_chain_policy, stub_verify_chain_policy)]
#[kani::stub(plan_leaf, stub_plan_leaf)]
#[kani::stub(verify_inclusion, stub_verify_inclusion)]
#[kani::stub(suite_allowed, stub_suite_allowed)]
#[kani::stub(pq_binding_ok, stub_pq_binding_ok)]
#[kani::stub(threshold_message, stub_threshold_message)]
#[kani::stub(verify_suite, stub_verify_suite)]
fn decision_aggregation_ints() { decision_aggregation_body(&[0, 1], false); }

#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(verify_chain_policy, stub_verify_chain_policy)]
#[kani::stub(plan_leaf, stub_plan_leaf)]
#[kani::stub(verify_inclusion, stub_verify_inclusion)]
#[kani::stub(suite_allowed, stub_suite_allowed)]
#[kani::stub(pq_binding_ok, stub_pq_binding_ok)]
#[kani::stub(threshold_message, stub_threshold_message)]
#[kani::stub(verify_suite, stub_verify_suite)]
fn decision_aggregation_chain_cap() { decision_aggregation_body(&[0, 1, 16, 17], true); }

// =====================================================================================================================
// COMPOSITIONAL decision proof (closes decision_aggregation, which ran out of memory building serde_json maps).
//
// Layer 1 (`decision_logic_abstract`): the REAL `verify_pcactn_core_policy` with the JSON layer abstracted. Every serde_json
//   map is an EMPTY `Map` (no BTreeMap nodes); `serde_json::Map::get` is stubbed by `stub_map_get`, which answers from an
//   abstract store keyed by (map address, key). Contract of the stub (CONTRACT-GET): `m.get(k)` returns the value stored
//   under k in m, or None. `Value::get(&str)` reaches it through serde_json's `Index for str` (Object(m) => m.get(k)), so
//   the real accessors (`as_object`, `as_array`, `as_str`, `safe_int`, `Value::get`) run unmodified on top of it. Inputs:
//   every integer field ANY i64 or ANY u64 or a string or absent; aud / grant_ref / root id over their discriminating
//   classes; cap_chain absent, not an array, or an array of ANY length n < 2^32 (a real Vec of symbolic length: only
//   chain[0] and chain[n-1] are initialised, which is exactly what the non-stubbed code reads). Leaves are nondeterministic
//   oracles whose outcomes are recorded, so the exact meaning of each of the nine checks is asserted against them.
// Layer 2 (`json_abs_*`): CONTRACT-GET holds for the real serde_json Map / Value::get, for bounded maps (see each harness).
// =====================================================================================================================
mod compositional {
    use super::super::*;
    use core::borrow::Borrow;
    use core::hash::Hash;
    use super::stub_fmt_nonempty;

    const MAXS: u64 = super::MAXS;

    // ---------------- abstract store behind the stubbed Map::get ----------------
    static mut REG: Vec<(usize, String, &'static Value)> = Vec::new();
    fn reg_ref(m: &Map<String, Value>, k: &str, v: &'static Value) {
        unsafe { (*core::ptr::addr_of_mut!(REG)).push((m as *const _ as usize, k.to_string(), v)) }
    }
    fn reg(m: &Map<String, Value>, k: &str, v: Value) { reg_ref(m, k, Box::leak(Box::new(v))) }
    pub fn stub_map_get<'a, Q>(m: &'a Map<String, Value>, key: &Q) -> Option<&'a Value>
    where
        String: Borrow<Q>,
        Q: ?Sized + Ord + Eq + Hash,
    {
        let id = m as *const _ as usize;
        let r = unsafe { &*core::ptr::addr_of!(REG) };
        for (mid, k, v) in r.iter() {
            if *mid == id && <String as Borrow<Q>>::borrow(k) == key {
                return Some(*v);
            }
        }
        None
    }

    // ---------------- recorded oracles ----------------
    static mut WIRE: Option<bool> = None;
    static mut CAV: Option<bool> = None;
    static mut SAME: Option<bool> = None;
    static mut CHAIN: Option<bool> = None;
    static mut LEAF: Option<bool> = None;
    static mut INCL: Option<bool> = None;
    static mut SUITE: Option<bool> = None;
    static mut PQB: Option<bool> = None;
    static mut TM: Option<bool> = None;
    static mut SIG: Option<bool> = None;
    fn rec(g: *mut Option<bool>) -> bool {
        let b: bool = kani::any();
        unsafe { assert!((*g).is_none(), "oracle consulted twice"); *g = Some(b); }
        b
    }
    fn got(g: *const Option<bool>) -> Option<bool> { unsafe { *g } }

    pub fn s_validate_wire(_p: &Value) -> Result<(), String> { if rec(core::ptr::addr_of_mut!(WIRE)) { Ok(()) } else { Err("w".into()) } }
    pub fn s_caveat_limit_exceeded(_c: &[Value]) -> bool { rec(core::ptr::addr_of_mut!(CAV)) }
    pub fn s_same_strict_hash(_a: &Value, _b: &Value) -> bool { rec(core::ptr::addr_of_mut!(SAME)) }
    pub fn s_verify_chain_policy(_c: &[Value], _r: Option<&str>, _a: Option<&[String]>, _pins: Option<&std::collections::HashMap<String, String>>, _t: Option<&Value>) -> Result<(), String> {
        if rec(core::ptr::addr_of_mut!(CHAIN)) { Ok(()) } else { Err("chain".into()) }
    }
    pub fn s_conditions_digest_default() -> String { String::from("cd") }
    pub fn s_plan_leaf(_n: Option<&Value>, _a: Option<&Map<String, Value>>, _c: &str) -> Option<Value> {
        if rec(core::ptr::addr_of_mut!(LEAF)) { Some(Value::Null) } else { None }
    }
    pub fn s_verify_inclusion(_r: &str, _p: Option<&Map<String, Value>>, _l: &Value) -> bool { rec(core::ptr::addr_of_mut!(INCL)) }
    pub fn s_suite_allowed(_a: Option<&Value>, _al: Option<&[String]>) -> bool { rec(core::ptr::addr_of_mut!(SUITE)) }
    pub fn s_pq_binding_ok(_a: Option<&Value>, _p: Option<&Value>, _c: Option<&Value>) -> bool { rec(core::ptr::addr_of_mut!(PQB)) }
    pub fn s_threshold_message(_p: &Map<String, Value>) -> Result<Vec<u8>, String> {
        if rec(core::ptr::addr_of_mut!(TM)) { Ok(Vec::new()) } else { Err("m".into()) }
    }
    pub fn s_verify_suite(_a: Option<&Value>, _h: &str, _pq: Option<&pinned::PinnedPq>, _m: &[u8], _s: Option<&Value>, _ps: Option<&Value>) -> bool {
        rec(core::ptr::addr_of_mut!(SIG))
    }

    // ---------------- abstract inputs ----------------
    #[derive(Clone, Copy)]
    enum Num { Absent, I(i64), U(u64), Str }
    fn any_num() -> Num {
        match kani::any_where(|t: &u8| *t < 4) { 0 => Num::Absent, 1 => Num::I(kani::any()), 2 => Num::U(kani::any()), _ => Num::Str }
    }
    fn num_value(n: Num) -> Option<Value> {
        match n { Num::Absent => None, Num::I(i) => Some(Value::Number(Number::from(i))), Num::U(u) => Some(Value::Number(Number::from(u))), Num::Str => Some(Value::String("2".into())) }
    }
    /// the abstract meaning of `safe_int` on an integer-backed number (proved for the real function: safe_int_*_full_range)
    fn num_safe(n: Num) -> Option<i64> {
        match n { Num::I(i) if i.unsigned_abs() <= MAXS => Some(i), Num::U(u) if u <= MAXS => Some(u as i64), _ => None }
    }
    // a string-or-number field over its discriminating classes: 0 absent, 1 "" , 2 "r", 3 "q", 4 number
    fn sel_value(s: u8) -> Option<Value> {
        match s { 0 => None, 1 => Some(Value::String(String::new())), 2 => Some(Value::String("r".into())), 3 => Some(Value::String("q".into())), _ => Some(Value::Number(Number::from(7u64))) }
    }

    #[kani::proof]
    #[kani::unwind(20)]
    #[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
    #[kani::stub(serde_json::map::Map::get, stub_map_get)]
    #[kani::stub(validate_wire, s_validate_wire)]
    #[kani::stub(caveat_limit_exceeded, s_caveat_limit_exceeded)]
    #[kani::stub(same_strict_hash, s_same_strict_hash)]
    #[kani::stub(verify_chain_policy, s_verify_chain_policy)]
    #[kani::stub(conditions_digest_default, s_conditions_digest_default)]
    #[kani::stub(plan_leaf, s_plan_leaf)]
    #[kani::stub(verify_inclusion, s_verify_inclusion)]
    #[kani::stub(suite_allowed, s_suite_allowed)]
    #[kani::stub(pq_binding_ok, s_pq_binding_ok)]
    #[kani::stub(threshold_message, s_threshold_message)]
    #[kani::stub(verify_suite, s_verify_suite)]
    fn decision_logic_abstract() {
        // ---- abstract input ----
        let (ver, iat, exp, counter) = (any_num(), any_num(), any_num(), any_num());
        let now: i64 = kani::any();
        let aud_sel: u8 = kani::any_where(|t: &u8| *t < 4); // 0 absent, 1 "A" (match), 2 "B", 3 number
        let gref_sel: u8 = kani::any_where(|t: &u8| *t < 5);
        let id_sel: u8 = kani::any_where(|t: &u8| *t < 5); // root id (when the root is an object)
        let root_is_obj: bool = kani::any();
        let chain_kind: u8 = kani::any_where(|t: &u8| *t < 3); // 0 absent, 1 not an array, 2 array
        let n: usize = if chain_kind == 2 { kani::any_where(|x: &usize| *x < (1usize << 32)) } else { 0 };
        let pc_is_obj: bool = kani::any();

        // ---- concretisation: empty maps + abstract store ----
        let mut chain: Vec<Value> = Vec::with_capacity(n);
        unsafe {
            if n >= 1 {
                chain.as_mut_ptr().write(if root_is_obj { Value::Object(Map::new()) } else { Value::Null });
                if n >= 2 { chain.as_mut_ptr().add(n - 1).write(Value::Object(Map::new())); }
            }
            chain.set_len(n);
        }
        let chain_v: &'static Value = Box::leak(Box::new(Value::Array(chain)));
        if let Some(Value::Object(m0)) = chain_v.as_array().unwrap().first() {
            if let Some(v) = sel_value(id_sel) { reg(m0, "id", v); }
        }
        let pc: &'static Value = Box::leak(Box::new(if pc_is_obj { Value::Object(Map::new()) } else { Value::Null }));
        if let Value::Object(p) = pc {
            for (k, x) in [("ver", ver), ("iat", iat), ("exp", exp), ("counter", counter)] {
                if let Some(v) = num_value(x) { reg(p, k, v); }
            }
            match aud_sel { 1 => reg(p, "aud", Value::String("A".into())), 2 => reg(p, "aud", Value::String("B".into())), 3 => reg(p, "aud", Value::Number(Number::from(1u64))), _ => {} }
            if let Some(v) = sel_value(gref_sel) { reg(p, "grant_ref", v); }
            match chain_kind { 1 => reg(p, "cap_chain", Value::String("x".into())), 2 => reg_ref(p, "cap_chain", chain_v), _ => {} }
        }
        let grant = Value::Object(Map::new());

        let v = verify_pcactn_core_policy(pc, &grant, now, "A", None);

        // ---- wire: terminal ----
        if got(core::ptr::addr_of!(WIRE)) == Some(false) || !pc_is_obj {
            assert!(!v.allow);
            assert_eq!(v.checks.len(), 1);
            assert_eq!(v.checks.get("wire"), Some(&false));
            assert!(!v.reason.is_empty());
            return;
        }
        // ---- the nine checks, each with its exact meaning over the abstract input and the oracle outcomes ----
        assert_eq!(v.checks.len(), 9);
        assert_eq!(v.checks.get("wire"), Some(&true));
        assert_eq!(v.checks.get("version"), Some(&(num_safe(ver) == Some(PCACTN_WIRE_VERSION))));
        assert_eq!(v.checks.get("audience"), Some(&(aud_sel == 1)));
        let (si, se) = (num_safe(iat).unwrap_or(0), num_safe(exp).unwrap_or(0));
        let validity = se > si && se - si <= MAX_LIFETIME_MS && si <= now.saturating_add(MAX_SKEW_MS) && now <= se;
        assert_eq!(v.checks.get("validity"), Some(&validity));
        // chain: cap and non-empty BEFORE any oracle; caveat cap before hashing; root == grant before the chain walk
        let in_cap = n >= 1 && n <= MAX_CHAIN_DEPTH;
        assert_eq!(got(core::ptr::addr_of!(CAV)).is_some(), in_cap);
        assert_eq!(got(core::ptr::addr_of!(SAME)).is_some(), in_cap && got(core::ptr::addr_of!(CAV)) == Some(false));
        assert_eq!(got(core::ptr::addr_of!(CHAIN)).is_some(), got(core::ptr::addr_of!(SAME)) == Some(true));
        assert_eq!(v.checks.get("chain"), Some(&(got(core::ptr::addr_of!(CHAIN)) == Some(true))));
        // grant_ref_bound: non-empty string byte-equal to cap_chain[0].id (a string)
        let gref_ok = n >= 1 && root_is_obj && (gref_sel == 2 || gref_sel == 3) && gref_sel == id_sel;
        assert_eq!(v.checks.get("grant_ref_bound"), Some(&gref_ok));
        assert_eq!(v.checks.get("plan_inclusion"), Some(&(got(core::ptr::addr_of!(LEAF)) == Some(true) && got(core::ptr::addr_of!(INCL)) == Some(true))));
        let sig = n >= 1 && got(core::ptr::addr_of!(SUITE)) == Some(true) && got(core::ptr::addr_of!(PQB)) == Some(true)
            && got(core::ptr::addr_of!(TM)) == Some(true) && got(core::ptr::addr_of!(SIG)) == Some(true);
        assert_eq!(v.checks.get("leaf_signature"), Some(&sig));
        assert_eq!(v.checks.get("counter"), Some(&matches!(num_safe(counter), Some(i) if i >= 0)));
        // ---- aggregation ----
        assert_eq!(v.allow, v.checks.values().all(|x| *x));
        assert_eq!(v.allow, v.reason.is_empty());
    }

    // ---------------- Layer 2: CONTRACT-GET on the real serde_json Map ----------------
    fn any_val() -> Value {
        match kani::any_where(|t: &u8| *t < 3) { 0 => Value::Null, 1 => Value::Number(Number::from(kani::any::<i64>())), _ => Value::String("r".into()) }
    }

    /// The PCActn shape: a real Map holding the seven fields the decision reads (each present or absent, any value of
    /// the abstract kinds); every key lookup the decision performs returns exactly the stored value or None. bounded-7 entries.
    #[kani::proof]
    #[kani::unwind(12)]
    fn json_abs_pcactn_shape() {
        const KEYS: [&str; 7] = ["ver", "aud", "iat", "exp", "counter", "grant_ref", "cap_chain"];
        const ABSENT: [&str; 7] = ["plan", "action", "alg", "pq_pk", "sig", "pq_sig", "id"];
        let mut m = Map::new();
        let mut model: [Option<Value>; 7] = Default::default();
        for i in 0..7 {
            if kani::any() { let v = any_val(); m.insert(KEYS[i].to_string(), v.clone()); model[i] = Some(v); }
        }
        for i in 0..7 { assert_eq!(m.get(KEYS[i]), model[i].as_ref()); }
        for k in ABSENT { assert!(m.get(k).is_none()); }
        // Value::get(&str) == Map::get on objects, None on any other value
        let k: usize = kani::any_where(|x: &usize| *x < 7);
        let ov = Value::Object(m);
        assert_eq!(ov.get(KEYS[k]), model[k].as_ref());
        let other = any_val();
        assert!(other.get(KEYS[k]).is_none());
    }

    /// Symbolic keys: up to 3 inserts with keys drawn from a 4-key universe (a strict prefix pair "id"/"idx", and keys
    /// sorting before/after), any values, overwrite semantics; a lookup of any universe key returns the LAST value inserted
    /// under it, or None. bounded: <= 3 entries, keys from that universe.
    #[kani::proof]
    #[kani::unwind(8)]
    fn json_abs_map_get_k3() {
        const U: [&str; 4] = ["aud", "id", "idx", "ver"];
        let mut m = Map::new();
        let mut model: [Option<Value>; 4] = Default::default();
        let ninserts: usize = kani::any_where(|x: &usize| *x <= 3);
        for _ in 0..ninserts {
            let k: usize = kani::any_where(|x: &usize| *x < 4);
            let v = any_val();
            m.insert(U[k].to_string(), v.clone());
            model[k] = Some(v);
        }
        let q: usize = kani::any_where(|x: &usize| *x < 4);
        assert_eq!(m.get(U[q]), model[q].as_ref());
    }
}

// =====================================================================================================================
// base64url: our wrapper `decode_b64u_strict` verified against CONTRACTS of what it calls (closes the bounded harnesses
// that ran out of memory inside the base64 crate), plus a differential harness tying a spec decoder to the real crate.
//
// `b64u_wrapper_contract_full`: the REAL wrapper on a string of ANY length n < 2^40 (a symbolic-length allocation; every
//   string the verifier can be handed is far shorter: MAX_ARTIFACT_BYTES = 524288) and ANY `len: Option<usize>`.
//   Callees replaced by contracts (each a sound over-approximation of the real callee):
//     CR-DEC  crate decode (`<GeneralPurpose as Engine>::decode`): Err, or Ok(v) with ANY contents and ANY length <= n.
//     CR-ENC  `b64_encode` (one line: the crate encoder): ANY string of ANY length < 2^41.
//     CR-ALL  `<slice::Iter<u8> as Iterator>::all` with the wrapper's own alphabet closure: result r; r = true constrains
//             f(s[i]) for an ARBITRARY index i (so assertions at i hold for every index), r = false requires a witness j
//             with !f(s[j]). This is exactly the std semantics (exact, not havoc), with no loop.
//     CR-EQ   `<str as PartialEq>::eq` (used by `String != &str`): length mismatch => false; otherwise the same
//             universal-index / witness encoding of byte-wise equality. No loop.
//   Proved: no panic, overflow or UB for any (s, len); and the result is Some(b) EXACTLY when every byte of s is in the
//   64-char url-safe alphabet (checked at the arbitrary index against an independent alphabet predicate, which also
//   checks the closure), n mod 4 != 1, the `len` length relation holds without overflow, the crate decodes s to b, the
//   crate re-encodes b to exactly s, and b.len() == len when given.
// `b64u_spec_vs_crate_leN`: our spec decoder `spec_decode` equals the real `URL_SAFE_NO_PAD.decode(..).ok()` on EVERY
//   byte string of length <= N (all 256 byte values, not only ASCII).
// =====================================================================================================================
mod b64_compositional {
    use super::super::*;
    use base64::engine::GeneralPurpose;

    const LIM_IN: usize = 1usize << 40;

    static mut ALL_R: Option<bool> = None;
    static mut ALL_I: usize = 0;
    static mut DEC: Option<Option<usize>> = None; // Some(None) = Err, Some(Some(m)) = Ok(len m)
    static mut EQ_R: Option<bool> = None;

    fn nondet_bytes(len: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(len);
        unsafe { v.set_len(len) } // CBMC heap: nondeterministic contents
        v
    }

    pub fn stub_all<'a, F: FnMut(&'a u8) -> bool>(it: &mut core::slice::Iter<'a, u8>, mut f: F) -> bool {
        let s: &'a [u8] = it.as_slice();
        let r: bool = if s.is_empty() { true } else { kani::any() };
        if !s.is_empty() {
            let i: usize = kani::any_where(|x: &usize| *x < s.len());
            if r { kani::assume(f(&s[i])); } else { kani::assume(!f(&s[i])); }
            unsafe { ALL_I = i; }
        }
        unsafe { assert!(ALL_R.is_none()); ALL_R = Some(r); }
        r
    }
    pub fn stub_str_eq(a: &str, b: &str) -> bool {
        let (x, y) = (a.as_bytes(), b.as_bytes());
        let r = if x.len() != y.len() { false } else if x.is_empty() { true } else {
            let r: bool = kani::any();
            let i: usize = kani::any_where(|k: &usize| *k < x.len());
            if r { kani::assume(x[i] == y[i]); } else { kani::assume(x[i] != y[i]); }
            r
        };
        unsafe { assert!(EQ_R.is_none()); EQ_R = Some(r); }
        r
    }
    pub fn stub_crate_decode<T: AsRef<[u8]>>(_e: &GeneralPurpose, input: T) -> Result<Vec<u8>, base64::DecodeError> {
        let n = input.as_ref().len();
        let res = if kani::any() {
            let m: usize = kani::any_where(|m: &usize| *m <= n);
            Ok(nondet_bytes(m))
        } else {
            Err(base64::DecodeError::InvalidLength(n))
        };
        unsafe { assert!(DEC.is_none()); DEC = Some(res.as_ref().ok().map(Vec::len)); }
        res
    }
    pub fn stub_b64_encode(_b: &[u8]) -> String {
        let k: usize = kani::any_where(|k: &usize| *k < 2 * LIM_IN);
        unsafe { String::from_utf8_unchecked(nondet_bytes(k)) }
    }

    fn is_b64u_char(c: u8) -> bool { matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') }

    #[kani::proof]
    #[kani::unwind(2)]
    #[kani::stub(<core::slice::Iter<u8> as core::iter::Iterator>::all, stub_all)]
    #[kani::stub(<str as core::cmp::PartialEq>::eq, stub_str_eq)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::decode, stub_crate_decode)]
    #[kani::stub(b64_encode, stub_b64_encode)]
    fn b64u_wrapper_contract_full() {
        let n: usize = kani::any_where(|x: &usize| *x < LIM_IN);
        let raw: &'static [u8] = Box::leak(nondet_bytes(n).into_boxed_slice());
        let s: &str = unsafe { core::str::from_utf8_unchecked(raw) };
        let len: Option<usize> = kani::any();

        let out = decode_b64u_strict(s, len);

        let all = unsafe { ALL_R };
        assert!(all.is_some()); // the alphabet scan is always run (first statement)
        // the REAL closure equals the url-safe alphabet at an ARBITRARY index, in both directions
        if n > 0 {
            let c = raw[unsafe { ALL_I }];
            if all == Some(true) { assert!(is_b64u_char(c)); } else { assert!(!is_b64u_char(c)); }
        }
        let alpha = all == Some(true);
        let len_ok = len.map_or(true, |m| m.checked_mul(4).is_some_and(|x| n == x.div_ceil(3)));
        let pre = alpha && n % 4 != 1 && len_ok;
        let dec = unsafe { DEC };
        assert_eq!(dec.is_some(), pre); // the crate is consulted iff the cheap checks pass
        let dec_ok = matches!(dec, Some(Some(_)));
        let eq = unsafe { EQ_R };
        assert_eq!(eq.is_some(), dec_ok); // re-encoding is compared iff the crate decoded
        let expect = pre && dec_ok && eq == Some(true) && len.map_or(true, |m| dec == Some(Some(m)));
        assert_eq!(out.is_some(), expect);
        if let Some(b) = out {
            assert_eq!(Some(Some(b.len())), dec);
            if let Some(m) = len { assert_eq!(b.len(), m); assert_eq!(n, (m * 4).div_ceil(3)); }
            assert!(n % 4 != 1);
        }
    }

    // ---------------- spec decoder (strict, canonical, no padding) ----------------
    fn sv(c: u8) -> Option<u32> {
        match c { b'A'..=b'Z' => Some((c - b'A') as u32), b'a'..=b'z' => Some((c - b'a') as u32 + 26), b'0'..=b'9' => Some((c - b'0') as u32 + 52), b'-' => Some(62), b'_' => Some(63), _ => None }
    }
    pub fn spec_decode(s: &[u8]) -> Option<Vec<u8>> {
        if s.len() % 4 == 1 { return None; }
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= s.len() {
            let w = (sv(s[i])? << 18) | (sv(s[i + 1])? << 12) | (sv(s[i + 2])? << 6) | sv(s[i + 3])?;
            out.push((w >> 16) as u8); out.push((w >> 8) as u8); out.push(w as u8);
            i += 4;
        }
        match s.len() - i {
            0 => {}
            2 => { let (a, b) = (sv(s[i])?, sv(s[i + 1])?); if b & 0x0f != 0 { return None; } out.push(((a << 2) | (b >> 4)) as u8); }
            3 => {
                let (a, b, c) = (sv(s[i])?, sv(s[i + 1])?, sv(s[i + 2])?);
                if c & 0x03 != 0 { return None; }
                let w = (a << 18) | (b << 12) | (c << 6);
                out.push((w >> 16) as u8); out.push((w >> 8) as u8);
            }
            _ => unreachable!(),
        }
        Some(out)
    }
    fn diff<const N: usize>() {
        let raw: [u8; N] = kani::any();
        let l: usize = kani::any_where(|x: &usize| *x <= N);
        let s = &raw[..l];
        assert_eq!(spec_decode(s), URL_SAFE_NO_PAD.decode(s).ok());
    }
    #[kani::proof] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le4() { diff::<4>() }
    #[kani::proof] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le5() { diff::<5>() }
    #[kani::proof] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le6() { diff::<6>() }
}
