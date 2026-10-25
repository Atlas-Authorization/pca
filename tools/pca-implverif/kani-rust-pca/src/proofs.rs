//! Kani proofs over the REAL atlas-pca code (copied byte-for-byte; see ../build.sh).
//! Every harness states its scope. "FULL" = the entire input range the verifier can reach (not an unwinding cap).
use super::*;

const MAXS: u64 = MAX_SAFE as u64;

// `format!` is only used to build human-readable reasons/errors. Its CBMC encoding (Display for f64/u128) is what exhausted memory in the
// first runs. The stub returns a fixed NON-EMPTY string: every `format!` template in lib.rs has a non-empty literal part, so this is
// faithful for every property asserted below (none inspects message text beyond non-emptiness).
fn stub_fmt_nonempty(_a: core::fmt::Arguments<'_>) -> String { String::from("<fmt>") }

// Intent Layer v2 (`decide_intent_v2`, intent_v2.rs) wraps each step in `std::panic::catch_unwind`, which lowers to the
// `catch_unwind` intrinsic whose signature Kani 0.68 rejects at reachability (kani-compiler intrinsics.rs; `std::panic` also
// resolves to the macro, so the std function cannot be stubbed by path). None of these harnesses is about Intent v2: the
// stub over-approximates its effect on the verdict (no v2 check, or one v2 check that passes or fails nondeterministically).
// Applied to every harness: the unused case is a no-op.
// V2_EXTRA records how many checks the stub reported (0 or 1): a verdict that reaches it carries the nine core checks
// PLUS these, so a harness asserting the size of the checks map must count them (it used to assert exactly 9, which the
// stub's extra passing check contradicts).
pub(crate) static mut V2_EXTRA: usize = 0;
pub(crate) fn stub_decide_intent_v2(_p: &serde_json::Value, _g: &serde_json::Value, _c: Option<&IntentV2Context>, _now: i64) -> IntentV2Decision {
    let mut d = IntentV2Decision::default();
    if kani::any() {
        let ok: bool = kani::any();
        d.checks.push(IntentV2Check { name: "intent_v2", ok, reason: if ok { String::new() } else { String::from("<stub>") } });
        unsafe { V2_EXTRA = 1; }
    }
    d
}

// ---- split(): RFC 6962 split point. FULL range: n is a safe integer (verify_inclusion bounds size by safe_int) ----
#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
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
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
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
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
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
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
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

// ---- decode_b64u_strict: public API with `len: Option<usize>`; the expected-length arithmetic is CHECKED ----
// It used to be the unchecked `(n * 4).div_ceil(3)` (this harness then documented the overflow panic for n > usize::MAX/4);
// decode_b64u_strict now computes `n.checked_mul(4)` and fails closed on overflow. This harness is the exact expression of
// the shipping code for ANY n: it never panics, it is None exactly on the overflow domain, and otherwise it is >= n.
#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
#[kani::unwind(6)]
fn decode_b64u_len_arith_any_n() {
    let n: usize = kani::any();
    // exact expression from decode_b64u_strict
    let m = n.checked_mul(4).map(|m| m.div_ceil(3));
    assert_eq!(m.is_none(), n > usize::MAX / 4);
    if let Some(m) = m {
        assert!(m >= n);
    }
}

// The pre-fix expression, restricted to the domain where `n * 4` cannot overflow: UNBOUNDED proof that the arithmetic is
// total there (the old unchecked form overflowed for n > usize::MAX/4; see decode_b64u_len_arith_any_n).
#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
fn decode_b64u_len_arith_guarded() {
    let n: usize = kani::any();
    kani::assume(n <= usize::MAX / 4);
    let m = (n * 4).div_ceil(3);
    assert!(m >= n); // 4n/3 >= n
}

// The REAL public function with a symbolic `len` (any usize, including the n > usize::MAX/4 overflow domain): no panic, and
// the empty input decodes exactly when the expected length is 0.
#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
#[kani::unwind(3)]
fn decode_b64u_real_fn_any_n() {
    let n: usize = kani::any();
    let r = decode_b64u_strict("", Some(n));
    assert_eq!(r.is_some(), n == 0);
}

// bounded-4: every ASCII string of length <= 4 (the bounded-6 harness exhausts 24 GB inside the base64 crate). 4 bytes
// cover every length class mod 4 (0, 2, 3; 1 is rejected before decoding) and one full quantum. The unbounded algorithmic
// statement is verus/b64u_strict.rs. Sharded BY LENGTH (decode_b64u_no_panic_bounded4_l0 .. _l4, together exactly the
// former single harness's domain, l <= 4): with a symbolic length every slice / Vec in the decoder has a symbolic size,
// and the one-harness form ended in a solver ERROR on the 16 GB runner after about 2 min ("0 of 2008 failed", verdict FAILED:
// CBMC's decision procedure returned D_ERROR, which it does when the solver runs out of memory during propositional
// reduction under the job's ulimit -v). One length per harness keeps the sizes concrete.
// That was not enough (run 38495915078): every length that reaches the base64 crate (l0, l2, l3, l4; l1 is rejected
// before it) still ends in a solver ERROR at 15 GB within 2 min, l0 included, because the cost is the real decode +
// encode + from_utf8 chain itself, whose heap contents CBMC does not fold even for concrete input. No check failed.
// Those four are probe tier (formal-kani-tiers.txt); the compositional b64_compositional harnesses carry the property.
fn decode_b64u_no_panic_len<const L: usize>() {
    let raw: [u8; L] = kani::any();
    kani::assume(raw.iter().all(|b| *b < 128));
    let s = unsafe { std::str::from_utf8_unchecked(&raw) };
    if let Some(b) = decode_b64u_strict(s, None) {
        assert_eq!(b64_encode(&b), s); // canonical: re-encoding reproduces the input
    }
}
macro_rules! b64_no_panic_len {
    ($($name:ident = $l:literal),* $(,)?) => {$(
        #[kani::proof]
        #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
        #[kani::unwind(8)]
        #[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
        fn $name() { decode_b64u_no_panic_len::<$l>() }
    )*};
}
b64_no_panic_len!(
    decode_b64u_no_panic_bounded4_l0 = 0,
    decode_b64u_no_panic_bounded4_l1 = 1,
    decode_b64u_no_panic_bounded4_l2 = 2,
    decode_b64u_no_panic_bounded4_l3 = 3,
    decode_b64u_no_panic_bounded4_l4 = 4,
);

// ---- decode_b64u_strict on all strings up to 6 bytes (bounded: base64 crate is opaque-heavy) ----
#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
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
static mut G_SAME_OK: bool = false;

fn stub_validate_wire(_p: &Value) -> Result<(), String> { Ok(()) }
fn stub_cap_hash(_c: &Value) -> String { if kani::any() { "h1".to_string() } else { "h2".to_string() } }
// chain[0] == grant: since 1ba8297a the decision compares the STRICT digests (same_strict_hash) instead of cap_hash. Left
// real, it ran strict canonicalisation + SHA-256 inside these harnesses (CBMC exit 6, its out-of-memory / internal-error
// code, after about 25 min on the 16 GB runner), and with the harness grant {} it matched only an id-less root, for which
// grant_ref_bound fails: allow was unreachable, so (A) and (F) were vacuous. Now a recorded nondeterministic oracle like
// the other leaves (as in the compositional d_* harnesses).
fn stub_same_strict_hash(_a: &Value, _b: &Value) -> bool {
    let ok: bool = kani::any(); unsafe { G_SAME_OK = ok; } ok
}
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
    unsafe { G_CHAIN_OK = false; G_INCL_OK = false; G_SIG_OK = false; G_CHAIN_CALLED = false; G_SAME_OK = false; }
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

    // (A) allow => the verdict carries EXACTLY the 9 named checks (plus the intent-v2 stub's, see V2_EXTRA), all true
    if v.allow {
        assert_eq!(v.checks.len(), 9 + unsafe { V2_EXTRA });
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
    // (E) the 16-hop cap and non-empty chain are enforced; the chain verifier is only consulted within them, and only
    //     for a chain whose root is the grant
    if v.checks.get("chain") == Some(&true) {
        assert!(n >= 1 && n <= MAX_CHAIN_DEPTH);
        unsafe { assert!(G_SAME_OK && G_CHAIN_CALLED && G_CHAIN_OK); }
    }
    // (F) allow => each oracle returned success
    if v.allow { unsafe { assert!(G_CHAIN_OK && G_INCL_OK && G_SIG_OK); } }
}

#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(same_strict_hash, stub_same_strict_hash)]
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
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(same_strict_hash, stub_same_strict_hash)]
#[kani::stub(verify_chain_policy, stub_verify_chain_policy)]
#[kani::stub(plan_leaf, stub_plan_leaf)]
#[kani::stub(verify_inclusion, stub_verify_inclusion)]
#[kani::stub(suite_allowed, stub_suite_allowed)]
#[kani::stub(pq_binding_ok, stub_pq_binding_ok)]
#[kani::stub(threshold_message, stub_threshold_message)]
#[kani::stub(verify_suite, stub_verify_suite)]
fn decision_aggregation_ints() { decision_aggregation_body(&[0, 1], false); }

#[kani::proof]
#[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
#[kani::unwind(20)]
#[kani::stub(alloc::fmt::format, stub_fmt_nonempty)]
#[kani::stub(validate_wire, stub_validate_wire)]
#[kani::stub(cap_hash, stub_cap_hash)]
#[kani::stub(same_strict_hash, stub_same_strict_hash)]
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
// Layer 1 (`d_*`, one harness per property): the REAL `verify_pcactn_core_policy` with the JSON layer abstracted. Every
//   serde_json map is an EMPTY `Map` (no BTreeMap nodes); `serde_json::Map::get` is stubbed by `stub_map_get`, which answers
//   from an abstract store keyed by (map address, key). Contract of the stub (CONTRACT-GET): `m.get(k)` returns the value
//   stored under k in m, or None. `Value::get(&str)` reaches it through serde_json's `Index for str` (Object(m) => m.get(k)),
//   so the real accessors (`as_object`, `as_array`, `as_str`, `safe_int`, `Value::get`) run unmodified on top of it. Each
//   harness starts from a fully passing input and makes symbolic only the fields of its property. cap_chain is a real Vec
//   of symbolic length (only chain[0] and chain[n-1] initialised: exactly what the non-stubbed code reads), so the length
//   needs no unwinding or loop contract: the decision function itself has no loop over the chain (the per-hop loops are
//   inside the stubbed leaves). Leaves are recorded nondeterministic oracles.
//   The nine checks are inline expressions of one function, not separate functions, so they cannot be given
//   #[kani::requires/ensures] contracts or `stub_verified` without modifying the library; each is instead proved in its
//   own harness against the real function.
// Layer 2 (`json_field_*`, `json_value_get_dispatch`): CONTRACT-GET holds for the real serde_json Map / Value::get.
// =====================================================================================================================
mod compositional {
    use super::super::*;
    use core::borrow::Borrow;
    use core::hash::Hash;
    use super::stub_fmt_nonempty;

    const MAXS: u64 = super::MAXS;

    // ---------------- abstract store behind the stubbed Map::get ----------------
    static mut REG: Vec<(usize, &'static str, &'static Value)> = Vec::new();
    fn reg_ref(m: &Map<String, Value>, k: &'static str, v: &'static Value) {
        unsafe { (*core::ptr::addr_of_mut!(REG)).push((m as *const _ as usize, k, v)) }
    }
    fn reg(m: &Map<String, Value>, k: &'static str, v: Value) { reg_ref(m, k, Box::leak(Box::new(v))) }
    pub fn stub_map_get<'a, Q>(m: &'a Map<String, Value>, key: &Q) -> Option<&'a Value>
    where
        String: Borrow<Q>,
        Q: ?Sized + Ord + Eq + Hash,
    {
        // every caller passes a &str key (Q = str); asserted, then the key is read as &str (static literals: no heap memcmp)
        assert!(core::any::type_name::<Q>() == "str");
        let ks: &str = unsafe { core::mem::transmute_copy::<&Q, &str>(&key) };
        let id = m as *const _ as usize;
        let r = unsafe { &*core::ptr::addr_of!(REG) };
        for (mid, k, v) in r.iter() {
            if *mid == id && *k == ks {
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
    static mut ORACLES_TRUE: bool = false; // set by harnesses whose property does not involve the oracles
    fn rec(g: *mut Option<bool>) -> bool {
        let b: bool = if unsafe { ORACLES_TRUE } { true } else { kani::any() };
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

    // ---------------- one abstract input, concretised onto empty maps + the abstract store ----------------
    #[derive(Clone, Copy)]
    struct In { ver: Num, iat: Num, exp: Num, counter: Num, now: i64, aud: u8, gref: u8, id: u8, root_obj: bool, chain_kind: u8, n: usize, pc_obj: bool }
    /// a fully PASSING input; each harness makes only the fields of its property symbolic
    fn base() -> In {
        In { ver: Num::I(PCACTN_WIRE_VERSION), iat: Num::I(1_000), exp: Num::I(2_000), counter: Num::I(0), now: 1_500, aud: 1, gref: 2, id: 2, root_obj: true, chain_kind: 2, n: 1, pc_obj: true }
    }
    fn run(x: &In) -> Verdict {
        let n = if x.chain_kind == 2 { x.n } else { 0 };
        let mut chain: Vec<Value> = Vec::with_capacity(n);
        unsafe {
            if n >= 1 {
                chain.as_mut_ptr().write(if x.root_obj { Value::Object(Map::new()) } else { Value::Null });
                if n >= 2 { chain.as_mut_ptr().add(n - 1).write(Value::Object(Map::new())); }
            }
            chain.set_len(n); // only chain[0] and chain[n-1] are read by the non-stubbed code
        }
        let chain_v: &'static Value = Box::leak(Box::new(Value::Array(chain)));
        if let Some(Value::Object(m0)) = chain_v.as_array().unwrap().first() {
            if let Some(v) = sel_value(x.id) { reg(m0, "id", v); }
        }
        let pc: &'static Value = Box::leak(Box::new(if x.pc_obj { Value::Object(Map::new()) } else { Value::Null }));
        if let Value::Object(p) = pc {
            for (k, f) in [("ver", x.ver), ("iat", x.iat), ("exp", x.exp), ("counter", x.counter)] {
                if let Some(v) = num_value(f) { reg(p, k, v); }
            }
            match x.aud { 1 => reg(p, "aud", Value::String("A".into())), 2 => reg(p, "aud", Value::String("B".into())), 3 => reg(p, "aud", Value::Number(Number::from(1u64))), _ => {} }
            if let Some(v) = sel_value(x.gref) { reg(p, "grant_ref", v); }
            match x.chain_kind { 1 => reg(p, "cap_chain", Value::String("x".into())), 2 => reg_ref(p, "cap_chain", chain_v), _ => {} }
        }
        let grant: &'static Value = Box::leak(Box::new(Value::Object(Map::new())));
        verify_pcactn_core_policy(pc, grant, x.now, "A", None)
    }
    fn chk(v: &Verdict, k: &str) -> Option<bool> { v.checks.get(k).copied() }
    fn force_oracles() { unsafe { ORACLES_TRUE = true; } }
    macro_rules! g { ($x:ident) => { got(core::ptr::addr_of!($x)) } }

    // every decision harness: the real function, JSON layer + leaves stubbed as described above
    macro_rules! dharness {
        ($name:ident, $unw:literal, $body:block) => {
            #[kani::proof]
            #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
            #[kani::unwind($unw)]
            #[kani::solver(cadical)]
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
            fn $name() $body
        };
    }

    // D1 wire is terminal: a failed wire oracle or a non-object PCActn yields exactly {wire:false}, deny, a reason;
    //    otherwise all nine checks are present and wire is true.
    dharness!(d_wire_terminal, 20, {
        let mut x = base(); x.pc_obj = kani::any();
        let v = run(&x);
        if g!(WIRE) == Some(false) || !x.pc_obj {
            assert!(!v.allow); assert_eq!(v.checks.len(), 1); assert_eq!(chk(&v, "wire"), Some(false)); assert!(!v.reason.is_empty());
        } else {
            assert_eq!(v.checks.len(), 9 + unsafe { super::V2_EXTRA }); assert_eq!(chk(&v, "wire"), Some(true));
        }
    });
    // D2 version == (safe_int(ver) == 2), ver absent / string / any i64 / any u64
    dharness!(d_version, 20, {
        force_oracles(); let mut x = base(); x.ver = any_num();
        let v = run(&x);
        assert_eq!(chk(&v, "version"), Some(num_safe(x.ver) == Some(PCACTN_WIRE_VERSION)));
    });
    // D3 audience == (aud is the string equal to this verifier's audience); aud absent / match / other string / number
    dharness!(d_audience, 20, {
        force_oracles(); let mut x = base(); x.aud = kani::any_where(|t: &u8| *t < 4);
        let v = run(&x);
        assert_eq!(chk(&v, "audience"), Some(x.aud == 1));
    });
    // D4 validity: exact spec over ANY now and iat/exp each absent / string / any i64 / any u64 (non-safe => 0)
    dharness!(d_validity, 20, {
        force_oracles(); let mut x = base(); x.iat = any_num(); x.exp = any_num(); x.now = kani::any();
        let v = run(&x);
        let (si, se) = (num_safe(x.iat).unwrap_or(0), num_safe(x.exp).unwrap_or(0));
        let ok = se > si && se - si <= MAX_LIFETIME_MS && si <= x.now.saturating_add(MAX_SKEW_MS) && x.now <= se;
        assert_eq!(chk(&v, "validity"), Some(ok));
    });
    // D5 counter == (safe integer >= 0)
    dharness!(d_counter, 20, {
        force_oracles(); let mut x = base(); x.counter = any_num();
        let v = run(&x);
        assert_eq!(chk(&v, "counter"), Some(matches!(num_safe(x.counter), Some(i) if i >= 0)));
    });
    // D6 grant_ref_bound == non-empty string byte-equal to cap_chain[0].id (a string); chain absent / non-array / 0..2 hops,
    //    root object or not, id and grant_ref over absent / "" / "r" / "q" / number
    dharness!(d_grant_ref_bound, 20, {
        force_oracles(); let mut x = base();
        x.gref = kani::any_where(|t: &u8| *t < 5); x.id = kani::any_where(|t: &u8| *t < 5); x.root_obj = kani::any();
        x.chain_kind = kani::any_where(|t: &u8| *t < 3); x.n = kani::any_where(|t: &usize| *t <= 2);
        let v = run(&x);
        let n = if x.chain_kind == 2 { x.n } else { 0 };
        let ok = n >= 1 && x.root_obj && (x.gref == 2 || x.gref == 3) && x.gref == x.id;
        assert_eq!(chk(&v, "grant_ref_bound"), Some(ok));
    });
    // D7 chain cap: for ANY chain length n < 2^32 (and absent / non-array), the caveat oracle (first chain oracle) is consulted
    //    iff 1 <= n <= 16, and with passing oracles chain == (1 <= n <= 16). No loop: the chain is a symbolic-length Vec.
    dharness!(d_chain_cap, 20, {
        force_oracles(); let mut x = base();
        x.chain_kind = kani::any_where(|t: &u8| *t < 3); x.n = kani::any_where(|t: &usize| *t < (1usize << 32));
        let v = run(&x);
        let n = if x.chain_kind == 2 { x.n } else { 0 };
        let in_cap = n >= 1 && n <= MAX_CHAIN_DEPTH;
        assert_eq!(g!(CAV).is_some(), in_cap);
        assert_eq!(chk(&v, "chain"), Some(in_cap));
    });
    // D8 chain gate order (pairwise): caveat cap before root==grant before the chain walk; each later gate is consulted iff
    //    the earlier passed; chain == the conjunction of the three oracle outcomes.
    dharness!(d_chain_gate_order, 20, {
        let v = run(&base());
        if g!(WIRE) != Some(true) { return; }
        assert!(g!(CAV).is_some());
        assert_eq!(g!(SAME).is_some(), g!(CAV) == Some(false));
        assert_eq!(g!(CHAIN).is_some(), g!(SAME) == Some(true));
        assert_eq!(chk(&v, "chain"), Some(g!(CAV) == Some(false) && g!(SAME) == Some(true) && g!(CHAIN) == Some(true)));
    });
    // D9 plan_inclusion == leaf computed && inclusion verified; the inclusion verifier only runs on a computed leaf
    dharness!(d_plan_inclusion, 20, {
        let v = run(&base());
        if g!(WIRE) != Some(true) { return; }
        assert_eq!(g!(INCL).is_some(), g!(LEAF) == Some(true));
        assert_eq!(chk(&v, "plan_inclusion"), Some(g!(LEAF) == Some(true) && g!(INCL) == Some(true)));
    });
    // D10 leaf_signature == chain non-empty && suite allowed && PQ binding ok && message built && signature verifies,
    //     consulted in that order (each only if the previous passed); chain absent / non-array / 0..2 hops
    dharness!(d_leaf_signature, 20, {
        let mut x = base(); x.chain_kind = kani::any_where(|t: &u8| *t < 3); x.n = kani::any_where(|t: &usize| *t <= 2);
        let v = run(&x);
        if g!(WIRE) != Some(true) { return; }
        let n = if x.chain_kind == 2 { x.n } else { 0 };
        assert_eq!(g!(SUITE).is_some(), n >= 1);
        assert_eq!(g!(PQB).is_some(), g!(SUITE) == Some(true));
        assert_eq!(g!(TM).is_some(), g!(PQB) == Some(true));
        assert_eq!(g!(SIG).is_some(), g!(TM) == Some(true));
        assert_eq!(chk(&v, "leaf_signature"), Some(n >= 1 && g!(SIG) == Some(true)));
    });
    // D11 aggregation: every check independently passing or failing (input selectors + nondeterministic oracles);
    //     exactly nine checks, allow iff all nine are true, and a reason iff deny
    dharness!(d_allow_iff_all_pass, 20, {
        let mut x = base();
        if kani::any() { x.ver = Num::I(3); }
        if kani::any() { x.aud = 2; }
        if kani::any() { x.exp = Num::I(999); }
        if kani::any() { x.counter = Num::I(-1); }
        if kani::any() { x.gref = 3; }
        let v = run(&x);
        if g!(WIRE) != Some(true) { return; }
        assert_eq!(v.checks.len(), 9 + unsafe { super::V2_EXTRA });
        for k in ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"] {
            assert!(v.checks.contains_key(k));
        }
        assert_eq!(v.allow, v.checks.values().all(|b| *b));
        assert_eq!(v.allow, v.reason.is_empty());
    });

    // ---------------- Layer 2: CONTRACT-GET on the real serde_json Map ----------------
    // No Value is cloned, compared with the recursive PartialEq, or dropped (serde_json's clone / eq / drop glue are
    // recursive over Value; CBMC unrolls that recursion at every level). Each value is BUILT twice from the same choice,
    // compared with the non-recursive `same`, and the maps are leaked.
    fn mk_val(t: u8, i: i64) -> Value { match t { 0 => Value::Null, 1 => Value::Number(Number::from(i)), _ => Value::String("r".into()) } }
    fn same(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Null, Value::Null) => true,
            (Value::Number(x), Value::Number(y)) => x.as_i64() == y.as_i64() && x.as_u64() == y.as_u64(),
            (Value::String(x), Value::String(y)) => x == y,
            _ => false,
        }
    }
    const KEYS: [&str; 7] = ["ver", "aud", "iat", "exp", "counter", "grant_ref", "cap_chain"];
    const ABSENT: [&str; 7] = ["plan", "action", "alg", "pq_pk", "sig", "pq_sig", "id"];
    // (A bounded-2 variant, the field plus one other PCActn field, ran out of 12 GB: with two real inserts the second
    //  insert's key comparison is a memcmp over heap String bytes that CBMC's symbolic execution does not fold.)
    /// Bounded-1, per field: a real Map holding only field `t` (present or absent, ANY value of the abstract kinds);
    /// `get(t)` returns exactly the stored value or None, and `get` of a different PCActn key returns None.
    fn json_field1(t: usize) {
        let mut m = Map::new();
        let present: bool = kani::any();
        let (kind, num): (u8, i64) = (kani::any_where(|k: &u8| *k < 3), kani::any());
        if present { core::mem::forget(m.insert(KEYS[t].to_string(), mk_val(kind, num))); }
        let model = mk_val(kind, num);
        match m.get(KEYS[t]) { Some(v) => { assert!(present); assert!(same(v, &model)); } None => assert!(!present) }
        assert!(m.get(KEYS[(t + 1) % 7]).is_none());
        assert!(m.get(ABSENT[t]).is_none());
        core::mem::forget(model); core::mem::forget(m);
    }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_ver() { json_field1(0) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_aud() { json_field1(1) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_iat() { json_field1(2) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_exp() { json_field1(3) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_counter() { json_field1(4) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_grant_ref() { json_field1(5) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(11)] #[kani::solver(cadical)] fn json_field1_cap_chain() { json_field1(6) }
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(6)]
    #[kani::solver(cadical)]
    fn json_value_get_dispatch() {
        let mut m = Map::new();
        let present: bool = kani::any();
        let (kind, num): (u8, i64) = (kani::any_where(|k: &u8| *k < 3), kani::any());
        if present { core::mem::forget(m.insert("id".to_string(), mk_val(kind, num))); }
        let o = Value::Object(m);
        let model = mk_val(kind, num);
        match o.get("id") { Some(v) => { assert!(present); assert!(same(v, &model)); } None => assert!(!present) }
        let other = mk_val(kani::any_where(|k: &u8| *k < 3), kani::any());
        assert!(other.get("id").is_none());
        core::mem::forget(o); core::mem::forget(model); core::mem::forget(other);
    }
}

// =====================================================================================================================
// base64url: our wrapper `decode_b64u_strict` verified against CONTRACTS of what it calls (closes the bounded harnesses
// that ran out of memory inside the base64 crate), plus a differential harness tying a spec decoder to the real crate.
//
// `b64u_wrapper_contract_le64` (cargo feature `b64wrap`): the REAL wrapper, the REAL alphabet scan, the REAL string
//   comparison and the crate's REAL `Engine::decode` code, on every ASCII string of length <= 64 and ANY `len`, with two
//   contracts: CR-DEC `<GeneralPurpose as Engine>::internal_decode` (the decoding loop): Err, or Ok with any decoded length
//   <= the conservative output buffer; CR-ENC `b64_encode`: any string of length <= 64. Proves no panic / overflow / UB
//   and that the result is Some exactly when: every byte is in the url-safe alphabet, n mod 4 != 1, the `len` relation
//   holds without overflow, the crate decodes, the re-encoding equals the input, and the decoded length equals `len`.
//   `b64u_decode_metadata_mirror` checks the layout mirror the CR-DEC stub uses to build the crate's DecodeMetadata.
// `b64u_spec_vs_crate_leN`: our spec decoder `spec_decode` equals the real `URL_SAFE_NO_PAD.decode(..).ok()` on EVERY
//   byte string of length <= N (all 256 byte values, not only ASCII).
// =====================================================================================================================
mod b64_compositional {
    use super::super::*;

    #[cfg(feature = "b64wrap")]
    pub use wrap::*;
    #[cfg(feature = "b64wrap")]
    mod wrap {
    use super::super::super::*;
    static mut DEC: Option<Option<usize>> = None; // Some(None) = Err, Some(Some(m)) = Ok(len m)
    static mut ENC_EQ: Option<bool> = None;
    static mut INPUT: (usize, usize) = (0, 0); // (ptr, len) of the harness input, for the encode contract

    fn nondet_bytes(len: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(len);
        unsafe { v.set_len(len) } // CBMC heap: nondeterministic contents
        v
    }

    /// CR-DEC, stubbing the impl method `<GeneralPurpose as Engine>::internal_decode` (the decoding loop). The crate's own
    /// `Engine::decode` (estimate, zeroed Vec of the conservative length, truncate) runs for real on top of it. Contract:
    /// Err(InvalidLength), or Ok with ANY decoded_len <= output.len(). The output bytes are left as the crate zeroed them:
    /// nothing in the wrapper reads decoded CONTENTS (only lengths; the encode contract ignores its argument).
    #[allow(dead_code)]
    pub struct DmMirror { pub decoded_len: usize, pub padding_offset: Option<usize> }
    pub fn stub_internal_decode(_e: &base64::engine::GeneralPurpose, input: &[u8], output: &mut [u8], _est: base64::engine::general_purpose::GeneralPurposeEstimate)
        -> Result<base64::engine::DecodeMetadata, base64::DecodeSliceError> {
        let ok: bool = kani::any();
        let m: usize = kani::any_where(|m: &usize| *m <= output.len());
        unsafe { assert!(DEC.is_none()); DEC = Some(if ok { Some(m) } else { None }); } // Engine::decode truncates to m
        let res = if ok {
            // layout of the mirror == DecodeMetadata: checked on real values by `b64u_decode_metadata_mirror` (no stub)
            Ok(unsafe { core::mem::transmute::<DmMirror, base64::engine::DecodeMetadata>(DmMirror { decoded_len: m, padding_offset: None }) })
        } else {
            Err(base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidLength(input.len())))
        };
        res
    }
    fn is_b64u_char(c: u8) -> bool { matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') }

    // NOTE: an any-length variant (alphabet scan and string equality replaced by loop-free exact contracts) was written
    // and dropped: Kani 0.68 cannot stub a trait's PROVIDED method for one Self type (`Iterator::all`, `Engine::decode`:
    // "Cannot stub"), and resolves `<T as Trait>::m` only for methods defined in that impl. The decoding loop is such a
    // method (`<GeneralPurpose as Engine>::internal_decode`), so it is the one contract used below.

    /// CR-ENC variants. `b64_encode` is one line (the crate encoder); the wrapper only compares its result with the input.
    pub fn stub_b64_encode_empty(_b: &[u8]) -> String { String::new() }
    pub fn stub_b64_encode_copy_or_any(_b: &[u8]) -> String {
        let (p, n) = unsafe { INPUT };
        let inp = unsafe { core::slice::from_raw_parts(p as *const u8, n) };
        let v = if kani::any() { inp.to_vec() } else { nondet_bytes(kani::any_where(|k: &usize| *k <= 64)) };
        unsafe { ENC_EQ = Some(v.as_slice() == inp); }
        unsafe { String::from_utf8_unchecked(v) }
    }
    fn input(raw: &'static [u8]) -> &'static str {
        unsafe { INPUT = (raw.as_ptr() as usize, raw.len()); core::str::from_utf8_unchecked(raw) }
    }
    /// n 'A's (in the alphabet), built by a concrete loop
    /// built as ONE allocation of nondeterministic bytes constrained to 'A' (a Vec push loop reallocates and copies, which
    /// ran out of 12 GB already at lengths 4..7)
    fn a_string(n: usize) -> &'static [u8] {
        let raw: &'static [u8] = Box::leak(nondet_bytes(n).into_boxed_slice());
        for i in 0..n { kani::assume(raw[i] == b'A'); }
        raw
    }

    /// The DmMirror layout equals DecodeMetadata: real `internal_decode` (no stub) on two concrete inputs, read back
    /// through the mirror. Validates the transmute in `stub_internal_decode`.
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(10)]
    fn b64u_decode_metadata_mirror() {
        for (inp, want) in [(&b"QUJD"[..], 3usize), (&b"QQ"[..], 1usize)] {
            let mut out = [0u8; 8];
            let est = URL_SAFE_NO_PAD.internal_decoded_len_estimate(inp.len());
            let dm = URL_SAFE_NO_PAD.internal_decode(inp, &mut out, est).ok().unwrap();
            let mm: DmMirror = unsafe { core::mem::transmute(dm) };
            assert_eq!(mm.decoded_len, want);
            assert_eq!(mm.padding_offset, None);
        }
    }

    // B1 alphabet scan (the REAL std scan with the wrapper's REAL closure): on every ASCII string of length <= 64, the crate
    //    is consulted only if EVERY byte (checked at an arbitrary index) is in the url-safe alphabet; a string with any byte
    //    outside it is rejected before the crate is consulted.
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(66)]
    #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_alphabet_scan_le64() {
        let n: usize = kani::any_where(|x: &usize| *x <= 64);
        let raw: &'static [u8] = Box::leak(nondet_bytes(n).into_boxed_slice());
        let i: usize = kani::any();
        kani::assume(i < n);
        kani::assume(raw[i] < 128);
        let out = decode_b64u_strict(input(raw), None);
        if !is_b64u_char(raw[i]) { assert!(out.is_none()); assert!(unsafe { DEC }.is_none()); }
        if unsafe { DEC }.is_some() { assert!(is_b64u_char(raw[i])); }
    }
    // B2 length / padding rules: on in-alphabet strings of every length n <= 64 and ANY `len: Option<usize>` (including
    //    n*4 overflow), the crate is consulted exactly when n mod 4 != 1 and (len given => n == ceil(4*len/3) without overflow).
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(66)]
    #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_length_rules_le64() { length_rules(0, 64) }
    fn length_rules(lo: usize, hi: usize) {
        let n: usize = kani::any_where(|x: &usize| *x >= lo && *x <= hi);
        let len: Option<usize> = kani::any();
        let _ = decode_b64u_strict(input(a_string(n)), len);
        let len_ok = len.map_or(true, |m| m.checked_mul(4).is_some_and(|x| n == x.div_ceil(3)));
        assert_eq!(unsafe { DEC }.is_some(), n % 4 != 1 && len_ok);
    }
    // B3 round trip and result: on in-alphabet strings of length <= 64 and any `len`, with the crate decoding to ANY length
    //    and re-encoding to the input or to ANY other string of length <= 64: Some(b) exactly when the cheap checks pass, the
    //    crate decodes, the re-encoding equals the input byte for byte (the REAL comparison), and b.len() == len when given.
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(66)]
    #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_roundtrip_le64() { roundtrip(0, 64) }
    fn roundtrip(lo: usize, hi: usize) {
        let n: usize = kani::any_where(|x: &usize| *x >= lo && *x <= hi);
        let len: Option<usize> = kani::any();
        let out = decode_b64u_strict(input(a_string(n)), len);
        let len_ok = len.map_or(true, |m| m.checked_mul(4).is_some_and(|x| n == x.div_ceil(3)));
        let dec = unsafe { DEC };
        let expect = n % 4 != 1 && len_ok && matches!(dec, Some(Some(_))) && unsafe { ENC_EQ } == Some(true) && len.map_or(true, |m| dec == Some(Some(m)));
        assert_eq!(out.is_some(), expect);
        if let Some(b) = out { assert_eq!(Some(Some(b.len())), dec); if let Some(m) = len { assert_eq!(b.len(), m); } }
    }
    // B2/B3 split by input length: [4k, 4k+3] for k = 0..15 (the last group includes 64)
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(6)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n00_03() { length_rules(0, 3) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(6)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n00_03() { roundtrip(0, 3) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(10)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n04_07() { length_rules(4, 7) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(10)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n04_07() { roundtrip(4, 7) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(14)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n08_11() { length_rules(8, 11) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(14)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n08_11() { roundtrip(8, 11) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(18)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n12_15() { length_rules(12, 15) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(18)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n12_15() { roundtrip(12, 15) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(22)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n16_19() { length_rules(16, 19) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(22)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n16_19() { roundtrip(16, 19) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(26)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n20_23() { length_rules(20, 23) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(26)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n20_23() { roundtrip(20, 23) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(30)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n24_27() { length_rules(24, 27) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(30)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n24_27() { roundtrip(24, 27) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(34)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n28_31() { length_rules(28, 31) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(34)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n28_31() { roundtrip(28, 31) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(38)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n32_35() { length_rules(32, 35) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(38)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n32_35() { roundtrip(32, 35) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(42)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n36_39() { length_rules(36, 39) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(42)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n36_39() { roundtrip(36, 39) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(46)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n40_43() { length_rules(40, 43) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(46)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n40_43() { roundtrip(40, 43) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(50)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n44_47() { length_rules(44, 47) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(50)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n44_47() { roundtrip(44, 47) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(54)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n48_51() { length_rules(48, 51) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(54)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n48_51() { roundtrip(48, 51) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(58)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n52_55() { length_rules(52, 55) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(58)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n52_55() { roundtrip(52, 55) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(62)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n56_59() { length_rules(56, 59) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(62)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n56_59() { roundtrip(56, 59) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(67)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_empty)]
    fn b_len_n60_64() { length_rules(60, 64) }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(67)] #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    #[kani::stub(b64_encode, stub_b64_encode_copy_or_any)]
    fn b_rt_n60_64() { roundtrip(60, 64) }
    // B4 the crate's own `Engine::decode` code over the CR-DEC contract, for an input of ANY length < 2^40 (symbolic-length
    //    buffer, no loop): no panic or overflow (estimate arithmetic, zeroed buffer, the OutputSliceTooSmall `unreachable!`),
    //    Ok(v) has exactly the decoded length the decoding loop reported, Err is passed through.
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(3)]
    #[kani::solver(cadical)]
    #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_decode, stub_internal_decode)]
    fn b_crate_decode_over_contract_any_len() {
        let n: usize = kani::any_where(|x: &usize| *x < (1usize << 40));
        let raw = nondet_bytes(n);
        let r = URL_SAFE_NO_PAD.decode(&raw[..]);
        match (r, unsafe { DEC }) {
            (Ok(v), Some(Some(m))) => assert_eq!(v.len(), m),
            (Err(_), Some(None)) => {}
            _ => panic!("result does not match the decoding loop's outcome"),
        }
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
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le4() { diff::<4>() }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le5() { diff::<5>() }
    #[kani::proof] #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)] #[kani::unwind(9)] #[kani::solver(cadical)] fn b64u_spec_vs_crate_le6() { diff::<6>() }
}

// =====================================================================================================================
// b64_encode (the shipped encoder, `URL_SAFE_NO_PAD.encode`): never panics and returns exactly ceil(4n/3) bytes of the
// url-safe alphabet (no padding). Required tier. The real decode + encode + compare chain of decode_b64u_no_panic_bounded4
// does not fit the 16 GB runner, so the encoder is proved in three compositional pieces, each on the REAL code:
//   E1 b64e_len_arith_any_n  the crate's `encoded_len(n, false)` for ANY usize n: the exact unpadded length, and Some for
//                            every n <= isize::MAX (every real slice length), so `.expect("integer overflow ...")` in
//                            Engine::encode never fires; URL_SAFE_NO_PAD does not pad.
//   E2 b64e_loop_nNN         the REAL encoding loop `<GeneralPurpose as Engine>::internal_encode` on ANY n input bytes into
//                            the exact-size output (stack arrays, no heap): no panic / overflow / out-of-bounds, returns
//                            exactly encoded_len(n), and EVERY output byte is written with an alphabet byte (the output starts
//                            zeroed and 0 is not in the alphabet). Shards n = 0..9 (every n mod 3, up to three 3-byte
//                            chunks) and n = 27..29 (the 24-byte fast loop runs once only from n = 27; then each n mod 3).
//   E3 b64e_contract_nNN     the REAL `b64_encode` (encoded_len, the zeroed Vec, encode_with_padding with its debug_asserts
//                            and checked_add, String::from_utf8(..).expect) with the loop replaced by the contract E2
//                            proves (CR-ENC-LOOP: fill the whole output with alphabet bytes, return output.len()): no
//                            panic, length ceil(4n/3), alphabet only. n = 0..6 required.
// E1 + E2 + E3 compose to: b64_encode never panics and returns exactly ceil(4n/3) alphabet bytes, for n in 0..=6 (all three
// pieces) -- E1 and E2 alone also cover the arithmetic for every n and the loop for n in 0..=9 and 27..=29.
// Probe tier (fit not yet measured on the runner): b64e_contract_n09 / n12 (from_utf8's 16-byte ASCII block path) / n27,
// and b64e_real_n00..n03, the real end-to-end encoder with nothing stubbed.
// =====================================================================================================================
mod b64_encoder {
    use super::super::*;
    use base64::engine::Config as _;

    fn b64u_char(c: u8) -> bool { matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') }
    /// ceil(4n/3), written as the crate's unpadded case split
    fn unpadded_len(n: usize) -> usize { 4 * (n / 3) + [0usize, 2, 3][n % 3] }

    // E1
    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::solver(cadical)]
    fn b64e_len_arith_any_n() {
        let n: usize = kani::any();
        let m = base64::encoded_len(n, false);
        match (n / 3).checked_mul(4) {
            Some(c) => assert_eq!(m, c.checked_add([0usize, 2, 3][n % 3])),
            None => assert!(m.is_none()),
        }
        if n <= isize::MAX as usize {
            let k = m.unwrap(); // Some for every real slice length
            assert_eq!(k, unpadded_len(n));
            let (k, n) = (k as u128, n as u128); // k == ceil(4n/3): 3k >= 4n > 3k - 3
            assert!(3 * k >= 4 * n && 3 * k < 4 * n + 3);
        }
        assert!(!URL_SAFE_NO_PAD.config().encode_padding());
    }

    // E2
    fn loop_shard<const N: usize, const M: usize>() {
        assert_eq!(M, unpadded_len(N));
        let raw: [u8; N] = kani::any();
        let mut out = [0u8; M];
        let w = URL_SAFE_NO_PAD.internal_encode(&raw, &mut out);
        assert_eq!(w, M);
        let mut i = 0;
        while i < M {
            assert!(b64u_char(out[i]));
            i += 1;
        }
    }
    macro_rules! enc_loop {
        ($($name:ident = ($n:literal, $m:literal, $u:literal)),* $(,)?) => {$(
            #[kani::proof]
            #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
            #[kani::unwind($u)]
            #[kani::solver(cadical)]
            fn $name() { loop_shard::<$n, $m>() }
        )*};
    }
    enc_loop!(
        b64e_loop_n00 = (0, 0, 4), b64e_loop_n01 = (1, 2, 5), b64e_loop_n02 = (2, 3, 5), b64e_loop_n03 = (3, 4, 6),
        b64e_loop_n04 = (4, 6, 8), b64e_loop_n05 = (5, 7, 9), b64e_loop_n06 = (6, 8, 10), b64e_loop_n07 = (7, 10, 12),
        b64e_loop_n08 = (8, 11, 13), b64e_loop_n09 = (9, 12, 14),
        b64e_loop_n27 = (27, 36, 38), b64e_loop_n28 = (28, 38, 40), b64e_loop_n29 = (29, 39, 41),
    );

    // E3: CR-ENC-LOOP, exactly what E2 proves of the real loop for an output of the exact encoded size
    pub fn stub_internal_encode_contract(_e: &base64::engine::GeneralPurpose, _input: &[u8], output: &mut [u8]) -> usize {
        let mut i = 0;
        while i < output.len() {
            let c: u8 = kani::any();
            kani::assume(b64u_char(c));
            output[i] = c;
            i += 1;
        }
        output.len()
    }
    fn encode_shard<const N: usize>() {
        let raw: [u8; N] = kani::any();
        let s = b64_encode(&raw);
        assert_eq!(s.len(), unpadded_len(N));
        assert!(s.bytes().all(b64u_char));
    }
    macro_rules! enc_contract {
        ($($name:ident = ($n:literal, $u:literal)),* $(,)?) => {$(
            #[kani::proof]
            #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
            #[kani::unwind($u)]
            #[kani::solver(cadical)]
            #[kani::stub(<base64::engine::GeneralPurpose as base64::Engine>::internal_encode, stub_internal_encode_contract)]
            fn $name() { encode_shard::<$n>() }
        )*};
    }
    enc_contract!(
        b64e_contract_n00 = (0, 4), b64e_contract_n01 = (1, 5), b64e_contract_n02 = (2, 6), b64e_contract_n03 = (3, 7),
        b64e_contract_n04 = (4, 9), b64e_contract_n05 = (5, 10), b64e_contract_n06 = (6, 11),
        b64e_contract_n09 = (9, 15), b64e_contract_n12 = (12, 19), b64e_contract_n27 = (27, 39),
    );
    // the real end-to-end encoder, nothing stubbed (probe: whether the full chain fits)
    macro_rules! enc_real {
        ($($name:ident = ($n:literal, $u:literal)),* $(,)?) => {$(
            #[kani::proof]
            #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
            #[kani::unwind($u)]
            #[kani::solver(cadical)]
            fn $name() { encode_shard::<$n>() }
        )*};
    }
    enc_real!(b64e_real_n00 = (0, 4), b64e_real_n01 = (1, 5), b64e_real_n02 = (2, 6), b64e_real_n03 = (3, 7));
}

// =====================================================================================================================
// Decision AGGREGATION, compositional (required tier). The end-to-end harnesses (decision_aggregation_ints /
// _chain_cap, d_allow_iff_all_pass) run the real verify_pcactn_core_with and do not fit the runner: the cost is the real
// Verdict.checks BTreeMap<String, bool> (9+ String-key inserts) and the serde_json maps; they stay in the long tier.
//
// Here the harness is cut at the aggregation: every check outcome and every oracle answer is a symbolic boolean (the
// per-check MEANINGS are the d_version / d_audience / d_validity / d_counter / d_grant_ref_bound harnesses), the chain
// length is ANY usize, and the checks map is an abstract map keyed by check id with BTreeMap::insert semantics. `decide`
// is a line-for-line transcription of verify_pcactn_core_with (sdks/rust-pca/src/lib.rs): wire_fail, the `record`
// closure (insert; the first failure sets the reason, `format!("{name}: {why}")`, never empty), the chain gate
// (empty -> cap -> caveat_limit_exceeded -> same_strict_hash -> verify_chain_policy), plan_leaf/verify_inclusion,
// the leaf signature gate (chain.last() -> suite_allowed || pq_binding_ok -> threshold_message -> verify_suite), counter,
// the optional M2 `intent` check and the intent-v2 checks, then `allow = checks.values().all(|v| *v)`.
// The link to the compiled function is that transcription (not machine-checked); the long-tier harnesses are the
// end-to-end check of it.
//
// Lemma CORE-KEYS (why an abstract map keyed by id is faithful), by construction of lib.rs / intent_v2.rs / intent_wb.rs:
//   - past the wire gate, `record` is called exactly once for each of the nine core names, in straight-line code (no
//     loop, no return between record("wire") and record("counter")), with nine distinct string literals;
//   - every later key is "intent" (M2) or an intent-v2 name: schema, intent_session, layers, map, accumulators, facts and
//     the W-B names facts / provenance / classes. None equals a core name, so no later insert replaces a core entry;
//   - within one decision each v2 name is reported at most once ("map" is run on exactly one of the two exclusive
//     branches `present` / `!present`); the model gives each extra key its own slot, recorded at most once.
//   With distinct keys, BTreeMap::insert adds one entry per call: len == 9 + number of extras.
// =====================================================================================================================
mod aggregation {
    use super::super::*;

    const WIRE: usize = 0;
    const VERSION: usize = 1;
    const AUDIENCE: usize = 2;
    const VALIDITY: usize = 3;
    const CHAIN: usize = 4;
    const GREF: usize = 5;
    const PLAN: usize = 6;
    const LEAF: usize = 7;
    const COUNTER: usize = 8;
    const CORE: usize = 9;
    const INTENT: usize = 9;
    const V2: usize = 10;
    const V2_NAMES: usize = 9;
    const KEYS: usize = V2 + V2_NAMES;

    #[derive(Clone, Copy)]
    struct In {
        wire_ok: bool, pc_obj: bool, version: bool, audience: bool, validity: bool, gref: bool, counter: bool,
        n: usize, cav: bool, same: bool, chain_ok: bool, leaf: bool, incl: bool, suite: bool, pqb: bool, tm: bool, sig: bool,
        intent: Option<bool>, v2: [Option<bool>; V2_NAMES],
    }
    fn any_in() -> In {
        In {
            wire_ok: kani::any(), pc_obj: kani::any(), version: kani::any(), audience: kani::any(), validity: kani::any(),
            gref: kani::any(), counter: kani::any(), n: kani::any(), cav: kani::any(), same: kani::any(), chain_ok: kani::any(),
            leaf: kani::any(), incl: kani::any(), suite: kani::any(), pqb: kani::any(), tm: kani::any(), sig: kani::any(),
            intent: kani::any(), v2: kani::any(),
        }
    }
    /// which oracles were consulted
    #[derive(Default)]
    struct Gates { cav: bool, same: bool, chain: bool, incl: bool, suite: bool, pqb: bool, tm: bool, sig: bool }
    struct Agg { checks: [Option<bool>; KEYS], reason: bool }
    impl Agg {
        /// the `record` closure: insert (or replace) the entry; the first failure sets the (non-empty) reason
        fn record(&mut self, k: usize, ok: bool) {
            self.checks[k] = Some(ok);
            if !ok && !self.reason {
                self.reason = true;
            }
        }
    }
    fn decide(x: &In, g: &mut Gates) -> (bool, Agg) {
        let mut a = Agg { checks: [None; KEYS], reason: false };
        // validate_wire, then as_object: wire_fail(why) is exactly {wire: false} with reason "wire: ..."
        if !x.wire_ok || !x.pc_obj {
            a.record(WIRE, false);
            return (false, a);
        }
        a.record(WIRE, true);
        a.record(VERSION, x.version);
        a.record(AUDIENCE, x.audience);
        a.record(VALIDITY, x.validity);
        let chain = if x.n == 0 {
            false
        } else if x.n > MAX_CHAIN_DEPTH {
            false
        } else {
            g.cav = true;
            if x.cav {
                false
            } else {
                g.same = true;
                if !x.same {
                    false
                } else {
                    g.chain = true;
                    x.chain_ok
                }
            }
        };
        a.record(CHAIN, chain);
        a.record(GREF, x.gref);
        let plan = if x.leaf {
            g.incl = true;
            x.incl
        } else {
            false
        };
        a.record(PLAN, plan);
        let sig = x.n >= 1
            && { g.suite = true; x.suite }
            && { g.pqb = true; x.pqb }
            && { g.tm = true; x.tm }
            && { g.sig = true; x.sig };
        a.record(LEAF, sig);
        a.record(COUNTER, x.counter);
        if let Some(r) = x.intent {
            a.record(INTENT, r);
        }
        let mut i = 0;
        while i < V2_NAMES {
            if let Some(r) = x.v2[i] {
                a.record(V2 + i, r);
            }
            i += 1;
        }
        let allow = a.checks.iter().all(|c| *c != Some(false));
        (allow, a)
    }

    #[kani::proof]
    #[kani::stub(crate::pca::intent_v2::decide_intent_v2, crate::pca::proofs::stub_decide_intent_v2)]
    #[kani::unwind(21)]
    #[kani::solver(cadical)]
    fn agg_decision_properties() {
        let x = any_in();
        let mut g = Gates::default();
        let (allow, a) = decide(&x, &mut g);
        let present = a.checks.iter().filter(|c| c.is_some()).count();
        // wire failure is terminal: exactly {wire: false}, deny, a reason, no oracle consulted
        if !x.wire_ok || !x.pc_obj {
            assert!(!allow);
            assert_eq!(present, 1);
            assert_eq!(a.checks[WIRE], Some(false));
            assert!(a.reason);
            assert!(!g.cav && !g.same && !g.chain && !g.incl && !g.suite && !g.sig);
            return;
        }
        // the nine core checks are always present; the map holds exactly them plus the reported extras
        let mut k = 0;
        while k < CORE {
            assert!(a.checks[k].is_some());
            k += 1;
        }
        let extras = (x.intent.is_some() as usize) + x.v2.iter().filter(|c| c.is_some()).count();
        assert_eq!(present, CORE + extras);
        // closed forms of the two gated checks
        let chain_spec = x.n >= 1 && x.n <= MAX_CHAIN_DEPTH && !x.cav && x.same && x.chain_ok;
        let sig_spec = x.n >= 1 && x.suite && x.pqb && x.tm && x.sig;
        assert_eq!(a.checks[CHAIN], Some(chain_spec));
        assert_eq!(a.checks[LEAF], Some(sig_spec));
        assert_eq!(a.checks[PLAN], Some(x.leaf && x.incl));
        // (A) allow => all nine core checks present and true, and every extra true
        if allow {
            let mut k = 0;
            while k < CORE {
                assert_eq!(a.checks[k], Some(true));
                k += 1;
            }
            assert!(x.intent != Some(false));
            assert!(x.v2.iter().all(|c| *c != Some(false)));
        }
        // (B) allow iff every check passed, in closed form over the inputs
        let spec = x.version && x.audience && x.validity && chain_spec && x.gref && x.leaf && x.incl && sig_spec && x.counter
            && x.intent != Some(false) && x.v2.iter().all(|c| *c != Some(false));
        assert_eq!(allow, spec);
        // (C) deny iff a reason
        assert_eq!(allow, !a.reason);
        // (E) the chain check passes only within 1..=16 hops, after the caveat cap and root == grant, and only when the
        //     chain verifier was consulted and answered success; gate order: each gate is consulted only past the previous
        if a.checks[CHAIN] == Some(true) {
            assert!(x.n >= 1 && x.n <= MAX_CHAIN_DEPTH);
            assert!(g.cav && !x.cav && g.same && x.same && g.chain && x.chain_ok);
        }
        if g.cav { assert!(x.n >= 1 && x.n <= MAX_CHAIN_DEPTH); }
        if g.same { assert!(g.cav && !x.cav); }
        if g.chain { assert!(g.same && x.same); }
        if g.incl { assert!(x.leaf); }
        if g.pqb { assert!(g.suite && x.suite); }
        if g.tm { assert!(g.pqb && x.pqb); }
        if g.sig { assert!(x.n >= 1 && g.tm && x.tm); }
        // (F) allow => every oracle was consulted and returned success
        if allow {
            assert!(g.chain && x.chain_ok && g.incl && x.incl && g.sig && x.sig);
            assert!(!x.cav && x.same && x.leaf && x.suite && x.pqb && x.tm);
        }
    }
}
