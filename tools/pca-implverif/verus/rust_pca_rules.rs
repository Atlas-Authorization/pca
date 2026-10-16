// Verus proofs (ALL inputs, unbounded) of decision rules of the Rust PCA verifier sdks/rust-pca (crate atlas-pca).
// IMPORTANT SCOPE: these are verified Verus-subset TRANSLITERATIONS of fragments of sdks/rust-pca/src/lib.rs. They are
// not the shipping code; the link to it is by line correspondence (each function names the exact line range of lib.rs at
// commit f0991ade (lib.rs last changed in d25f90f9) that it transliterates) plus the conformance corpus, not a machine-checked refinement.
//
// Modelling conventions (the theorems hold for EVERY value of the modelled inputs):
//   * a JSON string is a u64 id under an injective encoding (equal ids <=> equal strings); EMPTY_STR is "".
//     A field that is absent or not a string is `None` where the code distinguishes it.
//   * cryptographic and parsing results (signature verification, strict JSON hashing, base64url decoding) are boolean
//     oracle INPUTS; `holder_pq_commitment` (SHA-256 based, lib.rs 1073-1077) is the uninterpreted `commit`.
//   * roles: agent = 0, guardian = 1, principal = 2; any other role string (or a missing / non-string role) is an id >= 3.
use vstd::prelude::*;

verus! {

pub const EMPTY_STR: u64 = 0;
pub const NAME_ED25519: u64 = 1;   // "ed25519"
pub const NAME_MLDSA65: u64 = 2;   // "ml-dsa-65"
pub const NAME_HYBRID: u64 = 3;    // "hybrid-ed25519-ml-dsa-65"
pub const NAME_NONSTR: u64 = 4;    // "\u{0}non-string" (alg_name's label for a non-string alg, lib.rs 1083)
pub const SUITE_ED: u8 = 0;
pub const SUITE_ML: u8 = 1;
pub const SUITE_HY: u8 = 2;

pub open spec fn b2i(b: bool) -> int { if b { 1int } else { 0int } }

// ===================== A. chain depth and caveat caps =====================
pub const MAX_CHAIN_DEPTH: usize = 16;
pub const MAX_CAVEATS_PER_HOP: usize = 256;
pub const MAX_CAVEATS_PER_CHAIN: usize = 1024;

// lib.rs 1236-1242 (verify_chain_policy) and 1848-1851 (the "chain" check of verify_pcactn_core_policy).
// 0 = go on to the next gate, 1 = "empty chain", 2 = "chain too long (max 16 hops)".
pub fn chain_len_gate(len: usize) -> (r: u8)
    ensures
        (r == 0) <==> (1 <= len && len <= 16),
        len == 0 ==> r == 1,
        len > 16 ==> r == 2,     // a chain longer than 16 hops is ALWAYS rejected
{
    if len == 0 { 1 } else if len > MAX_CHAIN_DEPTH { 2 } else { 0 }
}

pub open spec fn sum(ns: Seq<usize>) -> int
    decreases ns.len(),
{
    if ns.len() == 0 { 0 } else { sum(ns.drop_last()) + ns.last() as int }
}

pub open spec fn caps_exceeded(ns: Seq<usize>) -> bool {
    (exists|i: int| 0 <= i < ns.len() && ns[i] > 256) || sum(ns) > 1024
}

proof fn lemma_prefix_sum_le(ns: Seq<usize>, i: int)
    requires 0 <= i <= ns.len(),
    ensures sum(ns.subrange(0, i)) <= sum(ns),
    decreases ns.len(),
{
    if i == ns.len() {
        assert(ns.subrange(0, i) =~= ns);
    } else {
        lemma_prefix_sum_le(ns.drop_last(), i);
        assert(ns.drop_last().subrange(0, i) =~= ns.subrange(0, i));
    }
}

// lib.rs 41-54 caveat_limit_exceeded. ns[i] = the raw caveat-list length of hop i (`map_or(0, Vec::len)`).
// Exact for every usize list, and `total += n` cannot overflow.
pub fn caveat_limit_exceeded(ns: &Vec<usize>) -> (r: bool)
    ensures r <==> caps_exceeded(ns@),
{
    let mut total: usize = 0;
    let mut i: usize = 0;
    while i < ns.len()
        invariant
            0 <= i <= ns.len(),
            total as int == sum(ns@.subrange(0, i as int)),
            total <= 1024,
            forall|k: int| 0 <= k < i ==> ns@[k] <= 256,
        decreases ns.len() - i,
    {
        let n = ns[i];
        if n > MAX_CAVEATS_PER_HOP {
            proof { assert(ns@[i as int] > 256); }
            return true;
        }
        proof {
            assert(ns@.subrange(0, i as int + 1).drop_last() =~= ns@.subrange(0, i as int));
            assert(ns@.subrange(0, i as int + 1).last() == ns@[i as int]);
        }
        total = total + n;
        if total > MAX_CAVEATS_PER_CHAIN {
            proof { lemma_prefix_sum_le(ns@, i as int + 1); }
            return true;
        }
        i += 1;
    }
    proof { assert(ns@.subrange(0, ns@.len() as int) =~= ns@); }
    false
}

// lib.rs 1844-1860: the "chain" check. Gate order as in the source: depth cap, caveat caps, root == grant, then the walk.
// `root_is_grant` = same_strict_hash(chain[0], grant); `walk_ok` = verify_chain_policy(...) is Ok (oracle).
pub fn chain_check(ns: &Vec<usize>, root_is_grant: bool, walk_ok: bool) -> (r: bool)
    ensures r <==> (1 <= ns@.len() <= 16 && !caps_exceeded(ns@) && root_is_grant && walk_ok),
{
    if chain_len_gate(ns.len()) != 0 {
        false
    } else if caveat_limit_exceeded(ns) {
        false
    } else if !root_is_grant {
        false
    } else {
        walk_ok
    }
}

// ===================== B. signature suites, suite policy, PQ binding =====================
pub enum AlgV { Absent, Str(u64), NonStr }

pub open spec fn suite_of(a: AlgV) -> Option<u8> {
    match a {
        AlgV::Absent => Some(SUITE_ED),
        AlgV::Str(s) => if s == NAME_ED25519 { Some(SUITE_ED) } else if s == NAME_MLDSA65 { Some(SUITE_ML) }
                        else if s == NAME_HYBRID { Some(SUITE_HY) } else { None },
        AlgV::NonStr => None,
    }
}
pub open spec fn needs_pq(a: AlgV) -> bool { suite_of(a) == Some(SUITE_ML) || suite_of(a) == Some(SUITE_HY) }

// lib.rs 806-833 sig_suite + resolve_sig_alg: absent => ed25519; a known name => that suite; anything else => None.
pub fn resolve_sig_alg(a: &AlgV) -> (r: Option<u8>)
    ensures r == suite_of(*a),
{
    match *a {
        AlgV::Absent => Some(SUITE_ED),
        AlgV::Str(s) => {
            if s == NAME_ED25519 { Some(SUITE_ED) } else if s == NAME_MLDSA65 { Some(SUITE_ML) }
            else if s == NAME_HYBRID { Some(SUITE_HY) } else { None }
        }
        AlgV::NonStr => None,
    }
}

// lib.rs 1079-1085 alg_name.
pub open spec fn alg_name(a: AlgV) -> u64 {
    match a { AlgV::Absent => NAME_ED25519, AlgV::Str(s) => s, AlgV::NonStr => NAME_NONSTR }
}

// lib.rs 1088-1096 suite_allowed. `has_policy == false` is `allowed: None`.
pub fn suite_allowed(alg: &AlgV, has_policy: bool, allowed: &Vec<u64>) -> (r: bool)
    ensures
        r <==> (!has_policy || allowed@.contains(alg_name(*alg))),
        // an alg whose name is outside a present policy is never accepted; an empty policy refuses every suite
        has_policy && allowed@.len() == 0 ==> !r,
{
    if !has_policy {
        return true;
    }
    let n = match *alg { AlgV::Absent => NAME_ED25519, AlgV::Str(s) => s, AlgV::NonStr => NAME_NONSTR };
    let mut i: usize = 0;
    while i < allowed.len()
        invariant 0 <= i <= allowed.len(), n == alg_name(*alg),
            forall|k: int| 0 <= k < i ==> allowed@[k] != n,
        decreases allowed.len() - i,
    {
        if allowed[i] == n {
            proof { assert(allowed@[i as int] == n); }
            return true;
        }
        i += 1;
    }
    false
}

pub uninterp spec fn commit(pk: u64) -> u64;   // holder_pq_commitment (lib.rs 1073-1077)

// lib.rs 1098-1108 pq_binding_ok. `pk_commit` = holder_pq_commitment(pq_pk), computed by the caller.
pub fn pq_binding_ok(alg: &AlgV, pq_pk: Option<u64>, pk_commit: u64, committed: Option<u64>) -> (r: bool)
    requires pq_pk is Some ==> pk_commit == commit(pq_pk->Some_0),
    ensures r <==> (needs_pq(*alg) ==> (pq_pk is Some && committed is Some && commit(pq_pk->Some_0) == committed->Some_0)),
{
    match resolve_sig_alg(alg) {
        Some(su) => {
            if su != SUITE_ED {
                match pq_pk {
                    Some(_) => match committed { Some(c) => pk_commit == c, None => false },
                    None => false,
                }
            } else {
                true
            }
        }
        None => true,
    }
}

// Under collision resistance of the commitment, a commitment binds exactly one PQ key.
pub proof fn lemma_binding_unique(alg: AlgV, a: u64, b: u64, c: u64)
    requires
        forall|x: u64, y: u64| commit(x) == commit(y) ==> x == y,
        needs_pq(alg), commit(a) == c, commit(b) == c,
    ensures a == b,
{
}

// lib.rs 988-1020 pinned::resolve_pq_key. `pin` = pq_pins.get(identity) when both are present (else None);
// `trusted` = trusted_pk. Returns the key the ML-DSA half verifies under, or None (REFUSE).
pub open spec fn has_trusted(t: Option<u64>) -> bool { t is Some && t->Some_0 != EMPTY_STR }

pub fn resolve_pq_key(pin: Option<u64>, artifact_pk: Option<u64>, pk_commit: u64, holder_pq: Option<u64>, trusted: Option<u64>) -> (r: Option<u64>)
    requires artifact_pk is Some ==> pk_commit == commit(artifact_pk->Some_0),
    ensures
        has_trusted(trusted) ==> r == trusted,
        (r is Some && !has_trusted(trusted)) ==> (
            artifact_pk == r && r->Some_0 != EMPTY_STR
            && (pin is Some ==> pin == r)
            && (pin is None ==> holder_pq == Some(commit(r->Some_0)))),
        // a pin that differs from the artifact's key refuses; holder_pq never rescues it
        (!has_trusted(trusted) && pin is Some && pin != artifact_pk) ==> r is None,
        // the artifact's own key is never enough
        (!has_trusted(trusted) && pin is None && holder_pq is None) ==> r is None,
{
    match trusted {
        Some(t) => { if t != EMPTY_STR { return Some(t); } }
        None => {}
    }
    let pk = match artifact_pk {
        Some(s) => { if s != EMPTY_STR { s } else { return None; } }
        None => { return None; }
    };
    match pin {
        Some(p) => { return if p == pk { Some(pk) } else { None }; }
        None => {}
    }
    match holder_pq {
        Some(c) => { if pk_commit == c { Some(pk) } else { None } }
        None => None,
    }
}

// lib.rs 1199-1224 resolve_root_pq. Outer None = Err(root_pq_pin_reason); Some(None) = Ok(None) (no PQ key needed).
// `trusted_same_hash` = trusted_root is present and same_strict_hash(trusted_root, root).
pub fn resolve_root_pq(alg: &AlgV, root_pk: Option<u64>, pk_commit: u64, trusted_same_hash: bool, pin: Option<u64>) -> (r: Option<Option<u64>>)
    requires root_pk is Some ==> pk_commit == commit(root_pk->Some_0),
    ensures
        !needs_pq(*alg) ==> r == Some(None::<u64>),
        // a PQ root key comes ONLY from the verifier's stored grant or a pin for the root issuer, never from holder_pq
        (r is Some && r->Some_0 is Some) ==> (root_pk == r->Some_0 && r->Some_0->Some_0 != EMPTY_STR
            && (trusted_same_hash || pin == r->Some_0)),
        (needs_pq(*alg) && !trusted_same_hash && pin is None) ==> r is None,
{
    let suite = match resolve_sig_alg(alg) { Some(s) => s, None => { return Some(None); } };
    if suite == SUITE_ED {
        return Some(None);
    }
    let trusted = if trusted_same_hash { root_pk } else { None };
    match resolve_pq_key(pin, root_pk, pk_commit, None, trusted) {
        Some(k) => Some(Some(k)),
        None => None,
    }
}

// lib.rs 1894-1913 (the "leaf_signature" check) with verify_suite (929-953) and ml_dsa65_verify_pinned (955-960).
// Oracles: `msg_ok` = threshold_message(p) is Ok; `sig_is_str` = `sig` is a string; `ed_ok` = Ed25519 verification of
// `sig` under the leaf holder; `ml_ok` = ML-DSA-65 verification under the key returned in r.1 (the pinned key).
pub fn leaf_signature_ok(chain_nonempty: bool, alg: &AlgV, has_policy: bool, allowed: &Vec<u64>,
    pq_pk: Option<u64>, pk_commit: u64, leaf_holder_pq: Option<u64>,
    msg_ok: bool, sig_is_str: bool, ed_ok: bool, ml_ok: bool) -> (r: (bool, Option<u64>))
    requires pq_pk is Some ==> pk_commit == commit(pq_pk->Some_0),
    ensures
        r.0 ==> chain_nonempty && msg_ok && sig_is_str,
        r.0 ==> suite_of(*alg) is Some,                      // unknown or non-string alg never accepted
        (r.0 && has_policy) ==> allowed@.contains(alg_name(*alg)),
        (r.0 && needs_pq(*alg)) ==> (pq_pk is Some && leaf_holder_pq == Some(commit(pq_pk->Some_0)) && r.1 == pq_pk && ml_ok),
        (r.0 && suite_of(*alg) != Some(SUITE_ML)) ==> ed_ok,
{
    if !chain_nonempty {
        return (false, None);
    }
    if !suite_allowed(alg, has_policy, allowed) || !pq_binding_ok(alg, pq_pk, pk_commit, leaf_holder_pq) {
        return (false, None);
    }
    if !msg_ok {
        return (false, None);
    }
    let key = resolve_pq_key(None, pq_pk, pk_commit, leaf_holder_pq, None);
    let suite = match resolve_sig_alg(alg) { Some(s) => s, None => { return (false, key); } };
    if !sig_is_str {
        return (false, key);
    }
    if suite == SUITE_ED {
        (ed_ok, key)
    } else if suite == SUITE_ML {
        (key.is_some() && ml_ok, key)
    } else {
        (ed_ok && key.is_some() && ml_ok, key)
    }
}

// The non-string alg label can collide with a string alg "\u{0}non-string" in the suite POLICY (alg_name is not
// injective), but such an alg is still refused because it resolves to no suite.
pub proof fn lemma_nonstring_alg_refused(a: AlgV)
    requires a is NonStr,
    ensures suite_of(a) is None,
{
}

// ===================== C. audience =====================
fn bytes_eq(a: &Vec<u8>, b: &Vec<u8>) -> (r: bool)
    ensures r <==> a@ == b@,
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant a.len() == b.len(), 0 <= i <= a.len(), forall|k: int| 0 <= k < i ==> a@[k] == b@[k],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            proof { assert(a@[i as int] != b@[i as int]); }
            return false;
        }
        i += 1;
    }
    proof { assert(a@ =~= b@); }
    true
}

// lib.rs 1372-1375 (validate_wire): `aud` must be a non-empty string of at most 256 bytes.
pub fn aud_wire_ok(aud: &Option<Vec<u8>>) -> (r: bool)
    ensures r <==> (aud is Some && 0 < aud->Some_0@.len() && aud->Some_0@.len() <= 256),
{
    match aud { Some(a) => a.len() > 0 && a.len() <= 256, None => false }
}

// lib.rs 1816-1823: the "audience" check, `p.aud == Some(audience)`.
pub fn aud_check(aud: &Option<Vec<u8>>, audience: &Vec<u8>) -> (r: bool)
    ensures r <==> (aud is Some && aud->Some_0@ == audience@),
{
    match aud { Some(a) => bytes_eq(a, audience), None => false }
}

// Composition (validate_wire runs first, lib.rs 1786-1788): an action is accepted on audience only if it carries `aud`, and
// that `aud` equals the verifier's audience; an empty verifier audience can never be matched (fail closed).
pub fn audience_accepts(aud: &Option<Vec<u8>>, audience: &Vec<u8>) -> (r: bool)
    ensures
        r <==> (aud is Some && aud->Some_0@ == audience@ && 0 < audience@.len() && audience@.len() <= 256),
        aud is None ==> !r,
        audience@.len() == 0 ==> !r,
{
    aud_wire_ok(aud) && aud_check(aud, audience)
}

// ===================== D. signer-set registry and the threshold share =====================
pub struct Entry { pub role: u64, pub pk: u64, pub pk_ok: bool, pub pq: Option<u64>, pub pq_ok: bool }
// pk_ok: publicKey is a string that decodes (strict base64url) to 32 bytes; pq_ok: a present pq_pk is a string decoding to
// a registered PQ key length (lib.rs 1626-1635). A non-object entry is modelled by role >= 3 (rejected first).
pub struct RegRow { pub role: u64, pub pk: u64, pub pq: Option<u64> }

pub open spec fn row_of(e: Entry) -> RegRow { RegRow { role: e.role, pk: e.pk, pq: e.pq } }
pub open spec fn entry_ok(e: Entry) -> bool { e.role < 3 && e.pk_ok && (e.pq is Some ==> e.pq_ok) }

// The rule: every entry well formed; ONE key (and one pq_pk) per role; ONE role per key.
pub open spec fn set_valid(s: Seq<Entry>) -> bool {
    &&& forall|i: int| 0 <= i < s.len() ==> entry_ok(#[trigger] s[i])
    &&& forall|i: int, j: int| #![trigger s[i], s[j]] 0 <= i < s.len() && 0 <= j < s.len() && s[i].role == s[j].role
            ==> s[i].pk == s[j].pk && s[i].pq == s[j].pq
    &&& forall|i: int, j: int| #![trigger s[i], s[j]] 0 <= i < s.len() && 0 <= j < s.len() && s[i].pk == s[j].pk
            ==> s[i].role == s[j].role
}

pub open spec fn reg_wf(reg: Seq<RegRow>) -> bool {
    &&& forall|j: int| 0 <= j < reg.len() ==> (#[trigger] reg[j]).role < 3
    &&& forall|a: int, b: int| #![trigger reg[a], reg[b]] 0 <= a < reg.len() && 0 <= b < reg.len() && a != b
            ==> reg[a].role != reg[b].role && reg[a].pk != reg[b].pk
}

pub open spec fn has_role(reg: Seq<RegRow>, r: u64) -> bool {
    exists|j: int| 0 <= j < reg.len() && (#[trigger] reg[j]).role == r
}
pub open spec fn n_reg_roles(reg: Seq<RegRow>) -> int {
    b2i(has_role(reg, 0)) + b2i(has_role(reg, 1)) + b2i(has_role(reg, 2))
}

proof fn lemma_push_role(reg: Seq<RegRow>, row: RegRow, r: u64)
    ensures has_role(reg.push(row), r) <==> (has_role(reg, r) || row.role == r),
{
    let n = reg.push(row);
    if has_role(n, r) {
        let j = choose|j: int| 0 <= j < n.len() && (#[trigger] n[j]).role == r;
        if j < reg.len() { assert(reg[j] == n[j]); }
    }
    if has_role(reg, r) {
        let j = choose|j: int| 0 <= j < reg.len() && (#[trigger] reg[j]).role == r;
        assert(n[j] == reg[j]);
    }
    if row.role == r {
        assert(n[reg.len() as int] == row);
    }
}

fn opt_eq(a: Option<u64>, b: Option<u64>) -> (r: bool)
    ensures r <==> a == b,
{
    match a {
        Some(x) => match b { Some(y) => x == y, None => false },
        None => match b { Some(_) => false, None => true },
    }
}

fn find_role(reg: &Vec<RegRow>, role: u64) -> (r: Option<usize>)
    ensures
        r is Some ==> (r->Some_0 < reg@.len() && reg@[r->Some_0 as int].role == role),
        r is None ==> forall|k: int| 0 <= k < reg@.len() ==> reg@[k].role != role,
{
    let mut q: usize = 0;
    while q < reg.len()
        invariant 0 <= q <= reg.len(), forall|k: int| 0 <= k < q ==> reg@[k].role != role,
        decreases reg.len() - q,
    {
        if reg[q].role == role {
            return Some(q);
        }
        q += 1;
    }
    None
}

fn any_pk(reg: &Vec<RegRow>, pk: u64) -> (r: bool)
    ensures r <==> exists|k: int| 0 <= k < reg@.len() && (#[trigger] reg@[k]).pk == pk,
{
    let mut q: usize = 0;
    while q < reg.len()
        invariant 0 <= q <= reg.len(), forall|k: int| 0 <= k < q ==> reg@[k].pk != pk,
        decreases reg.len() - q,
    {
        if reg[q].pk == pk {
            proof { assert(reg@[q as int].pk == pk); }
            return true;
        }
        q += 1;
    }
    false
}

// Post-loop half of validate_signer_set, proved in its own small query: if every entry is well formed and maps (via the
// ghost witness idx) onto a row of a well-formed registry, the set satisfies the rule.
proof fn lemma_set_valid_from_reg(ss: Seq<Entry>, reg: Seq<RegRow>, idx: Seq<int>)
    requires
        reg_wf(reg),
        forall|k: int| 0 <= k < ss.len() ==> entry_ok(#[trigger] ss[k]),
        idx.len() == ss.len(),
        forall|k: int| #![trigger idx[k]] 0 <= k < ss.len() ==> 0 <= idx[k] && idx[k] < reg.len() && reg[idx[k]] == row_of(ss[k]),
    ensures set_valid(ss),
{
    assert forall|a: int, b: int| #![trigger ss[a], ss[b]] 0 <= a < ss.len() && 0 <= b < ss.len() && ss[a].role == ss[b].role
        implies ss[a].pk == ss[b].pk && ss[a].pq == ss[b].pq by {
        let ja = idx[a];
        let jb = idx[b];
        assert(reg[ja] == row_of(ss[a]) && reg[jb] == row_of(ss[b]));
        if ja != jb { assert(reg[ja].role != reg[jb].role); }
    }
    assert forall|a: int, b: int| #![trigger ss[a], ss[b]] 0 <= a < ss.len() && 0 <= b < ss.len() && ss[a].pk == ss[b].pk
        implies ss[a].role == ss[b].role by {
        let ja = idx[a];
        let jb = idx[b];
        assert(reg[ja] == row_of(ss[a]) && reg[jb] == row_of(ss[b]));
        if ja != jb { assert(reg[ja].pk != reg[jb].pk); }
    }
}

// lib.rs 1616-1650 validate_signer_set. Some(reg) EXACTLY when the set satisfies the rule; then reg has one row per
// role (<= 3 rows), distinct roles and distinct keys (role -> key injective, the registry_ok premise of
// core_checks.rs count_valid), and its rows are exactly the entries' (role, publicKey, pq_pk) triples.
//
// Proof shape: the entry<->row correspondence is carried as two GHOST WITNESS MAPS (idx: entry k -> its row, src: row j
// -> an entry it came from) rather than as `forall k. exists j` / `forall j. exists k` invariants. Those two existential
// invariants trigger each other (an ss[k] term yields a skolem reg[j] term, which yields a skolem ss[k'] term, ...): a
// matching loop that exhausted the rlimit on the function-body check (CI run 38436318175). With the witness maps no
// invariant has a quantifier alternation; the existential postconditions are discharged once, at the end, from them.
// rlimit(200) is kept only as headroom for the 4-vCPU runner; the spec is unchanged.
#[verifier::rlimit(200)]
pub fn validate_signer_set(ss: &Vec<Entry>) -> (r: Option<Vec<RegRow>>)
    ensures
        r is Some <==> set_valid(ss@),
        r is Some ==> reg_wf(r->Some_0@) && r->Some_0@.len() <= 3,
        r is Some ==> forall|k: int| 0 <= k < ss@.len() ==>
            exists|j: int| 0 <= j < r->Some_0@.len() && r->Some_0@[j] == row_of(#[trigger] ss@[k]),
        r is Some ==> forall|j: int| 0 <= j < r->Some_0@.len() ==>
            exists|k: int| 0 <= k < ss@.len() && #[trigger] r->Some_0@[j] == row_of(ss@[k]),
{
    let mut reg: Vec<RegRow> = Vec::new();
    let ghost mut idx: Seq<int> = Seq::empty();   // entry k (k < i) -> index of its row in reg
    let ghost mut src: Seq<int> = Seq::empty();   // row j -> an entry index (< i) it was made from
    let mut i: usize = 0;
    while i < ss.len()
        invariant
            0 <= i <= ss.len(),
            reg_wf(reg@),
            reg@.len() == n_reg_roles(reg@),
            forall|k: int| 0 <= k < i ==> entry_ok(#[trigger] ss@[k]),
            idx.len() == i,
            forall|k: int| #![trigger idx[k]] 0 <= k < i ==> 0 <= idx[k] && idx[k] < reg@.len() && reg@[idx[k]] == row_of(ss@[k]),
            src.len() == reg@.len(),
            forall|j: int| #![trigger src[j]] 0 <= j < reg@.len() ==> 0 <= src[j] && src[j] < i && reg@[j] == row_of(ss@[src[j]]),
        decreases ss.len() - i,
    {
        let e = &ss[i];
        if e.role >= 3 || !e.pk_ok || (e.pq.is_some() && !e.pq_ok) {
            proof { assert(!entry_ok(ss@[i as int])); }
            return None;
        }
        match find_role(&reg, e.role) {
            Some(q) => {
                if reg[q].pk != e.pk || !opt_eq(reg[q].pq, e.pq) {
                    proof {
                        let k = src[q as int];
                        assert(reg@[q as int] == row_of(ss@[k]));
                        assert(ss@[k].role == ss@[i as int].role);
                        assert(!set_valid(ss@));
                    }
                    return None; // two keys for one role, or a conflicting pq_pk on a duplicate (role, key)
                }
                proof {
                    assert(reg@[q as int] == row_of(ss@[i as int]));
                    let old_idx = idx;
                    idx = idx.push(q as int);
                    assert forall|k: int| #![trigger idx[k]] 0 <= k < i + 1 implies
                        0 <= idx[k] && idx[k] < reg@.len() && reg@[idx[k]] == row_of(ss@[k]) by {
                        if k < i { assert(idx[k] == old_idx[k]); }
                    }
                }
            }
            None => {
                if any_pk(&reg, e.pk) {
                    proof {
                        let j = choose|j: int| 0 <= j < reg@.len() && (#[trigger] reg@[j]).pk == ss@[i as int].pk;
                        let k = src[j];
                        assert(reg@[j] == row_of(ss@[k]));
                        assert(ss@[k].pk == ss@[i as int].pk);
                        assert(ss@[k].role != ss@[i as int].role);
                        assert(!set_valid(ss@));
                    }
                    return None; // one key under two roles
                }
                let row = RegRow { role: e.role, pk: e.pk, pq: e.pq };
                let ghost old_reg = reg@;
                reg.push(row);
                proof {
                    assert(reg@ == old_reg.push(row));
                    assert(row == row_of(ss@[i as int]));
                    assert(!has_role(old_reg, row.role));
                    lemma_push_role(old_reg, row, 0);
                    lemma_push_role(old_reg, row, 1);
                    lemma_push_role(old_reg, row, 2);
                    assert(reg@.len() == n_reg_roles(reg@));
                    assert forall|a: int, b: int| #![trigger reg@[a], reg@[b]] 0 <= a < reg@.len() && 0 <= b < reg@.len() && a != b
                        implies reg@[a].role != reg@[b].role && reg@[a].pk != reg@[b].pk by {
                        if a < old_reg.len() && b < old_reg.len() {
                            assert(reg@[a] == old_reg[a] && reg@[b] == old_reg[b]);
                        } else if a == old_reg.len() {
                            assert(reg@[b] == old_reg[b]);
                        } else {
                            assert(reg@[a] == old_reg[a]);
                        }
                    }
                    assert(reg_wf(reg@));
                    let old_idx = idx;
                    let old_src = src;
                    idx = idx.push(old_reg.len() as int);
                    src = src.push(i as int);
                    assert forall|k: int| #![trigger idx[k]] 0 <= k < i + 1 implies
                        0 <= idx[k] && idx[k] < reg@.len() && reg@[idx[k]] == row_of(ss@[k]) by {
                        if k < i {
                            assert(idx[k] == old_idx[k]);
                            assert(reg@[old_idx[k]] == old_reg[old_idx[k]]);
                        } else {
                            assert(idx[k] == old_reg.len());
                            assert(reg@[old_reg.len() as int] == row);
                        }
                    }
                    assert forall|j: int| #![trigger src[j]] 0 <= j < reg@.len() implies
                        0 <= src[j] && src[j] < i + 1 && reg@[j] == row_of(ss@[src[j]]) by {
                        if j < old_reg.len() {
                            assert(src[j] == old_src[j]);
                            assert(reg@[j] == old_reg[j]);
                        } else {
                            assert(src[j] == i);
                            assert(reg@[j] == row);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    proof {
        lemma_set_valid_from_reg(ss@, reg@, idx);
        assert forall|k: int| 0 <= k < ss@.len() implies
            exists|j: int| 0 <= j < reg@.len() && reg@[j] == row_of(#[trigger] ss@[k]) by {
            assert(reg@[idx[k]] == row_of(ss@[k]));
        }
        assert forall|j: int| 0 <= j < reg@.len() implies
            exists|k: int| 0 <= k < ss@.len() && #[trigger] reg@[j] == row_of(ss@[k]) by {
            assert(reg@[j] == row_of(ss@[src[j]]));
        }
    }
    Some(reg)
}

// lib.rs 1674-1678: t = safe_int(entry.t) restricted to 1..=3, else the share is refused.
pub fn threshold_t(t: Option<i64>) -> (r: Option<u8>)
    ensures
        r is Some <==> (t is Some && 1 <= t->Some_0 && t->Some_0 <= 3),
        r is Some ==> r->Some_0 as i64 == t->Some_0,
{
    match t {
        Some(v) => { if 1 <= v && v <= 3 { Some(v as u8) } else { None } }
        None => None,
    }
}

// lib.rs 1665-1755 verify_threshold_share (decision skeleton). Oracles: `pre_ok` = entry is an object with a string role,
// signer_set is an array, threshold_message decodes, signer_set_hash is Some, `share` is an object; `sig_ok` =
// verify_suite(...) over the bound message. share_pq: None = absent, Some(None) = present but not a string.
// r.1 = the PQ key handed to verify_suite (always the signer set's registered one).
pub fn share_decision(t: Option<i64>, pre_ok: bool, ss: &Vec<Entry>, role: u64, share_role: Option<u64>,
    share_pk: Option<u64>, share_alg: &AlgV, share_pq: Option<Option<u64>>, sig_ok: bool) -> (r: (bool, Option<u64>))
    ensures
        r.0 ==> (t is Some && 1 <= t->Some_0 && t->Some_0 <= 3),   // t outside {1,2,3} is never rescued
        r.0 ==> pre_ok && sig_ok && set_valid(ss@),
        r.0 ==> share_role == Some(role) && share_pk is Some && suite_of(*share_alg) is Some,
        r.0 ==> exists|k: int| 0 <= k < ss@.len() && (#[trigger] ss@[k]).role == role && ss@[k].pk == share_pk->Some_0
            && (ss@[k].pq is Some ==> suite_of(*share_alg) != Some(SUITE_ED))
            && (suite_of(*share_alg) != Some(SUITE_ED) ==> (ss@[k].pq is Some && r.1 == ss@[k].pq && ss@[k].pq->Some_0 != EMPTY_STR))
            && (share_pq is Some ==> (ss@[k].pq is Some && share_pq == Some(ss@[k].pq))),
{
    let tt = threshold_t(t);
    if tt.is_none() {
        return (false, None);
    }
    if !pre_ok {
        return (false, None);
    }
    let reg = match validate_signer_set(ss) { Some(r) => r, None => { return (false, None); } };
    match share_role {
        Some(sr) => { if sr != role { return (false, None); } }
        None => { return (false, None); }
    }
    let pk = match share_pk { Some(p) => p, None => { return (false, None); } };
    let q = match find_role(&reg, role) { Some(q) => q, None => { return (false, None); } };
    if reg[q].pk != pk {
        return (false, None);
    }
    let reg_pq = reg[q].pq;
    let role_has_pq = reg_pq.is_some();
    let suite = match resolve_sig_alg(share_alg) { Some(s) => s, None => { return (false, None); } };
    match share_pq {
        Some(sp) => match sp {
            Some(s) => match reg_pq {
                Some(rq) => { if s != rq { return (false, None); } }
                None => { return (false, None); }
            },
            None => { return (false, None); }
        },
        None => {}
    }
    if role_has_pq && suite == SUITE_ED {
        return (false, None); // R6-02: a PQ-registered role needs a PQ share
    }
    let mut vouched: Option<u64> = None;
    if suite != SUITE_ED {
        let rq = match reg_pq { Some(x) => x, None => { return (false, None); } };
        if rq == EMPTY_STR {
            return (false, None); // caller_vouched refuses ""
        }
        vouched = Some(rq);
    }
    proof {
        let k = choose|k: int| 0 <= k < ss@.len() && #[trigger] reg@[q as int] == row_of(ss@[k]);
        assert(ss@[k].role == role && ss@[k].pk == pk && ss@[k].pq == reg_pq);
    }
    (sig_ok, vouched)
}

// ===================== E. root-caveat enforcement (0.4.1) and caveat evaluation =====================
pub struct Cav { pub id: u64, pub env: bool, pub sat: bool }
// env <=> the caveat's `type` is "envelope"; sat = caveat_satisfied(cv, ctx) (lib.rs 2034-2103) for the fixed ctx,
// LEFT ARBITRARY: the theorems hold for every caveat semantics.

pub open spec fn is_first_env(cs: Seq<Cav>, j: int) -> bool {
    cs[j].env && forall|k: int| 0 <= k < j ==> !(#[trigger] cs[k]).env
}

fn first_env(cs: &Vec<Cav>) -> (r: Option<usize>)
    ensures
        r is Some ==> (r->Some_0 < cs@.len() && is_first_env(cs@, r->Some_0 as int)),
        r is None ==> forall|k: int| 0 <= k < cs@.len() ==> !(#[trigger] cs@[k]).env,
{
    let mut i: usize = 0;
    while i < cs.len()
        invariant 0 <= i <= cs.len(), forall|k: int| 0 <= k < i ==> !(#[trigger] cs@[k]).env,
        decreases cs.len() - i,
    {
        if cs[i].env {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn push_range(out: &mut Vec<Cav>, src: &Vec<Cav>, lo: usize, hi: usize)
    requires lo <= hi <= src.len(),
    ensures final(out)@ == old(out)@ + src@.subrange(lo as int, hi as int),
{
    let ghost o = out@;
    let mut k = lo;
    while k < hi
        invariant lo <= k <= hi, hi <= src.len(), o == old(out)@, out@ == o + src@.subrange(lo as int, k as int),
        decreases hi - k,
    {
        let c = Cav { id: src[k].id, env: src[k].env, sat: src[k].sat };
        out.push(c);
        proof {
            assert(c == src@[k as int]);
            assert(src@.subrange(lo as int, k as int + 1) =~= src@.subrange(lo as int, k as int).push(src@[k as int]));
            assert(out@ =~= o + src@.subrange(lo as int, k as int + 1));
        }
        k += 1;
    }
}

pub open spec fn removed(cs: Seq<Cav>, fe: Option<usize>) -> Seq<Cav> {
    match fe {
        Some(i) => cs.subrange(0, i as int) + cs.subrange(i as int + 1, cs.len() as int),
        None => cs,
    }
}
pub open spec fn appended(cs_len: int, leaf: Option<Seq<Cav>>) -> Seq<Cav> {
    match leaf {
        Some(l) => if l.len() >= cs_len { l.subrange(cs_len, l.len() as int) } else { Seq::empty() },
        None => Seq::empty(),
    }
}
pub open spec fn leaf_view(leaf: Option<Vec<Cav>>) -> Option<Seq<Cav>> {
    match leaf { Some(l) => Some(l@), None => None }
}

// lib.rs 1983-1996 policy_caveats. grant = the grant's caveat list (None: not an array -> returned as is, i.e. not a
// list); leaf = the last chain element's caveat list (None: chain not a non-empty array or caveats not an array).
// The grant's caveats WITHOUT its first envelope caveat, then the leaf caveats beyond the grant's length.
// r.1 is the index of the removed envelope caveat (ghost-like witness, not part of the shipped return value).
pub fn policy_caveats(grant: &Option<Vec<Cav>>, leaf: &Option<Vec<Cav>>) -> (r: (Option<Vec<Cav>>, Option<usize>))
    ensures
        grant is None ==> r.0 is None,
        grant is Some ==> (r.0 is Some
            && (r.1 is Some ==> (r.1->Some_0 < grant->Some_0@.len() && is_first_env(grant->Some_0@, r.1->Some_0 as int)))
            && (r.1 is None ==> forall|k: int| 0 <= k < grant->Some_0@.len() ==> !(#[trigger] grant->Some_0@[k]).env)
            && r.0->Some_0@ == removed(grant->Some_0@, r.1) + appended(grant->Some_0@.len() as int, leaf_view(*leaf))),
{
    let cs = match grant { Some(c) => c, None => { return (None, None); } };
    let mut out: Vec<Cav> = Vec::new();
    let fe = first_env(cs);
    match fe {
        Some(i) => {
            push_range(&mut out, cs, 0, i);
            push_range(&mut out, cs, i + 1, cs.len());
        }
        None => {
            push_range(&mut out, cs, 0, cs.len());
            proof { assert(cs@.subrange(0, cs@.len() as int) =~= cs@); assert(out@ =~= cs@); }
        }
    }
    let ghost base = out@;
    match leaf {
        Some(l) => {
            if l.len() >= cs.len() {
                push_range(&mut out, l, cs.len(), l.len());
            } else {
                proof { assert(out@ =~= base + Seq::<Cav>::empty()); }
            }
        }
        None => { proof { assert(out@ =~= base + Seq::<Cav>::empty()); } }
    }
    proof {
        assert(base =~= removed(cs@, fe));
    }
    (Some(out), fe)
}

pub open spec fn all_sat(s: Seq<Cav>) -> bool { forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).sat }

// lib.rs 2012-2024 evaluate_caveats. `list` None = not an array. r.1 = ids of the failed caveats.
pub fn evaluate_caveats(list: &Option<Vec<Cav>>) -> (r: (bool, Vec<u64>))
    ensures
        r.0 <==> (list is Some && all_sat(list->Some_0@)),
        list is Some ==> (r.0 <==> r.1@.len() == 0),
        list is Some ==> forall|j: int| 0 <= j < list->Some_0@.len() && !(#[trigger] list->Some_0@[j]).sat
            ==> r.1@.contains(list->Some_0@[j].id),   // every unsatisfied caveat is reported
{
    let l = match list { Some(l) => l, None => { let mut f = Vec::new(); f.push(u64::MAX); return (false, f); } };
    let mut failed: Vec<u64> = Vec::new();
    let mut i: usize = 0;
    while i < l.len()
        invariant
            0 <= i <= l.len(),
            (failed@.len() == 0) <==> forall|j: int| 0 <= j < i ==> (#[trigger] l@[j]).sat,
            forall|j: int| 0 <= j < i && !(#[trigger] l@[j]).sat ==> failed@.contains(l@[j].id),
        decreases l.len() - i,
    {
        if !l[i].sat {
            let ghost of = failed@;
            failed.push(l[i].id);
            proof {
                assert(failed@[failed@.len() - 1] == l@[i as int].id);
                assert forall|j: int| 0 <= j < i + 1 && !(#[trigger] l@[j]).sat implies failed@.contains(l@[j].id) by {
                    if j < i {
                        let z = choose|z: int| 0 <= z < of.len() && of[z] == l@[j].id;
                        assert(failed@[z] == of[z]);
                    } else {
                        assert(failed@[failed@.len() - 1] == l@[j].id);
                    }
                }
            }
        }
        i += 1;
    }
    (failed.len() == 0, failed)
}

// ROOT-CAVEAT ENFORCEMENT (0.4.1, commit d25f90f9): if the policy layer allows
// (evaluate_caveats(policy_caveats(grant, chain)) is ok), then EVERY grant (root) caveat except the first envelope
// caveat is satisfied, and every caveat a delegation hop appended (leaf beyond the grant's length) is satisfied.
// With the chain's prefix property (core_checks.rs caveats_extend: the grant's caveats are a prefix of the leaf's),
// every leaf caveat except that one envelope is satisfied.
pub fn policy_allows(grant: &Option<Vec<Cav>>, leaf: &Option<Vec<Cav>>) -> (r: bool)
    ensures
        r ==> grant is Some,
        r ==> forall|j: int| 0 <= j < grant->Some_0@.len() && !is_first_env(grant->Some_0@, j)
            ==> (#[trigger] grant->Some_0@[j]).sat,
        r ==> forall|j: int| 0 <= j < grant->Some_0@.len() && !grant->Some_0@[j].env ==> (#[trigger] grant->Some_0@[j]).sat,
        (r && leaf is Some && leaf->Some_0@.len() >= grant->Some_0@.len()) ==>
            forall|j: int| grant->Some_0@.len() <= j < leaf->Some_0@.len() ==> (#[trigger] leaf->Some_0@[j]).sat,
        (r && leaf is Some && leaf->Some_0@.len() >= grant->Some_0@.len()
            && leaf->Some_0@.subrange(0, grant->Some_0@.len() as int) == grant->Some_0@) ==>
            forall|j: int| 0 <= j < leaf->Some_0@.len() && !is_first_env(leaf->Some_0@, j) ==> (#[trigger] leaf->Some_0@[j]).sat,
{
    let (pc, fe) = policy_caveats(grant, leaf);
    let (ok, _failed) = evaluate_caveats(&pc);
    proof {
        if ok {
            let cs = grant->Some_0@;
            let out = pc->Some_0@;
            let rm = removed(cs, fe);
            let ap = appended(cs.len() as int, leaf_view(*leaf));
            assert(out == rm + ap);
            assert forall|j: int| 0 <= j < cs.len() && !is_first_env(cs, j) implies (#[trigger] cs[j]).sat by {
                match fe {
                    Some(f) => {
                        if j < f {
                            assert(out[j] == rm[j]);
                            assert(rm[j] == cs[j]);
                        } else if j > f {
                            assert(out[j - 1] == rm[j - 1]);
                            assert(rm[j - 1] == cs[j]);
                        } else {
                            assert(is_first_env(cs, j));
                        }
                    }
                    None => {
                        assert(out[j] == rm[j]);
                    }
                }
            }
            assert forall|j: int| 0 <= j < cs.len() && !cs[j].env implies (#[trigger] cs[j]).sat by {
                assert(!is_first_env(cs, j));
            }
            if leaf is Some && leaf->Some_0@.len() >= cs.len() {
                let l = leaf->Some_0@;
                assert(ap == l.subrange(cs.len() as int, l.len() as int));
                assert forall|j: int| cs.len() <= j < l.len() implies (#[trigger] l[j]).sat by {
                    assert(out[rm.len() + (j - cs.len())] == ap[j - cs.len()]);
                    assert(ap[j - cs.len()] == l[j]);
                }
                if l.subrange(0, cs.len() as int) == cs {
                    assert forall|j: int| 0 <= j < l.len() && !is_first_env(l, j) implies (#[trigger] l[j]).sat by {
                        if j < cs.len() {
                            assert(l[j] == cs[j]);
                            assert forall|k: int| 0 <= k < j implies l[k] == cs[k] by {
                                assert(l.subrange(0, cs.len() as int)[k] == l[k]);
                            }
                            assert(l.subrange(0, cs.len() as int)[j] == l[j]);
                            if is_first_env(cs, j) {
                                assert forall|k: int| 0 <= k < j implies !(#[trigger] l[k]).env by {
                                    assert(l.subrange(0, cs.len() as int)[k] == l[k]);
                                    assert(!cs[k].env);
                                }
                                assert(is_first_env(l, j));
                            }
                        }
                    }
                }
            }
        }
    }
    ok
}

// ===================== F. validity (copied from core_checks.rs, needed by the decision fold) =====================
pub const MAX_SAFE: i64 = 9_007_199_254_740_991;
pub const MAX_LIFETIME_MS: i64 = 3_600_000;
pub const MAX_SKEW_MS: i64 = 60_000;

pub open spec fn validity_ok(iat: int, exp: int, now: int) -> bool {
    exp > iat && exp - iat <= 3_600_000 && iat <= now + 60_000 && now <= exp
}

pub fn validity_code(iat: i64, exp: i64, now: i64) -> (r: u8)
    requires -MAX_SAFE <= iat <= MAX_SAFE, -MAX_SAFE <= exp <= MAX_SAFE,
    ensures (r == 0) <==> validity_ok(iat as int, exp as int, now as int),
{
    let skew = if now > i64::MAX - MAX_SKEW_MS { i64::MAX } else { now + MAX_SKEW_MS };
    if exp <= iat { 1 }
    else if exp - iat > MAX_LIFETIME_MS { 2 }
    else if iat > skew { 3 }
    else if now > exp { 4 }
    else { 0 }
}

// ===================== G. the check fold of verify_pcactn_core_policy =====================
// lib.rs 1796-1807 (`record`, "wire" recorded Ok) and 1924 (`allow = checks.values().all(..)`). The nine check names are distinct string
// literals (wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter), so the
// BTreeMap holds exactly one entry per recorded check: it is modelled as the sequence of results in recording order.
// `reason` is assigned only while empty and every `format!("{name}: {why}")` is non-empty: modelled as Option<index>.
pub fn fold_checks(res: &Vec<bool>) -> (r: (bool, Option<usize>))
    ensures
        r.0 <==> forall|k: int| 0 <= k < res@.len() ==> res@[k],
        r.1 is None <==> r.0,                                   // Deny always carries a reason
        r.1 is Some ==> (r.1->Some_0 < res@.len() && !res@[r.1->Some_0 as int]
            && forall|k: int| 0 <= k < r.1->Some_0 ==> res@[k]),  // ... and it is the FIRST failed check
{
    let mut reason: Option<usize> = None;
    let mut i: usize = 0;
    while i < res.len()
        invariant
            0 <= i <= res.len(),
            (reason is None) <==> forall|k: int| 0 <= k < i ==> res@[k],
            reason is Some ==> (reason->Some_0 < i && !res@[reason->Some_0 as int] && forall|k: int| 0 <= k < reason->Some_0 ==> res@[k]),
        decreases res.len() - i,
    {
        if !res[i] {
            if reason.is_none() {
                reason = Some(i);
            }
        }
        i += 1;
    }
    let mut allow = true;
    let mut j: usize = 0;
    while j < res.len()
        invariant 0 <= j <= res.len(), allow <==> forall|k: int| 0 <= k < j ==> res@[k],
        decreases res.len() - j,
    {
        if !res[j] {
            allow = false;
        }
        j += 1;
    }
    (allow, reason)
}

pub open spec fn opt0(o: Option<i64>) -> int { match o { Some(v) => v as int, None => 0 } }

// lib.rs 1785-1926 verify_pcactn_core_policy after validate_wire succeeded (the "wire" check is recorded Ok, 1807).
// Oracles: root_is_grant / walk_ok (see chain_check), plan_ok (plan inclusion), leaf_ok (leaf_signature_ok above).
// gref / root_id: grant_ref and cap_chain[0].id (None when absent / not a string / empty chain).
// Allow iff ALL nine checks pass, each with its exact meaning; a Deny always carries the first failing check.
pub fn core_decision(
    ver: Option<i64>, aud: &Option<Vec<u8>>, audience: &Vec<u8>,
    iat: Option<i64>, exp: Option<i64>, now: i64,
    hop_caveats: &Vec<usize>, root_is_grant: bool, walk_ok: bool,
    gref: Option<u64>, root_id: Option<u64>, plan_ok: bool, leaf_ok: bool, counter: Option<i64>,
) -> (r: (bool, Option<usize>))
    requires
        iat is Some ==> -MAX_SAFE <= iat->Some_0 <= MAX_SAFE,
        exp is Some ==> -MAX_SAFE <= exp->Some_0 <= MAX_SAFE,
    ensures
        r.0 <==> (
            ver == Some(2i64)
            && (aud is Some && aud->Some_0@ == audience@)
            && validity_ok(opt0(iat), opt0(exp), now as int)
            && (1 <= hop_caveats@.len() <= 16 && !caps_exceeded(hop_caveats@) && root_is_grant && walk_ok)
            && (gref is Some && gref->Some_0 != EMPTY_STR && root_id == gref)
            && plan_ok && leaf_ok
            && (counter is Some && counter->Some_0 >= 0)),
        r.1 is None <==> r.0,
        r.1 is Some ==> r.1->Some_0 < 9,
{
    let c_ver = match ver { Some(v) => v == 2, None => false };
    let c_aud = aud_check(aud, audience);
    let i0 = match iat { Some(v) => v, None => 0 };
    let e0 = match exp { Some(v) => v, None => 0 };
    let c_val = validity_code(i0, e0, now) == 0;
    let c_chain = chain_check(hop_caveats, root_is_grant, walk_ok);
    let c_gref = match gref {
        Some(g) => match root_id { Some(rid) => g != EMPTY_STR && g == rid, None => false },
        None => false,
    };
    let c_ctr = match counter { Some(c) => c >= 0, None => false };
    let mut res: Vec<bool> = Vec::new();
    res.push(true);      // wire
    res.push(c_ver);     // version
    res.push(c_aud);     // audience
    res.push(c_val);     // validity
    res.push(c_chain);   // chain
    res.push(c_gref);    // grant_ref_bound
    res.push(plan_ok);   // plan_inclusion
    res.push(leaf_ok);   // leaf_signature
    res.push(c_ctr);     // counter
    let r = fold_checks(&res);
    proof {
        assert(res@.len() == 9);
        assert(res@[0] == true && res@[1] == c_ver && res@[2] == c_aud && res@[3] == c_val && res@[4] == c_chain
            && res@[5] == c_gref && res@[6] == plan_ok && res@[7] == leaf_ok && res@[8] == c_ctr);
        let conj = c_ver && c_aud && c_val && c_chain && c_gref && plan_ok && leaf_ok && c_ctr;
        if conj {
            assert forall|k: int| 0 <= k < res@.len() implies res@[k] by {
                assert(k == 0 || k == 1 || k == 2 || k == 3 || k == 4 || k == 5 || k == 6 || k == 7 || k == 8);
            }
        }
        assert(r.0 <==> conj);
    }
    r
}

fn main() {}

} // verus!
