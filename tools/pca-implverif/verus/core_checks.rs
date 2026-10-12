// Verus proofs (ALL inputs, unbounded) of the decision-procedure cores of the PCA verifiers.
// IMPORTANT SCOPE: these are verified Verus-subset TRANSLITERATIONS of the corresponding fragments of
// sdks/rust-pca/src/lib.rs (validity, verify_chain caveat loop) and packages/pca/src/threshold.ts (verifyThreshold
// counting). They are not the shipping code; the link between the translation and the shipping code is by
// line-by-line correspondence (documented in docs/pca/security/implementation-verification.md) plus the
// conformance corpus, not by a machine-checked refinement.
use vstd::prelude::*;

verus! {

// ===================== A. validity (time comparisons) =====================
// lib.rs: iat/exp come from safe_int() => |x| <= MAX_SAFE (proved for every i64/u64 JSON integer by Kani
// harnesses safe_int_i64_full_range / safe_int_u64_full_range); `now` is any i64.
pub const MAX_SAFE: i64 = 9_007_199_254_740_991;
pub const MAX_LIFETIME_MS: i64 = 3_600_000;
pub const MAX_SKEW_MS: i64 = 60_000;

pub open spec fn validity_ok(iat: int, exp: int, now: int) -> bool {
    exp > iat && exp - iat <= 3_600_000 && iat <= now + 60_000 && now <= exp
}

// Rust: now.saturating_add(MAX_SKEW_MS)
pub fn sat_add_skew(now: i64) -> (r: i64)
    ensures r as int == if now as int + 60_000 > i64::MAX as int { i64::MAX as int } else { now as int + 60_000 },
{
    if now > i64::MAX - MAX_SKEW_MS { i64::MAX } else { now + MAX_SKEW_MS }
}

// codes: 0 = Ok, 1 = exp<=iat, 2 = lifetime, 3 = future iat, 4 = expired -- same order as lib.rs.
pub fn validity_code(iat: i64, exp: i64, now: i64) -> (r: u8)
    requires -MAX_SAFE <= iat <= MAX_SAFE, -MAX_SAFE <= exp <= MAX_SAFE,
    ensures
        (r == 0) <==> validity_ok(iat as int, exp as int, now as int),
        r <= 4,
        r == 1 ==> exp <= iat,
{
    if exp <= iat { 1 }
    else if exp - iat > MAX_LIFETIME_MS { 2 }
    else if iat > sat_add_skew(now) { 3 }
    else if now > exp { 4 }
    else { 0 }
}

// ===================== B. chain attenuation =====================
// A capability caveat is identified by hash_canonical(caveat) (collision resistance assumed, as in the
// protocol model); `sat(c, a)` = "action a satisfies caveat c" is left UNINTERPRETED, so the theorem holds for
// every possible caveat semantics.
pub uninterp spec fn sat(c: u64, a: int) -> bool;

pub open spec fn allowed(cv: Seq<u64>, a: int) -> bool {
    forall|j: int| 0 <= j < cv.len() ==> sat(cv[j], a)
}

pub open spec fn is_prefix(pc: Seq<u64>, cc: Seq<u64>) -> bool {
    pc.len() <= cc.len() && pc =~= cc.subrange(0, pc.len() as int)
}

// lib.rs verify_chain: `cc.len() < pc.len()` => Err; then for j in 0..pc.len(): hash(cc[j]) != hash(pc[j]) => Err.
pub fn caveats_extend(pc: &Vec<u64>, cc: &Vec<u64>) -> (r: bool)
    ensures r <==> is_prefix(pc@, cc@),
{
    if cc.len() < pc.len() {
        return false;
    }
    let mut j: usize = 0;
    while j < pc.len()
        invariant
            0 <= j <= pc.len(), pc.len() <= cc.len(),
            forall|k: int| 0 <= k < j ==> pc@[k] == cc@[k],
        decreases pc.len() - j,
    {
        if cc[j] != pc[j] {
            proof { assert(!(pc@ =~= cc@.subrange(0, pc@.len() as int))) by {
                assert(cc@.subrange(0, pc@.len() as int)[j as int] == cc@[j as int]); } }
            return false;
        }
        j += 1;
    }
    proof { assert(pc@ =~= cc@.subrange(0, pc@.len() as int)); }
    true
}

pub open spec fn chain_ok(chain: Seq<Seq<u64>>) -> bool {
    forall|i: int| 1 <= i < chain.len() ==> #[trigger] is_prefix(chain[i - 1], chain[i])
}

// One hop: anything the child allows, the parent allows (child authority subset of parent authority).
pub proof fn hop_attenuates(pc: Seq<u64>, cc: Seq<u64>, a: int)
    requires is_prefix(pc, cc), allowed(cc, a),
    ensures allowed(pc, a),
{
    assert forall|j: int| 0 <= j < pc.len() implies sat(pc[j], a) by {
        assert(cc.subrange(0, pc.len() as int)[j] == pc[j]);
        assert(cc[j] == pc[j]);
    }
}

// Whole chain, ANY length: whatever the leaf hop allows, every ancestor (hence the root) allows.
pub proof fn chain_attenuates(chain: Seq<Seq<u64>>, a: int, i: int)
    requires chain_ok(chain), 0 <= i < chain.len(), allowed(chain[chain.len() - 1], a),
    ensures allowed(chain[i], a),
    decreases chain.len() - i,
{
    if i < chain.len() - 1 {
        chain_attenuates(chain, a, i + 1);
        assert(is_prefix(chain[(i + 1) - 1], chain[i + 1]));
        hop_attenuates(chain[i], chain[i + 1], a);
    }
}

// The loop of verify_chain over hops 1..len.
pub fn chain_caveats_ok(chain: &Vec<Vec<u64>>) -> (r: bool)
    ensures r <==> chain_ok(chain@.map_values(|v: Vec<u64>| v@)),
{
    let ghost m = chain@.map_values(|v: Vec<u64>| v@);
    let mut i: usize = 1;
    while i < chain.len()
        invariant
            1 <= i || chain.len() == 0, i <= chain.len() || chain.len() == 0,
            m == chain@.map_values(|v: Vec<u64>| v@),
            forall|k: int| 1 <= k < i ==> #[trigger] is_prefix(m[k - 1], m[k]),
        decreases chain.len() - i,
    {
        if !caveats_extend(&chain[i - 1], &chain[i]) {
            proof { assert(!is_prefix(m[i as int - 1], m[i as int])); }
            return false;
        }
        i += 1;
    }
    true
}

// ===================== C. threshold: distinct-role counting =====================
// packages/pca/src/threshold.ts verifyThreshold: a share counts iff (its key is not already counted) && role is
// registered && share.publicKey == registered key for that role && its signature verifies; count = |validKeys|.
// Registry invariant enforced earlier in verifyThreshold (else `fail`): at most one key per role AND a key under
// at most one role => role -> key is INJECTIVE. Roles: 0=agent 1=guardian 2=principal.
pub struct Share { pub role: u8, pub key: u64, pub sig_ok: bool }   // sig_ok = verifyWithSuite(...) result

pub open spec fn counts(reg: Seq<Option<u64>>, s: Share) -> bool {
    s.role < 3 && s.sig_ok && reg[s.role as int] == Some(s.key)
}
pub open spec fn registry_ok(reg: Seq<Option<u64>>) -> bool {
    reg.len() == 3 &&
    forall|r1: int, r2: int| 0 <= r1 < 3 && 0 <= r2 < 3 && r1 != r2 && reg[r1] is Some ==> reg[r1] != reg[r2]
}
pub open spec fn role_counted(reg: Seq<Option<u64>>, shares: Seq<Share>, r: int) -> bool {
    exists|j: int| 0 <= j < shares.len() && counts(reg, #[trigger] shares[j]) && shares[j].role as int == r
}
pub open spec fn b2i(b: bool) -> int { if b { 1int } else { 0int } }
pub open spec fn n_roles(reg: Seq<Option<u64>>, shares: Seq<Share>) -> int {
    b2i(role_counted(reg, shares, 0)) + b2i(role_counted(reg, shares, 1)) + b2i(role_counted(reg, shares, 2))
}
pub open spec fn key_counted(reg: Seq<Option<u64>>, shares: Seq<Share>, k: u64) -> bool {
    exists|j: int| 0 <= j < shares.len() && counts(reg, #[trigger] shares[j]) && shares[j].key == k
}

proof fn lemma_push_contains(s: Seq<u64>, v: u64, x: u64)
    ensures s.push(v).contains(x) <==> (s.contains(x) || x == v),
{
    if s.push(v).contains(x) {
        let z = choose|z: int| 0 <= z < s.push(v).len() && s.push(v)[z] == x;
        if z < s.len() { assert(s[z] == x); }
    }
    if s.contains(x) { let z = choose|z: int| 0 <= z < s.len() && s[z] == x; assert(s.push(v)[z] == x); }
    if x == v { assert(s.push(v)[s.len() as int] == x); }
}

proof fn lemma_step(reg: Seq<Option<u64>>, shares: Seq<Share>, i: int, r: int)
    requires 0 <= i < shares.len(), reg.len() == 3, 0 <= r < 3,
    ensures
        role_counted(reg, shares.subrange(0, i + 1), r)
            <==> (role_counted(reg, shares.subrange(0, i), r) || (counts(reg, shares[i]) && shares[i].role as int == r)),
        key_counted(reg, shares.subrange(0, i + 1), shares[i].key)
            || !counts(reg, shares[i]),
{
    let n = shares.subrange(0, i + 1);
    let o = shares.subrange(0, i);
    if role_counted(reg, n, r) {
        let j = choose|j: int| 0 <= j < n.len() && counts(reg, n[j]) && n[j].role as int == r;
        if j < i { assert(o[j] == shares[j]); assert(role_counted(reg, o, r)); }
        else { assert(j == i); }
    }
    if role_counted(reg, o, r) {
        let j = choose|j: int| 0 <= j < o.len() && counts(reg, o[j]) && o[j].role as int == r;
        assert(n[j] == o[j]);
        assert(role_counted(reg, n, r));
    }
    if counts(reg, shares[i]) && shares[i].role as int == r {
        assert(n[i] == shares[i]);
        assert(role_counted(reg, n, r));
    }
    if counts(reg, shares[i]) { assert(n[i] == shares[i]); assert(key_counted(reg, n, shares[i].key)); }
}

// exec: validKeys as a Vec<u64> used as a set (the TS `Set<string>`), over an ARBITRARY-length share list.
pub fn count_valid(reg: &Vec<Option<u64>>, shares: &Vec<Share>) -> (count: usize)
    requires registry_ok(reg@),
    ensures
        count as int == n_roles(reg@, shares@),   // exactly the number of DISTINCT roles with a valid registered share
        count <= 3,                               // duplicates / replays can never inflate the count
{
    let mut valid: Vec<u64> = Vec::new();
    let mut i: usize = 0;
    while i < shares.len()
        invariant
            0 <= i <= shares.len(), registry_ok(reg@),
            valid@.no_duplicates(),
            valid@.len() as int == n_roles(reg@, shares@.subrange(0, i as int)),
            forall|r: int| 0 <= r < 3 ==> (role_counted(reg@, shares@.subrange(0, i as int), r)
                <==> (reg@[r] is Some && valid@.contains(reg@[r]->Some_0))),
            forall|k: int| 0 <= k < valid@.len() ==> exists|r: int| 0 <= r < 3 && reg@[r] == Some(#[trigger] valid@[k]),
        decreases shares.len() - i,
    {
        let s = &shares[i];
        let ghost old_valid = valid@;
        if s.role < 3 && s.sig_ok && reg[s.role as usize] == Some(s.key) {
            let mut already = false;
            let mut q: usize = 0;
            while q < valid.len()
                invariant 0 <= q <= valid.len(), already <==> exists|z: int| 0 <= z < q && valid@[z] == s.key,
                decreases valid.len() - q,
            {
                if valid[q] == s.key { already = true; }
                q += 1;
            }
            if !already {
                valid.push(s.key);
            }
            proof {
                let ro = s.role as int;
                assert(counts(reg@, *s));
                assert(shares@[i as int] == *s);
                // contains() <=> exists index
                assert(old_valid.contains(s.key) <==> already) by {
                    if old_valid.contains(s.key) { let z = choose|z: int| 0 <= z < old_valid.len() && old_valid[z] == s.key; assert(already); }
                    if already { let z = choose|z: int| 0 <= z < old_valid.len() && old_valid[z] == s.key; assert(old_valid.contains(s.key)); }
                }
                let o = shares@.subrange(0, i as int);
                let n = shares@.subrange(0, i as int + 1);
                lemma_step(reg@, shares@, i as int, ro);
                if !already {
                    assert(valid@ =~= old_valid.push(s.key));
                    assert forall|x: u64| valid@.contains(x) <==> (old_valid.contains(x) || x == s.key) by { lemma_push_contains(old_valid, s.key, x); }
                    // role ro was not counted before: else reg[ro]=Some(s.key) would be in old_valid
                    assert(!role_counted(reg@, o, ro));
                    assert(role_counted(reg@, n, ro));
                    // other roles unchanged; adding exactly one role
                    assert(n_roles(reg@, n) == n_roles(reg@, o) + 1) by {
                        assert forall|r: int| 0 <= r < 3 implies (role_counted(reg@, n, r) == (role_counted(reg@, o, r) || r == ro)) by { lemma_step(reg@, shares@, i as int, r); }
                    }
                    assert forall|r: int| 0 <= r < 3 implies (role_counted(reg@, n, r) <==> (reg@[r] is Some && valid@.contains(reg@[r]->Some_0))) by {
                        lemma_step(reg@, shares@, i as int, r);
                        if r != ro && reg@[r] is Some && valid@.contains(reg@[r]->Some_0) {
                            // new element is s.key = reg[ro]; reg[r] == s.key would contradict injectivity
                            assert(reg@[r]->Some_0 != s.key);
                            assert(old_valid.contains(reg@[r]->Some_0));
                        }
                    }
                    assert forall|k: int| 0 <= k < valid@.len() implies exists|r: int| 0 <= r < 3 && reg@[r] == Some(#[trigger] valid@[k]) by {
                        if k == valid@.len() - 1 { assert(reg@[ro] == Some(valid@[k])); }
                    }
                } else {
                    // already counted: key in old_valid => its role is exactly ro (injectivity) => already role_counted
                    assert(role_counted(reg@, o, ro)) by { assert(old_valid.contains(reg@[ro]->Some_0)); }
                    assert forall|r: int| 0 <= r < 3 implies (role_counted(reg@, n, r) == role_counted(reg@, o, r)) by { lemma_step(reg@, shares@, i as int, r); }
                    assert(n_roles(reg@, n) == n_roles(reg@, o));
                }
            }
        } else {
            proof {
                let o = shares@.subrange(0, i as int);
                let n = shares@.subrange(0, i as int + 1);
                assert(!counts(reg@, shares@[i as int]));
                assert forall|r: int| 0 <= r < 3 implies (role_counted(reg@, n, r) == role_counted(reg@, o, r)) by { lemma_step(reg@, shares@, i as int, r); }
                assert(n_roles(reg@, n) == n_roles(reg@, o));
            }
        }
        i += 1;
    }
    proof { assert(shares@.subrange(0, shares@.len() as int) =~= shares@); }
    valid.len()
}

fn main() {}

} // verus!
