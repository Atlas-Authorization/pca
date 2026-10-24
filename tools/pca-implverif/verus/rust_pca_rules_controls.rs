// NEGATIVE CONTROLS for rust_pca_rules.rs: each `control_*` function is a MUTATED copy of a rule from that file, with the
// SAME contract (ensures) as the proved original. Verus MUST REJECT every control_* function; this file is expected to
// report exactly one error per control (and to verify the unmutated helpers). A control that verified would mean the
// contract does not pin down the rule. Line numbers refer to sdks/rust-pca/src/lib.rs (commit f0991ade).
use vstd::prelude::*;

verus! {

pub const EMPTY_STR: u64 = 0;
pub const NAME_ED25519: u64 = 1;
pub const NAME_MLDSA65: u64 = 2;
pub const NAME_HYBRID: u64 = 3;
pub const NAME_NONSTR: u64 = 4;
pub const SUITE_ED: u8 = 0;
pub const SUITE_ML: u8 = 1;
pub const SUITE_HY: u8 = 2;

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
pub open spec fn alg_name(a: AlgV) -> u64 {
    match a { AlgV::Absent => NAME_ED25519, AlgV::Str(s) => s, AlgV::NonStr => NAME_NONSTR }
}
pub uninterp spec fn commit(pk: u64) -> u64;
pub open spec fn has_trusted(t: Option<u64>) -> bool { t is Some && t->Some_0 != EMPTY_STR }

// C1 (lib.rs 1240, 1850): depth cap off by one (`> 17`): a 17-hop chain would pass.
pub fn control_chain_len_gate(len: usize) -> (r: u8)
    ensures
        (r == 0) <==> (1 <= len && len <= 16),
        len == 0 ==> r == 1,
        len > 16 ==> r == 2,
{
    if len == 0 { 1 } else if len > 17 { 2 } else { 0 }
}

// C2 (lib.rs 1676): t range widened to 0..=3.
pub fn control_threshold_t(t: Option<i64>) -> (r: Option<u8>)
    ensures
        r is Some <==> (t is Some && 1 <= t->Some_0 && t->Some_0 <= 3),
        r is Some ==> r->Some_0 as i64 == t->Some_0,
{
    match t {
        Some(v) => { if 0 <= v && v <= 3 { Some(v as u8) } else { None } }
        None => None,
    }
}

// C3 (lib.rs 1088-1096): an EMPTY present policy treated as "no policy".
pub fn control_suite_allowed(alg: &AlgV, has_policy: bool, allowed: &Vec<u64>) -> (r: bool)
    ensures
        r <==> (!has_policy || allowed@.contains(alg_name(*alg))),
        has_policy && allowed@.len() == 0 ==> !r,
{
    if !has_policy || allowed.len() == 0 {
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

// C4 (lib.rs 1100-1108): PQ binding accepted when the signer committed no holder_pq.
pub fn control_pq_binding_ok(alg: &AlgV, pq_pk: Option<u64>, pk_commit: u64, committed: Option<u64>) -> (r: bool)
    requires pq_pk is Some ==> pk_commit == commit(pq_pk->Some_0),
    ensures r <==> (needs_pq(*alg) ==> (pq_pk is Some && committed is Some && commit(pq_pk->Some_0) == committed->Some_0)),
{
    let su = match *alg {
        AlgV::Absent => Some(SUITE_ED),
        AlgV::Str(s) => if s == NAME_ED25519 { Some(SUITE_ED) } else if s == NAME_MLDSA65 { Some(SUITE_ML) }
                        else if s == NAME_HYBRID { Some(SUITE_HY) } else { None },
        AlgV::NonStr => None,
    };
    match su {
        Some(su) => {
            if su != SUITE_ED {
                match pq_pk {
                    Some(_) => match committed { Some(c) => pk_commit == c, None => true },
                    None => false,
                }
            } else {
                true
            }
        }
        None => true,
    }
}

// C5 (lib.rs 1012-1014): a pin that differs from the artifact's key falls through to the holder_pq commitment.
pub fn control_resolve_pq_key(pin: Option<u64>, artifact_pk: Option<u64>, pk_commit: u64, holder_pq: Option<u64>, trusted: Option<u64>) -> (r: Option<u64>)
    requires artifact_pk is Some ==> pk_commit == commit(artifact_pk->Some_0),
    ensures
        has_trusted(trusted) ==> r == trusted,
        (r is Some && !has_trusted(trusted)) ==> (
            artifact_pk == r && r->Some_0 != EMPTY_STR
            && (pin is Some ==> pin == r)
            && (pin is None ==> holder_pq == Some(commit(r->Some_0)))),
        (!has_trusted(trusted) && pin is Some && pin != artifact_pk) ==> r is None,
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
        Some(p) => { if p == pk { return Some(pk); } }
        None => {}
    }
    match holder_pq {
        Some(c) => { if pk_commit == c { Some(pk) } else { None } }
        None => None,
    }
}

// C6 (lib.rs 1372-1375 + 1819): the wire rule dropped, so an empty verifier audience matches an empty aud.
pub fn control_audience_accepts(aud: &Option<Vec<u8>>, audience: &Vec<u8>) -> (r: bool)
    ensures
        r <==> (aud is Some && aud->Some_0@ == audience@ && 0 < audience@.len() && audience@.len() <= 256),
        aud is None ==> !r,
        audience@.len() == 0 ==> !r,
{
    match aud {
        Some(a) => {
            if a.len() != audience.len() { return false; }
            let mut i: usize = 0;
            while i < a.len()
                invariant a.len() == audience.len(), 0 <= i <= a.len(), forall|k: int| 0 <= k < i ==> a@[k] == audience@[k],
                decreases a.len() - i,
            {
                if a[i] != audience[i] { return false; }
                i += 1;
            }
            proof { assert(a@ =~= audience@); }
            true
        }
        None => false,
    }
}

// C7 (lib.rs 1796-1806): `reason` overwritten by every failure (reports the LAST failed check, not the first).
pub fn control_fold_checks(res: &Vec<bool>) -> (r: (bool, Option<usize>))
    ensures
        r.0 <==> forall|k: int| 0 <= k < res@.len() ==> res@[k],
        r.1 is None <==> r.0,
        r.1 is Some ==> (r.1->Some_0 < res@.len() && !res@[r.1->Some_0 as int]
            && forall|k: int| 0 <= k < r.1->Some_0 ==> res@[k]),
{
    let mut reason: Option<usize> = None;
    let mut allow = true;
    let mut i: usize = 0;
    while i < res.len()
        invariant
            0 <= i <= res.len(),
            allow <==> forall|k: int| 0 <= k < i ==> res@[k],
            (reason is None) <==> allow,
            reason is Some ==> (reason->Some_0 < i && !res@[reason->Some_0 as int]),
        decreases res.len() - i,
    {
        if !res[i] {
            reason = Some(i);
            allow = false;
        }
        i += 1;
    }
    (allow, reason)
}

// C8 (lib.rs 1983-1996, the PRE-0.4.1 behaviour): only the caveats the hops appended are evaluated, the root grant's own
// caveats are not. The root-caveat enforcement statement proved for policy_allows must fail.
pub struct Cav { pub id: u64, pub env: bool, pub sat: bool }
pub open spec fn all_sat(s: Seq<Cav>) -> bool { forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).sat }

pub fn control_policy_pre041(cs: &Vec<Cav>, leaf: &Vec<Cav>) -> (r: Vec<Cav>)
    requires leaf@.len() >= cs@.len(),
    ensures all_sat(r@) ==> forall|j: int| 0 <= j < cs@.len() && !cs@[j].env ==> (#[trigger] cs@[j]).sat,
{
    let mut out: Vec<Cav> = Vec::new();
    let mut k = cs.len();
    while k < leaf.len()
        invariant cs@.len() <= k <= leaf@.len(),
        decreases leaf.len() - k,
    {
        out.push(Cav { id: leaf[k].id, env: leaf[k].env, sat: leaf[k].sat });
        k += 1;
    }
    out
}

// C9 (lib.rs 1644-1646): validate_signer_set WITHOUT the "one role per key" check. With the contract part
// "r is Some ==> distinct keys" this must fail.
pub struct RegRow { pub role: u64, pub pk: u64 }
pub fn control_signer_set_no_key_check(roles: &Vec<u64>, pks: &Vec<u64>) -> (r: Option<Vec<RegRow>>)
    requires roles.len() == pks.len(),
    ensures r is Some ==> forall|a: int, b: int| #![trigger r->Some_0@[a], r->Some_0@[b]]
        0 <= a < r->Some_0@.len() && 0 <= b < r->Some_0@.len() && a != b ==> r->Some_0@[a].pk != r->Some_0@[b].pk,
{
    let mut reg: Vec<RegRow> = Vec::new();
    let mut i: usize = 0;
    while i < roles.len()
        invariant 0 <= i <= roles.len(), roles.len() == pks.len(),
        decreases roles.len() - i,
    {
        let role = roles[i];
        if role >= 3 { return None; }
        let mut found = false;
        let mut q: usize = 0;
        while q < reg.len()
            invariant 0 <= q <= reg.len(),
            decreases reg.len() - q,
        {
            if reg[q].role == role { found = true; }
            q += 1;
        }
        if !found {
            reg.push(RegRow { role, pk: pks[i] });
        }
        i += 1;
    }
    Some(reg)
}

fn main() {}

} // verus!
