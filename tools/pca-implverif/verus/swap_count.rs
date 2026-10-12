// Transposition lemma used by the decomposed SampleChallenge proof (LESS fork tests/formal/harness_sc_contract.c, sc_frame):
// exchanging two entries of a byte sequence preserves (a) the number of non-zero entries and (b) "every entry <= m".
// Together with the CBMC frame obligation (one real shuffle iteration exchanges exactly entries p and pos and nothing else) this
// gives the shuffle-loop invariant step without a global popcount in SAT. The link between `cnt` below and the C loop that counts
// non-zero entries (sc_IB) is by inspection: both count indices k < T with fws[k] != 0.
use vstd::prelude::*;
verus! {

spec fn nz(x: u8) -> nat { if x != 0 { 1 } else { 0 } }

spec fn cnt(s: Seq<u8>) -> nat decreases s.len() {
    if s.len() == 0 { 0 } else { cnt(s.drop_last()) + nz(s.last()) }
}

proof fn lemma_update(s: Seq<u8>, i: int, v: u8)
    requires 0 <= i < s.len(),
    ensures cnt(s.update(i, v)) + nz(s[i]) == cnt(s) + nz(v),
    decreases s.len(),
{
    let t = s.update(i, v);
    if i == s.len() - 1 {
        assert(t.drop_last() =~= s.drop_last());
    } else {
        lemma_update(s.drop_last(), i, v);
        assert(t.drop_last() =~= s.drop_last().update(i, v));
    }
}

/// count and range are invariant under exchanging entries i and j
proof fn lemma_swap(s: Seq<u8>, i: int, j: int, m: u8)
    requires 0 <= i < s.len(), 0 <= j < s.len(),
    ensures
        cnt(s.update(i, s[j]).update(j, s[i])) == cnt(s),
        (forall|k: int| 0 <= k < s.len() ==> s[k] <= m) ==>
            (forall|k: int| 0 <= k < s.len() ==> #[trigger] s.update(i, s[j]).update(j, s[i])[k] <= m),
{
    let t = s.update(i, s[j]);
    lemma_update(s, i, s[j]);
    lemma_update(t, j, s[i]);
    if i == j {
        assert(t =~= s);
    }
}

fn main() {}
}
