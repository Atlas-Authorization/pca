//! Kani proofs over the REAL folding-pca native helpers (byte-identical source). The proof-byte decoder is bincode + nova-snark
//! (dependencies); folding-pca owns no decoder of its own. Field-arithmetic helpers (Scalar) use x86_64 inline assembly in
//! halo2curves, which Kani cannot model, so only the integer-side budget pre-check is proved.
use super::*;

// within_budget on every history of up to 3 steps with ANY u64 digests/costs: equals the exact u128 sum test (no overflow possible:
// each term < 2^64, so a sum of fewer than 2^64 terms fits u128; the bound 3 is the loop-unwinding bound only).
#[kani::proof]
#[kani::unwind(6)]
fn fold_within_budget_n3_any_u64() {
    let n: usize = kani::any(); kani::assume(n <= 3);
    let a: [ActionStep; 3] = [
        ActionStep { action_digest: kani::any(), cost: kani::any() },
        ActionStep { action_digest: kani::any(), cost: kani::any() },
        ActionStep { action_digest: kani::any(), cost: kani::any() },
    ];
    let mut spec: u128 = 0; let mut i = 0; while i < n { spec += a[i].cost as u128; i += 1; }
    assert_eq!(within_budget(&a[..n]), spec <= B_MAX as u128);
}
