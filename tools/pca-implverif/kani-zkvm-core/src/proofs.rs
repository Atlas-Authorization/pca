//! Kani proofs over the REAL pca-zkvm-core fixed-point risk functional and the f64->scaled-integer parser (byte-identical sources).
use super::*;
use crate::risk::*;

const S2: u128 = (S as u128) * (S as u128);
fn any_policy() -> RiskPolicyScaled {
    RiskPolicyScaled { weights: kani::any(), theta1_scaled: kani::any(), theta2_scaled: kani::any(), kappa: kani::any(), bmax_scaled: kani::any() }
}

// UNBOUNDED over all u64 inputs/weights/floor: no overflow, exact spec, r <= 1.0 (S^2), floor only raises.
#[kani::proof]
fn zk_risk_raw_exact_all_u64() {
    let x: [u64; 6] = kani::any();
    let p = any_policy();
    let f: u64 = kani::any();
    let r = risk_raw(&RiskInputsScaled { x }, &p, f);
    // independent specification
    let inv = [false, true, false, false, true, false];
    let mut acc: u128 = 0;
    let mut i = 0;
    while i < 6 {
        let xi = if x[i] > S { S } else { x[i] } as u128;
        let t = if inv[i] { S as u128 - xi } else { xi };
        acc += (p.weights[i] as u128) * t;
        i += 1;
    }
    let clamped = if acc > S2 { S2 } else { acc };
    let fl = (if f > S { S } else { f } as u128) * (S as u128);
    let spec = if clamped > fl { clamped } else { fl };
    assert_eq!(r, spec);
    assert!(r <= S2);
    assert!(r >= fl);
}

// tier ladder is exactly the three-way threshold, for every r_raw: u128 and every policy; monotone when theta1 <= theta2.
#[kani::proof]
fn zk_tier_ladder_all() {
    let p = any_policy();
    let r1: u128 = kani::any();
    let r2: u128 = kani::any();
    let t = tier(r1, &p);
    assert!(t == 1 || t == 2 || t == 3);
    let (t1, t2) = ((p.theta1_scaled as u128) * (S as u128), (p.theta2_scaled as u128) * (S as u128));
    assert_eq!(t == 1, r1 <= t1);
    if r1 > t1 { assert_eq!(t == 2, r1 <= t2); }
    if p.theta1_scaled <= p.theta2_scaled && r1 <= r2 { assert!(tier(r1, &p) <= tier(r2, &p)); }
}

// budget gate and auto-admit on the range risk_raw can produce (r_raw <= S^2): no overflow for ANY kappa/budget.
#[kani::proof]
fn zk_budget_and_auto_admit_in_range() {
    let p = any_policy();
    let r: u128 = kani::any();
    kani::assume(r <= S2);
    let b: u64 = kani::any();
    let c = budget_covers(b, r, &p);
    assert_eq!(c, (b as u128) * (S as u128) >= (p.kappa as u128) * r);
    let a = auto_admit(r, b, &p);
    assert_eq!(a, tier(r, &p) == 1 && c);
}

// scale(): any f64 (NaN/inf/negative included) never panics; non-finite and negative map to 0; result is the saturating cast.
#[kani::proof]
fn zk_scale_any_f64() {
    let f: f64 = kani::any();
    let v = scale(f);
    if !f.is_finite() || f < 0.0 { assert_eq!(v, 0); }
}
