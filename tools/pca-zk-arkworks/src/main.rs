//! Independent Groth16 verifier for snarkjs proofs. It shares no code with snarkjs, so a disagreement between the two on
//! any input is a finding in one of them.
//!
//!   pca-zk-arkworks verify bn254|bls12-381 <case.json>      case = {"vkey": ..., "proof": ..., "publicSignals": [...]}
//!
//! Prints one JSON line {"valid":bool,"reason":str} and exits 0 (valid), 1 (rejected) or 2 (usage). Everything is strict:
//! decimal strings must be canonical and below the field modulus, every curve point must be on the curve AND in the
//! prime-order subgroup (G1 and G2, in the key and in the proof), affine points need z = 1 (G2 z = [1,0]), and the number
//! of public signals must equal the key's. Anything else is a rejection, never a panic.
use num_bigint::BigUint;
use serde_json::Value;

type R<T> = Result<T, String>;

fn dec(v: &Value, modulus: &BigUint, what: &str) -> R<BigUint> {
    let s = v.as_str().ok_or_else(|| format!("{what}: not a string"))?;
    if s.is_empty()
        || s.len() > 120
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(format!("{what}: not a canonical decimal"));
    }
    let n: BigUint = s.parse().map_err(|_| format!("{what}: unparsable"))?;
    if &n >= modulus {
        return Err(format!("{what}: not below the field modulus"));
    }
    Ok(n)
}

fn arr<'a>(v: &'a Value, len: usize, what: &str) -> R<&'a Vec<Value>> {
    match v.as_array() {
        Some(a) if a.len() == len => Ok(a),
        _ => Err(format!("{what}: expected an array of {len}")),
    }
}

macro_rules! curve {
    ($m:ident, $c:ident, $pairing:ident, $curve_name:expr) => {
        mod $m {
            use super::*;
            use ark_ff::PrimeField;
            use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
            use ark_snark::SNARK;
            use $c::{$pairing, Fq, Fq2, Fr, G1Affine, G2Affine};
            pub const CURVE: &str = $curve_name;

            fn fq(v: &Value, what: &str) -> R<Fq> {
                let m: BigUint = Fq::MODULUS.into();
                Ok(Fq::from(dec(v, &m, what)?))
            }
            fn fr(v: &Value, what: &str) -> R<Fr> {
                let m: BigUint = Fr::MODULUS.into();
                Ok(Fr::from(dec(v, &m, what)?))
            }
            fn g1(v: &Value, what: &str) -> R<G1Affine> {
                let a = arr(v, 3, what)?;
                if a[2].as_str() != Some("1") {
                    return Err(format!("{what}: not an affine point (z != 1)"));
                }
                let p = G1Affine::new_unchecked(fq(&a[0], what)?, fq(&a[1], what)?);
                if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(format!("{what}: not a point of the prime-order subgroup"));
                }
                Ok(p)
            }
            fn g2(v: &Value, what: &str) -> R<G2Affine> {
                let a = arr(v, 3, what)?;
                let z = arr(&a[2], 2, what)?;
                if z[0].as_str() != Some("1") || z[1].as_str() != Some("0") {
                    return Err(format!("{what}: not an affine point (z != [1,0])"));
                }
                let c = |i: usize| -> R<Fq2> {
                    let r = arr(&a[i], 2, what)?;
                    Ok(Fq2::new(fq(&r[0], what)?, fq(&r[1], what)?))
                };
                let p = G2Affine::new_unchecked(c(0)?, c(1)?);
                if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(format!("{what}: not a point of the prime-order subgroup"));
                }
                Ok(p)
            }

            pub fn verify(case: &Value) -> R<bool> {
                let vk = &case["vkey"];
                if vk["protocol"] != "groth16"
                    || vk["curve"]
                        != Value::String(
                            if CURVE == "bn254" {
                                "bn128"
                            } else {
                                "bls12381"
                            }
                            .into(),
                        )
                {
                    return Err("vkey: wrong protocol or curve".into());
                }
                let ic = vk["IC"].as_array().ok_or("vkey: no IC")?;
                let key = VerifyingKey {
                    alpha_g1: g1(&vk["vk_alpha_1"], "vk_alpha_1")?,
                    beta_g2: g2(&vk["vk_beta_2"], "vk_beta_2")?,
                    gamma_g2: g2(&vk["vk_gamma_2"], "vk_gamma_2")?,
                    delta_g2: g2(&vk["vk_delta_2"], "vk_delta_2")?,
                    gamma_abc_g1: ic.iter().map(|p| g1(p, "IC")).collect::<R<Vec<_>>>()?,
                };
                let pr = &case["proof"];
                if pr["protocol"] != "groth16" || pr["curve"] != vk["curve"] {
                    return Err("proof: wrong protocol or curve".into());
                }
                let proof = Proof {
                    a: g1(&pr["pi_a"], "pi_a")?,
                    b: g2(&pr["pi_b"], "pi_b")?,
                    c: g1(&pr["pi_c"], "pi_c")?,
                };
                let sigs = case["publicSignals"]
                    .as_array()
                    .ok_or("publicSignals: not an array")?;
                if sigs.len() + 1 != key.gamma_abc_g1.len() {
                    return Err("publicSignals: count does not match the key".into());
                }
                let inputs = sigs
                    .iter()
                    .map(|s| fr(s, "publicSignals"))
                    .collect::<R<Vec<_>>>()?;
                let pvk = PreparedVerifyingKey::from(key);
                Groth16::<$pairing>::verify_with_processed_vk(&pvk, &inputs, &proof)
                    .map_err(|e| format!("verification error: {e}"))
            }
        }
    };
}

curve!(bn254, ark_bn254, Bn254, "bn254");
curve!(bls12_381, ark_bls12_381, Bls12_381, "bls12-381");

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 || a[1] != "verify" || (a[2] != "bn254" && a[2] != "bls12-381") {
        eprintln!("usage: pca-zk-arkworks verify bn254|bls12-381 <case.json>");
        std::process::exit(2);
    }
    let outcome: R<bool> = std::fs::read_to_string(&a[3])
        .map_err(|e| format!("cannot read case: {e}"))
        .and_then(|t| {
            serde_json::from_str::<Value>(&t).map_err(|e| format!("case is not JSON: {e}"))
        })
        .and_then(|v| {
            if a[2] == "bn254" {
                bn254::verify(&v)
            } else {
                bls12_381::verify(&v)
            }
        });
    let (valid, reason) = match outcome {
        Ok(true) => (true, String::from("ok")),
        Ok(false) => (false, String::from("pairing equation does not hold")),
        Err(e) => (false, e),
    };
    println!(
        "{}",
        serde_json::json!({ "valid": valid, "reason": reason })
    );
    std::process::exit(if valid { 0 } else { 1 });
}
