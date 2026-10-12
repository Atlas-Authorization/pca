//! Kani proofs over the REAL stark-pca-plonky3 public-input validation and commitment parser (byte-identical source).
//! The proof-byte decoder itself is `postcard` (a dependency); crate-owned code on the untrusted-input path is PolicyParams validation
//! and hex256_limbs, which is what is proved here.
use super::*;

// Error-message formatting (u128 Display) is irrelevant to the Ok/Err decision but is very expensive for CBMC: stub it out.
fn stub_format(_a: core::fmt::Arguments<'_>) -> String { String::new() }

fn any_params() -> PolicyParams {
    PolicyParams {
        weights: kani::any(), s: kani::any(), theta1_scaled: kani::any(), kappa: kani::any(), bmax_scaled: kani::any(),
        policy_commitment: String::new(), action_commitment: String::new(), witness_commitment: Default::default(),
    }
}

// UNBOUNDED over every u64 field: validate_bounds accepts iff the five documented bounds hold; the u128 weight sum cannot overflow.
#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(alloc::fmt::format, stub_format)]
fn p3_validate_bounds_exact_all_u64() {
    let p = any_params();
    let ok = p.validate_bounds().is_ok();
    let mut sum: u128 = 0; let mut i = 0; while i < 6 { sum += p.weights[i] as u128; i += 1; }
    let spec = p.s == S && sum <= MAX_WEIGHT_SUM as u128 && p.kappa <= MAX_KAPPA && p.bmax_scaled <= MAX_BMAX && p.theta1_scaled <= MAX_THETA1;
    assert_eq!(ok, spec);
    // consequence the AIR relies on (RT-01): after validation every operand is far below the Goldilocks order
    if ok { assert!(p.weights.iter().all(|w| *w <= MAX_WEIGHT_SUM) && p.t1_rraw() < GOLDI_P); }
}

// g_from_u128 reduction: for every u128 the residue fits u64 and is canonical (< p).
#[kani::proof]
fn p3_g_from_u128_reduction_total() {
    let v: u128 = kani::any();
    let r = v % GOLDI_P;
    assert!(r < GOLDI_P && GOLDI_P <= u64::MAX as u128);
    assert_eq!(r as u64 as u128, r);
}

// hex256_limbs on ANY byte string of length <= 70 (covers wrong lengths 0..=70 and the exact 64): never panics (incl. str slicing);
// Ok iff exactly 64 hex digits; the limbs are the big-endian 32-bit words (checked for limb 0 and limb 7).
#[kani::proof]
#[kani::unwind(72)]
#[kani::stub(alloc::fmt::format, stub_format)]
fn p3_hex256_limbs_len_le_70() {
    let raw: [u8; 70] = kani::any();
    let l: usize = kani::any(); kani::assume(l <= 70);
    kani::assume(raw[..l].iter().all(|b| *b < 128)); // ASCII => valid UTF-8 (non-ASCII is rejected by the all(is_ascii_hexdigit) check anyway)
    let s = std::str::from_utf8(&raw[..l]).unwrap();
    let r = hex256_limbs(s);
    let hex = |b: u8| -> Option<u32> { match b { b'0'..=b'9' => Some((b - b'0') as u32), b'a'..=b'f' => Some((b - b'a' + 10) as u32), b'A'..=b'F' => Some((b - b'A' + 10) as u32), _ => None } };
    let all_hex = raw[..l].iter().all(|b| hex(*b).is_some());
    assert_eq!(r.is_ok(), l == HEX_COMMITMENT_DIGITS && all_hex);
    if let Ok(limbs) = r {
        let word = |k: usize| -> u32 { let mut a = 0u32; let mut j = 0; while j < 8 { a = (a << 4) | hex(raw[8 * k + j]).unwrap(); j += 1; } a };
        assert_eq!(limbs[0], word(0));
        assert_eq!(limbs[HEX_LIMBS - 1], word(HEX_LIMBS - 1));
    }
}

// ---- hex256_limbs, compositional. The monolithic harness above (70 symbolic bytes, 8 real from_str_radix calls) exhausts CBMC memory
// (CBMC exit status 6 = uncaught std::bad_alloc under the 14 GB cap). It is split into a lemma about std and a composition proof:
fn hexval(b: u8) -> Option<u32> { match b { b'0'..=b'9' => Some((b - b'0') as u32), b'a'..=b'f' => Some((b - b'a' + 10) as u32), b'A'..=b'F' => Some((b - b'A' + 10) as u32), _ => None } }
// hex256_limbs accepts LOWERCASE hex only (R6-ALIAS-06: one accepted spelling per commitment).
fn lowerhex(b: u8) -> bool { matches!(b, b'0'..=b'9' | b'a'..=b'f') }
fn spec_word(b: &[u8]) -> u32 { let mut a = 0u32; let mut j = 0; while j < 8 { a = (a << 4) | hexval(b[j]).unwrap(); j += 1; } a }

// Lemma: on EVERY 8-byte ASCII-hex string the REAL u32::from_str_radix(_, 16) returns Ok(spec_word). (2^32-scale input space, all symbolic.)
#[kani::proof]
#[kani::unwind(10)]
fn p3_lemma_from_str_radix_8hex() {
    let raw: [u8; 8] = kani::any();
    kani::assume(raw.iter().all(|b| hexval(*b).is_some()));
    let s = std::str::from_utf8(&raw).unwrap();
    assert_eq!(u32::from_str_radix(s, 16), Ok(spec_word(&raw)));
}

// The stub used below returns exactly what the lemma proves the real function returns on 8-hex-digit input; anything else is unreachable
// (asserted), so the stub is faithful on every call hex256_limbs can make.
fn stub_from_str_radix(s: &str, radix: u32) -> Result<u32, core::num::ParseIntError> {
    assert!(radix == 16 && s.len() == 8 && s.bytes().all(|b| hexval(b).is_some()), "stub only reached on 8 hex digits");
    Ok(spec_word(s.as_bytes()))
}

// Composition, split in two (the single 70-byte harness with value checks did not finish in 40 min under CBMC):
// (G) gate: for ANY byte string of length <= 70 (non-ASCII is rejected by the hex check before any slicing; ASCII assumed so the
//     input is a valid &str): no panic, and Ok iff exactly 64 LOWERCASE hex digits.
#[kani::proof]
#[kani::unwind(72)]
#[kani::stub(alloc::fmt::format, stub_format)]
#[kani::stub(u32::from_str_radix, stub_from_str_radix)]
fn p3_hex256_limbs_gate_len_le_70() {
    let raw: [u8; 70] = kani::any();
    let l: usize = kani::any(); kani::assume(l <= 70);
    kani::assume(raw[..l].iter().all(|b| *b < 128));
    let s = unsafe { std::str::from_utf8_unchecked(&raw[..l]) };
    let r = hex256_limbs(s);
    let all_hex = raw[..l].iter().all(|b| lowerhex(*b));
    assert_eq!(r.is_ok(), l == HEX_COMMITMENT_DIGITS && all_hex);
}

// (V) values: for EVERY 64-lowercase-hex-digit string, every limb i equals the big-endian word of digits 8i..8i+8.
#[kani::proof]
#[kani::unwind(72)]
#[kani::stub(alloc::fmt::format, stub_format)]
#[kani::stub(u32::from_str_radix, stub_from_str_radix)]
fn p3_hex256_limbs_values_all_64hex() {
    let raw: [u8; 64] = kani::any();
    kani::assume(raw.iter().all(|b| lowerhex(*b)));
    let s = unsafe { std::str::from_utf8_unchecked(&raw) };
    let limbs = hex256_limbs(s).unwrap();
    let mut i = 0; while i < HEX_LIMBS { assert_eq!(limbs[i], spec_word(&raw[8 * i..8 * i + 8])); i += 1; }
}
