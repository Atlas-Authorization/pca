//! Miri driver: folding-pca compressed-proof decoder (bincode + nova-snark, run on an aarch64 target: halo2curves uses x86 inline asm).
//! Decode only (vk generation is outside Miri's reach): genuine, truncations, boundary bytes, hostile u64 length prefixes at the
//! plausible length-prefix offsets, plus the integer helpers.
//!
//! SHARDED BY TEST NAME (one queue job per test): every looping test is split into parts `_pK` that take the inputs with
//! index = K (mod N) of the SAME full input list, so the union of the parts is exactly the unsharded input set (checked by
//! `shards_cover_inputs`, which does no decoding). No input is dropped and no input size is reduced: each decode is a full
//! bincode + nova-snark deserialisation of the real 10.6 KB fixture or a mutant of it. The fixture is embedded with
//! include_bytes!, so the run needs no file system access (Miri isolation stays ON).
use pca_folding_ivc::{check_claimed_z0, felt_to_hex, hash2_native, within_budget, ActionStep, Compressed, Scalar};
include!("miri_common.rs");
const PROOF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/compressed_proof.bin"));
fn proof() -> Vec<u8> { PROOF.to_vec() }
fn dec(b: &[u8]) -> bool { bincode::deserialize::<Compressed>(b).is_ok() }

// full input lists (identical to the unsharded driver)
fn truncations() -> Vec<usize> { let n = PROOF.len(); offsets(n).into_iter().filter(|k| *k < n).collect() }
fn boundary() -> Vec<(usize, u8)> { offsets(PROOF.len()).into_iter().flat_map(|o| [(o, 0x00u8), (o, 0xffu8)]).collect() }
fn hostile() -> Vec<(usize, u64)> { length_prefix_offsets(PROOF, 8).into_iter().flat_map(|o| [(o, 1u64 << 33), (o, u64::MAX)]).collect() }
fn part<T: Clone>(v: &[T], k: usize, n: usize) -> Vec<T> { v.iter().enumerate().filter(|(i, _)| i % n == k).map(|(_, x)| x.clone()).collect() }

const NT: usize = 4; // truncation parts
const NB: usize = 8; // boundary-byte parts
const NH: usize = 2; // hostile-prefix parts

fn run_trunc(k: usize) { let b = proof(); for t in part(&truncations(), k, NT) { assert!(!dec(&b[..t])); } }
fn run_boundary(k: usize) { let b = proof(); for (o, v) in part(&boundary(), k, NB) { let mut m = b.clone(); m[o] = v; let _ = dec(&m); } }
fn run_hostile(k: usize) { let b = proof(); for (off, h) in part(&hostile(), k, NH) { let mut m = b.clone(); m[off..off + 8].copy_from_slice(&h.to_le_bytes()); let _ = dec(&m); } }

#[test] fn decode_genuine() { assert!(dec(&proof())); }
#[test] fn decode_truncations_p0() { run_trunc(0) }
#[test] fn decode_truncations_p1() { run_trunc(1) }
#[test] fn decode_truncations_p2() { run_trunc(2) }
#[test] fn decode_truncations_p3() { run_trunc(3) }
#[test] fn decode_boundary_bytes_p0() { run_boundary(0) }
#[test] fn decode_boundary_bytes_p1() { run_boundary(1) }
#[test] fn decode_boundary_bytes_p2() { run_boundary(2) }
#[test] fn decode_boundary_bytes_p3() { run_boundary(3) }
#[test] fn decode_boundary_bytes_p4() { run_boundary(4) }
#[test] fn decode_boundary_bytes_p5() { run_boundary(5) }
#[test] fn decode_boundary_bytes_p6() { run_boundary(6) }
#[test] fn decode_boundary_bytes_p7() { run_boundary(7) }
#[test] fn decode_hostile_prefixes_p0() { run_hostile(0) }
#[test] fn decode_hostile_prefixes_p1() { run_hostile(1) }
#[test] fn small_helpers() {
    let hist: Vec<ActionStep> = (0..4u64).map(|i| ActionStep { action_digest: i, cost: u64::MAX }).collect();
    let _ = within_budget(&hist);
    assert!(check_claimed_z0(&[Scalar::from(0u64), Scalar::from(0u64)]).is_ok());
    assert!(check_claimed_z0(&[Scalar::from(1u64), Scalar::from(0u64)]).is_err());
    assert!(check_claimed_z0(&[]).is_err());
    let _ = felt_to_hex(&hash2_native(Scalar::from(3u64), Scalar::from(4u64)));
}
/// The parts partition each full input list: every input is in exactly one part (no decoding; fast).
#[test] fn shards_cover_inputs() {
    fn check<T: Clone + PartialEq + std::fmt::Debug>(all: Vec<T>, n: usize) {
        let mut got: Vec<(usize, T)> = vec![];
        for k in 0..n { let mut c = 0; for (i, x) in all.iter().enumerate() { if i % n == k { assert_eq!(&part(&all, k, n)[c], x); c += 1; got.push((i, x.clone())); } } assert_eq!(c, part(&all, k, n).len()); }
        got.sort_by_key(|(i, _)| *i);
        assert_eq!(got.into_iter().map(|(_, x)| x).collect::<Vec<_>>(), all);
    }
    assert!(!truncations().is_empty() && !boundary().is_empty() && !hostile().is_empty());
    check(truncations(), NT); check(boundary(), NB); check(hostile(), NH);
    eprintln!("inputs: truncations {} boundary {} hostile {}", truncations().len(), boundary().len(), hostile().len());
}
