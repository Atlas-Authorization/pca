//! Miri driver: stark-pca-plonky3 proof decoder (postcard) on the committed proof: genuine decode, truncations and byte mutations at the
//! boundary/sampled offsets, hostile varint length prefixes at the first plausible prefixes, and one honest verify.
use stark_pca_plonky3::{proof_from_bytes, verify_release, PolicyParams};
include!("miri_common.rs");
fn fixture() -> Vec<u8> { std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin")).unwrap() }
fn varint(mut n: u64) -> Vec<u8> { let mut v = vec![]; loop { let b = (n & 0x7f) as u8; n >>= 7; if n == 0 { v.push(b); break } v.push(b | 0x80) } v }
#[test] fn decode_genuine() { assert!(proof_from_bytes(&fixture()).is_ok()); }
#[test] fn decode_truncations() { let b = fixture(); for k in offsets(b.len()) { assert!(proof_from_bytes(&b[..k]).is_err()); } }
#[test] fn decode_boundary_bytes() { let b = fixture(); for o in offsets(b.len()) { for v in BOUNDARY_BYTES { let mut m = b.clone(); m[o] = v; let _ = proof_from_bytes(&m); } } }
#[test] fn decode_trailing_and_empty() { let mut b = fixture(); b.push(0); let _ = proof_from_bytes(&b); let _ = proof_from_bytes(&[]); let _ = proof_from_bytes(&[0xff; 64]); }
#[test] fn decode_hostile_varints() {
    let b = fixture();
    for off in offsets(b.len()).into_iter().take(8) { for h in [1u64 << 33, 1 << 62, u64::MAX] { let mut m = b.clone(); m.splice(off..off + 1, varint(h)); let _ = proof_from_bytes(&m); } }
}
#[test] fn verify_genuine() { let p = proof_from_bytes(&fixture()).unwrap(); assert!(verify_release(&p, &PolicyParams::default_policy()).is_ok()); }
