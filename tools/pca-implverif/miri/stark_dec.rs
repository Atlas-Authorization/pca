//! Miri driver: stark-pca (winterfell) fail-closed proof decoder: genuine, truncations, boundary bytes, hostile 9-byte vints at plausible
//! length prefixes, garbage, and one honest verify.
use stark_pca::{proof_from_bytes, verify_release_bytes, PolicyParams};
include!("miri_common.rs");
fn fixture() -> Vec<u8> { std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin")).unwrap() }
fn vint9(n: u64) -> [u8; 9] { let mut o = [0u8; 9]; o[0] = 0xff; o[1..].copy_from_slice(&n.to_le_bytes()); o }
#[test] fn decode_genuine() { assert!(proof_from_bytes(&fixture()).is_ok()); }
#[test] fn decode_truncations() { let b = fixture(); for k in offsets(b.len()) { assert!(proof_from_bytes(&b[..k]).is_err()); } }
#[test] fn decode_boundary_bytes() { let b = fixture(); for o in offsets(b.len()) { for v in BOUNDARY_BYTES { let mut m = b.clone(); m[o] = v; let _ = proof_from_bytes(&m); } } }
#[test] fn decode_hostile_counts() {
    let b = fixture();
    for off in offsets(b.len()).into_iter().filter(|o| o + 9 <= b.len()).take(8) { for h in [1u64 << 33, 1 << 62, u64::MAX] { let mut m = b.clone(); m[off..off + 9].copy_from_slice(&vint9(h)); let _ = proof_from_bytes(&m); } }
}
#[test] fn verify_bytes_garbage() { let _ = verify_release_bytes(&[], &PolicyParams::default_policy()); let _ = verify_release_bytes(&[0u8; 100], &PolicyParams::default_policy()); }
#[test] fn verify_genuine() { assert!(verify_release_bytes(&fixture(), &PolicyParams::default_policy()).is_ok()); }
