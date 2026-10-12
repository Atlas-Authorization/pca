//! Miri driver: pca-zkvm-core input decoder (serde_json DecideInput), strict base64url / ed25519 byte decoders.
use pca_zkvm_core::{chain::ed25519_verify_b64u, decide_from_str};
include!("miri_common.rs");
fn sample() -> String { std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/decide_input.sample.json")).unwrap() }
#[test] fn decide_genuine() { let _ = decide_from_str(&sample()); }
#[test] fn decide_truncations() { let s = sample(); for k in offsets(s.len()) { if s.is_char_boundary(k) { let _ = decide_from_str(&s[..k]); } } }
#[test] fn decide_byte_mutants() {
    let s = sample().into_bytes();
    for i in offsets(s.len()) { for v in [b'0', b'"', b'\\', b'{', b'-', b'e'] { let mut m = s.clone(); m[i] = v; if let Ok(t) = String::from_utf8(m) { let _ = decide_from_str(&t); } } }
}
#[test] fn decide_garbage() { for t in ["", "{}", "null", "[]", "{\"action\":", "\u{0}", "{\"now\":1e999}", "{\"now\":-0}"] { let _ = decide_from_str(t); } }
#[test] fn b64u_decoders() {
    let alpha = ["", "A", "AA", "AAA", "AAAA", "AAAAA", "-_-_", "====", "\u{00e9}\u{00e9}", "A\0A\0"];
    for a in alpha { for b in alpha { let _ = ed25519_verify_b64u(a, b"msg", b); } }
    let s86 = "A".repeat(86); let _ = ed25519_verify_b64u(&"A".repeat(43), b"m", &s86);
    let _ = ed25519_verify_b64u(&format!("{}B", "A".repeat(42)), b"m", &s86);
}
