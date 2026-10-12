// child module of chain.rs: sees private decode_b64u_strict
#[kani::proof]
#[kani::unwind(12)]
fn zk_decode_b64u_strict_bounded6() {
    let raw: [u8; 6] = kani::any();
    let l: usize = kani::any();
    kani::assume(l <= 6);
    let want: usize = kani::any();
    kani::assume(want <= 8);
    let s = match std::str::from_utf8(&raw[..l]) { Ok(s) => s, Err(_) => return };
    if let Some(b) = decode_b64u_strict(s, want) {
        assert_eq!(b.len(), want);
        assert_eq!(b64u(&b), s);          // canonical: re-encoding reproduces the input
        assert!(s.len() % 4 != 1);
    }
    if s.len() % 4 == 1 { assert!(decode_b64u_strict(s, want).is_none()); }
}
