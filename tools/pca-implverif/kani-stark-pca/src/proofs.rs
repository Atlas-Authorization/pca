//! Kani proofs over the REAL BoundedReader / check_batch_opening of sdks/stark-pca (byte-identical copy, see build.sh).
//! `len`/`digests`/`node_vectors` style quantities are ANY usize (the attacker-controlled part); the byte buffer is
//! symbolic with length <= BUF (the logic reads only a bounded prefix; the arithmetic is separately proved for all
//! usize by tools/pca-implverif/verus/bounded_reader.rs).
use super::*;
const BUF: usize = 12;

#[kani::proof]
#[kani::unwind(16)]
fn bounded_reader_read_slice_any_len() {
    let data: [u8; BUF] = kani::any();
    let dl: usize = kani::any(); kani::assume(dl <= BUF);
    let p: usize = kani::any(); kani::assume(p <= dl);
    let mut r = BoundedReader::new(&data[..dl]);
    r.pos = p;
    let len: usize = kani::any();          // ANY usize incl. usize::MAX - small (the original wrap bug)
    match r.read_slice(len) {
        Ok(s) => { assert!(len <= dl - p); assert_eq!(s.len(), len); assert_eq!(r.pos, p + len); assert!(r.pos <= dl); }
        Err(_) => { assert!(len > dl - p); assert_eq!(r.pos, p); }
    }
}

#[kani::proof]
#[kani::unwind(16)]
fn bounded_reader_read_u8_and_array() {
    let data: [u8; BUF] = kani::any();
    let dl: usize = kani::any(); kani::assume(dl <= BUF);
    let mut r = BoundedReader::new(&data[..dl]);
    let _ = r.read_u8();
    assert!(r.pos <= dl);
    let _ = r.read_array::<4>();
    assert!(r.pos <= dl);
    let _ = r.read_u32();
    assert!(r.pos <= dl);
}

#[kani::proof]
#[kani::unwind(16)]
fn bounded_reader_read_many_alloc_guard() {
    let data: [u8; BUF] = kani::any();
    let dl: usize = kani::any(); kani::assume(dl <= BUF);
    let n: usize = kani::any();            // ANY element count
    let r = BoundedReader::new(&data[..dl]);
    // the allocation guard: a count larger than the remaining input is refused BEFORE Vec::with_capacity
    assert_eq!(r.check_eor(n).is_ok(), n <= dl);
}

#[kani::proof]
#[kani::unwind(16)]
fn check_batch_opening_no_panic() {
    let data: [u8; BUF] = kani::any();
    let dl: usize = kani::any(); kani::assume(dl <= BUF);
    let _ = check_batch_opening(&data[..dl]);   // any panic / overflow / OOB is a failure
}
