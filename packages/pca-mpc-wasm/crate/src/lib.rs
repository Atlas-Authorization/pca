//! Constant-time Ed25519 base-OT curve core, compiled to WebAssembly.
//!
//! This is the "fix the lang limit" core for `@atlasauth/pca-mpc`. The pure-JS group in that
//! package (`ec.ts`) is correct and malicious-hardened, but its BigInt modular arithmetic is NOT
//! constant-time and cannot be in JS — a genuine language/runtime boundary (docs §7.1). The
//! security-critical operations are the base-OT scalar multiplications over SECRET scalars
//! (`y`, `x`, the Schnorr nonce `r`): `S = y·B`, `T = y·S`, `R = x·B (+S)`, `y·R`, `x·S`. Those are
//! exactly where a timing side-channel would leak the receiver's choice bit or the sender's `y`.
//!
//! Here those operations run through `curve25519-dalek`'s audited, constant-time field and scalar
//! multiplication (`EdwardsPoint::mul_base` over the precomputed fixed-base table, and the
//! variable-base `point * scalar` ladder) — genuinely constant-time, the JS `@noble`/BigInt path
//! being the current fallback.
//!
//! ## Byte encodings (the wire contract)
//! Points cross the WASM boundary as the **canonical 32-byte compressed Ed25519 encoding**
//! (`CompressedEdwardsY`: little-endian `y` with the sign bit of `x` in the top bit) — the same
//! encoding `@noble/curves` and every Ed25519 implementation produce from `point.toRawBytes()`,
//! which is what makes the TS parity test an exact identical-bytes cross-check. Scalars cross as
//! 32-byte little-endian and are reduced mod `L` by `Scalar::from_bytes_mod_order`, matching
//! `ec.ts`'s `k mod L`. (`curve25519-dalek` exposes no affine accessor, so the 64-byte affine
//! `x‖y` form `ec.ts` hashes is reconstructed on the TS side — see `src/index.ts` — never a
//! secret-dependent step.)
//!
//! ## Validation (malicious-security point contract, mirrors `ec.ts`)
//!  - canonical → a received point must be the canonical encoding of the point it decodes to
//!    (RFC 8032 §5.1.3): `y < p` and no "negative zero" (`x = 0` with the sign bit set). `curve25519-dalek`'s
//!    `decompress` accepts both of those malformed forms, so the decoder re-compresses and compares;
//!  - on-curve  → `CompressedEdwardsY::decompress` returns `Some`,
//!  - identity  → `is_identity()`,
//!  - subgroup  → on-curve ∧ ¬identity ∧ `is_torsion_free()` (the `[L]·P = O` cofactor check that
//!    rejects every small-order and mixed-order point).
//!
//! ## ABI
//! No std, no allocator, no imports. All I/O is through fixed static buffers in linear memory whose
//! addresses the `ptr_*` exports hand back; the module instantiates with an empty import object and
//! is driven single-threaded (write inputs → call op → read `OUT`).

#![no_std]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No code path below panics on adversarial input (decode is fallible, not panicking), so this is
    // only reached on a genuine bug; abort the module rather than pull in any unwinding machinery.
    core::arch::wasm32::unreachable()
}

const PLEN: usize = 32; // compressed point
const SLEN: usize = 32; // scalar (LE)

static mut SCALAR: [u8; SLEN] = [0u8; SLEN];
static mut PA: [u8; PLEN] = [0u8; PLEN];
static mut PB: [u8; PLEN] = [0u8; PLEN];
static mut OUT: [u8; PLEN] = [0u8; PLEN];

// --- Linear-memory buffer addresses (stable for the life of the instance). ---
#[no_mangle]
pub extern "C" fn ptr_scalar() -> *mut u8 {
    core::ptr::addr_of_mut!(SCALAR) as *mut u8
}
#[no_mangle]
pub extern "C" fn ptr_pa() -> *mut u8 {
    core::ptr::addr_of_mut!(PA) as *mut u8
}
#[no_mangle]
pub extern "C" fn ptr_pb() -> *mut u8 {
    core::ptr::addr_of_mut!(PB) as *mut u8
}
#[no_mangle]
pub extern "C" fn ptr_out() -> *mut u8 {
    core::ptr::addr_of_mut!(OUT) as *mut u8
}

fn read_scalar() -> Scalar {
    let b: [u8; SLEN] = unsafe { SCALAR };
    Scalar::from_bytes_mod_order(b)
}

/// Decode a received 32-byte point, accepting ONLY its canonical encoding (RFC 8032 §5.1.3).
///
/// `decompress` alone also accepts (a) a field element `y >= p` (24 aliases of small `y`, including
/// aliases of the identity and of the small-order points) and (b) `x = 0` with the sign bit set
/// ("negative zero"). Both would let a peer present a second encoding of the same point, which
/// breaks byte-for-byte transcript binding in the OT. Re-encoding and comparing rejects both.
/// The point is public (received from the peer), so this comparison needs no constant-time care.
fn decode_canonical(bytes: [u8; PLEN]) -> Option<EdwardsPoint> {
    let compressed = CompressedEdwardsY(bytes);
    let point = compressed.decompress()?;
    if point.compress() == compressed {
        Some(point)
    } else {
        None
    }
}

fn read_pa() -> Option<EdwardsPoint> {
    decode_canonical(unsafe { PA })
}

fn read_pb() -> Option<EdwardsPoint> {
    decode_canonical(unsafe { PB })
}

fn store_out(p: &EdwardsPoint) {
    unsafe { OUT = p.compress().to_bytes() }
}

// --- Curve operations. Status: 1 = ok, 0 = a received point failed to decode (off-curve). ---

/// `OUT = [SCALAR]·B` — constant-time fixed-base multiplication (`S = y·B`, `R`'s `x·B`, the
/// Schnorr `r·B`). Always succeeds.
#[no_mangle]
pub extern "C" fn mul_base() -> i32 {
    store_out(&EdwardsPoint::mul_base(&read_scalar()));
    1
}

/// `OUT = [SCALAR]·PA` — constant-time variable-base multiplication (`y·R`, `x·S`, `y·S`).
#[no_mangle]
pub extern "C" fn scalar_mul() -> i32 {
    match read_pa() {
        Some(a) => {
            store_out(&(a * read_scalar()));
            1
        }
        None => 0,
    }
}

/// `OUT = PA + PB` (the unified complete Edwards addition).
#[no_mangle]
pub extern "C" fn point_add() -> i32 {
    match (read_pa(), read_pb()) {
        (Some(a), Some(b)) => {
            store_out(&(a + b));
            1
        }
        _ => 0,
    }
}

/// `OUT = PA − PB`.
#[no_mangle]
pub extern "C" fn point_sub() -> i32 {
    match (read_pa(), read_pb()) {
        (Some(a), Some(b)) => {
            store_out(&(a - b));
            1
        }
        _ => 0,
    }
}

/// `OUT = −PA`.
#[no_mangle]
pub extern "C" fn point_neg() -> i32 {
    match read_pa() {
        Some(a) => {
            store_out(&(-a));
            1
        }
        None => 0,
    }
}

/// Whether `PA` decodes to a point on the curve (`ec.ts::isOnCurve`).
#[no_mangle]
pub extern "C" fn is_on_curve() -> i32 {
    i32::from(read_pa().is_some())
}

/// Whether `PA` is a valid curve point equal to the identity (`ec.ts::isIdentity`). 0 if off-curve.
#[no_mangle]
pub extern "C" fn is_identity() -> i32 {
    match read_pa() {
        Some(a) => i32::from(a.is_identity()),
        None => 0,
    }
}

/// Whether `PA` is a valid NON-identity point of the prime-order subgroup
/// (`ec.ts::isInSubgroup`: on-curve ∧ ¬identity ∧ `[L]·P = O`).
#[no_mangle]
pub extern "C" fn is_in_subgroup() -> i32 {
    match read_pa() {
        Some(a) => i32::from(!a.is_identity() && a.is_torsion_free()),
        None => 0,
    }
}

/// Whether `PA` and `PB` are valid curve points equal as group elements (`ec.ts::equal`). The
/// compressed encoding is canonical, so for valid points this is also a byte-equality — but we
/// decode + compare to reject off-curve input the way the JS layer does.
#[no_mangle]
pub extern "C" fn point_equal() -> i32 {
    match (read_pa(), read_pb()) {
        (Some(a), Some(b)) => i32::from(a == b),
        _ => 0,
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    //! Native tests for the exported C ABI. The statics are shared, so every test takes `LOCK`.
    //!
    //! Official data: RFC 8032 section 7.1 (Ed25519) and Project Wycheproof `ed25519_test.json`, both in
    //! `test-vectors/` with provenance. The WASM ABI exposes group operations, so Ed25519 verification
    //! is assembled from those operations plus SHA-512 (dev-dependency `sha2`).
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha512};
    use std::string::String;
    use std::sync::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());

    const RFC8032: &str = include_str!("../test-vectors/rfc8032-ed25519.json");
    const WYCHEPROOF: &str = include_str!("../test-vectors/wycheproof-ed25519_test.json");

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| std::format!("{x:02x}")).collect()
    }
    fn set(ptr: *mut u8, b: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), ptr, b.len()) }
    }
    fn out() -> [u8; 32] {
        unsafe { OUT }
    }
    fn abi_mul_base(k: &[u8; 32]) -> [u8; 32] {
        set(ptr_scalar(), k);
        assert_eq!(mul_base(), 1);
        out()
    }
    fn abi_scalar_mul(k: &[u8; 32], p: &[u8]) -> Option<[u8; 32]> {
        set(ptr_pa(), p);
        set(ptr_scalar(), k);
        (scalar_mul() == 1).then(out)
    }
    fn abi_add(a: &[u8], b: &[u8]) -> Option<[u8; 32]> {
        set(ptr_pa(), a);
        set(ptr_pb(), b);
        (point_add() == 1).then(out)
    }
    fn abi_equal(a: &[u8], b: &[u8]) -> bool {
        set(ptr_pa(), a);
        set(ptr_pb(), b);
        point_equal() == 1
    }
    fn on_curve(p: &[u8]) -> bool {
        set(ptr_pa(), p);
        is_on_curve() == 1
    }
    fn in_subgroup(p: &[u8]) -> bool {
        set(ptr_pa(), p);
        is_in_subgroup() == 1
    }
    fn ident(p: &[u8]) -> bool {
        set(ptr_pa(), p);
        is_identity() == 1
    }

    /// The group order L, little-endian.
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    fn lt_l(s: &[u8]) -> bool {
        for i in (0..32).rev() {
            if s[i] != L_LE[i] {
                return s[i] < L_LE[i];
            }
        }
        false
    }

    /// RFC 8032 5.1.5: clamped secret scalar from a seed.
    fn clamped(seed: &[u8]) -> [u8; 32] {
        let h = Sha512::digest(seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        a
    }

    #[derive(Debug, PartialEq)]
    enum Verdict {
        Ok,
        Reject(&'static str),
    }

    /// Ed25519 verification (RFC 8032 5.1.7, cofactorless) from the ABI's group operations.
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Verdict {
        if pk.len() != 32 {
            return Verdict::Reject("bad-pk-length");
        }
        if sig.len() != 64 {
            return Verdict::Reject("bad-sig-length");
        }
        let (r, s) = sig.split_at(32);
        if !lt_l(s) {
            return Verdict::Reject("S-not-canonical");
        }
        if !on_curve(pk) {
            return Verdict::Reject("A-undecodable");
        }
        if !on_curve(r) {
            return Verdict::Reject("R-undecodable");
        }
        let mut h = Sha512::new();
        h.update(r);
        h.update(pk);
        h.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into()).to_bytes();
        let mut s32 = [0u8; 32];
        s32.copy_from_slice(s);
        let lhs = abi_mul_base(&s32);
        let ka = abi_scalar_mul(&k, pk).unwrap();
        let rhs = abi_add(r, &ka).unwrap();
        if abi_equal(&lhs, &rhs) {
            Verdict::Ok
        } else {
            Verdict::Reject("equation-mismatch")
        }
    }

    #[test]
    fn rfc8032_public_keys_are_derived_by_mul_base() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let doc: Value = serde_json::from_str(RFC8032).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 5);
        for v in vectors {
            let a = clamped(&unhex(v["secretKey"].as_str().unwrap()));
            assert_eq!(hex(&abi_mul_base(&a)), v["publicKey"].as_str().unwrap(), "TEST {}", v["name"]);
        }
    }

    #[test]
    fn rfc8032_signatures_verify_and_tampering_is_rejected_for_the_right_reason() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let doc: Value = serde_json::from_str(RFC8032).unwrap();
        for v in doc["vectors"].as_array().unwrap() {
            let pk = unhex(v["publicKey"].as_str().unwrap());
            let msg = unhex(v["message"].as_str().unwrap());
            let sig = unhex(v["signature"].as_str().unwrap());
            assert_eq!(verify(&pk, &msg, &sig), Verdict::Ok, "TEST {}", v["name"]);
            let mut bad_msg = msg.clone();
            bad_msg.push(0);
            assert_eq!(verify(&pk, &bad_msg, &sig), Verdict::Reject("equation-mismatch"));
            let mut bad_s = sig.clone();
            bad_s[40] ^= 1;
            assert_eq!(verify(&pk, &msg, &bad_s), Verdict::Reject("equation-mismatch"));
        }
    }

    #[test]
    fn wycheproof_ed25519_all_151_cases() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let doc: Value = serde_json::from_str(WYCHEPROOF).unwrap();
        let mut n = 0;
        let mut failures: Vec<String> = Vec::new();
        for g in doc["testGroups"].as_array().unwrap() {
            let pk = unhex(g["publicKey"]["pk"].as_str().unwrap());
            for t in g["tests"].as_array().unwrap() {
                n += 1;
                let v = verify(&pk, &unhex(t["msg"].as_str().unwrap()), &unhex(t["sig"].as_str().unwrap()));
                let expect_valid = t["result"] == "valid";
                if (v == Verdict::Ok) != expect_valid {
                    failures.push(std::format!("tcId {} expected {} got {:?}: {}", t["tcId"], t["result"], v, t["comment"]));
                }
            }
        }
        assert_eq!(n, 151);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    fn le(y: &[u8; 32], sign: bool) -> [u8; 32] {
        let mut b = *y;
        if sign {
            b[31] |= 0x80;
        }
        b
    }

    /// p = 2^255 - 19 as little-endian bytes.
    fn p_plus(t: u8) -> [u8; 32] {
        // p + t for 0 <= t <= 18 fits in 255 bits: low byte = 0xed + t (with carry-free since 0xed + 18 < 0x100)
        let mut b = [0xffu8; 32];
        b[0] = 0xed + t;
        b[31] = 0x7f;
        b
    }

    fn one() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    }

    #[test]
    fn non_canonical_y_encodings_are_rejected() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // y = p + 1 is a non-canonical alias of y = 1 (the identity); y = p is an alias of y = 0 (order 4).
        for t in 0..=18u8 {
            for sign in [false, true] {
                let enc = le(&p_plus(t), sign);
                assert!(!on_curve(&enc), "p+{t} sign={sign} must be rejected");
            }
        }
        // their canonical counterparts are accepted
        assert!(on_curve(&one()));
        assert!(ident(&one()));
        assert!(on_curve(&[0u8; 32])); // y = 0: a point of order 4
    }

    #[test]
    fn negative_zero_encodings_are_rejected() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // y = 1, x = 0 with the sign bit set; and y = p - 1 (order 2), x = 0 with the sign bit set.
        assert!(!on_curve(&le(&one(), true)));
        let mut pm1 = p_plus(0);
        pm1[0] = 0xec;
        assert!(on_curve(&le(&pm1, false)));
        assert!(!on_curve(&le(&pm1, true)));
    }

    #[test]
    fn operations_refuse_non_canonical_operands() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let alias_of_identity = le(&p_plus(1), false);
        let b = abi_mul_base(&one());
        assert_eq!(abi_add(&alias_of_identity, &b), None);
        assert_eq!(abi_add(&b, &alias_of_identity), None);
        assert_eq!(abi_scalar_mul(&one(), &alias_of_identity), None);
        assert!(!abi_equal(&alias_of_identity, &one()));
    }

    #[test]
    fn small_order_points_are_on_curve_but_never_in_the_prime_subgroup() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The 8 canonical encodings of the torsion subgroup (identity, order 2, two of order 4, four of order 8).
        let torsion = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        ];
        let mut eight = [0u8; 32];
        eight[0] = 8;
        for h in torsion {
            let t = unhex(h);
            assert!(on_curve(&t), "{h} is a valid point");
            assert!(!in_subgroup(&t), "{h} must be rejected by the subgroup check");
            let eight_t = abi_scalar_mul(&eight, &t).unwrap();
            assert!(ident(&eight_t), "8 * {h} must be the identity");
        }
        // the identity is the one torsion point that is also "in" the group; it is excluded explicitly
        assert!(ident(&unhex(torsion[0])));
    }

    #[test]
    fn prime_subgroup_points_pass_the_subgroup_check_and_are_closed_under_the_ops() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let b = abi_mul_base(&one());
        assert!(in_subgroup(&b));
        // [L]B = identity; [L-1]B = -B
        let l_minus_1 = {
            let mut x = L_LE;
            x[0] -= 1;
            x
        };
        let neg_b = abi_scalar_mul(&l_minus_1, &b).unwrap();
        let sum = abi_add(&b, &neg_b).unwrap();
        assert!(ident(&sum));
        // a scalar equal to L reduces to zero (mul_base of L is the identity encoding)
        assert_eq!(hex(&abi_mul_base(&L_LE)), hex(&one()));
    }
}
