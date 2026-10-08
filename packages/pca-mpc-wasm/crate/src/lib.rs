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

fn read_pa() -> Option<EdwardsPoint> {
    CompressedEdwardsY(unsafe { PA }).decompress()
}

fn read_pb() -> Option<EdwardsPoint> {
    CompressedEdwardsY(unsafe { PB }).decompress()
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
