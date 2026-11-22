//! FN-DSA (Falcon, FIPS 206) signature core, compiled to WebAssembly.
//!
//! This is the lattice **signature** backend for `@atlasauth/pca`'s post-quantum suite registry. It
//! exposes FN-DSA key generation, signing and — the operation the PCA verifier actually performs —
//! **signature verification**, for the two standardized parameter sets FN-DSA-512 (NIST security
//! category 1) and FN-DSA-1024 (category 5).
//!
//! ## What is vetted (no hand-rolled crypto)
//! Every cryptographic step runs through the pure-Rust **`fn-dsa` crate family by Thomas Pornin**
//! (the Falcon author) — `fn-dsa-kgen` (ntrugen key generation), `fn-dsa-sign` (the Falcon
//! `sign_dyn` Gaussian sampler + FFT) and `fn-dsa-vrfy` (NTT verification over `q = 12289`), tied
//! together by the `fn-dsa` meta crate and its `fn-dsa-comm` common core. This is the
//! RustSec-recommended successor to `pqcrypto-falcon`. NONE of the lattice math, the FFT/NTT, the
//! discrete-Gaussian sampler, or the key/signature encodings is reimplemented here.
//!
//! This crate adds only non-cryptographic glue: a SHAKE256-seeded deterministic RNG (so keygen and
//! signing are reproducible for known-answer tests — built from `fn-dsa`'s own re-exported SHAKE256)
//! and the fixed-buffer C-ABI marshalling below.
//!
//! ## Standard status (honest note)
//! FN-DSA is **FIPS 206, finalized-pending**: NIST has not yet published the final text. The `fn-dsa`
//! crate tracks the draft and warns that key encodings / pre-hashing / domain separation MAY change
//! before FN-DSA 1.0, so keys and signatures produced here are not guaranteed interoperable with the
//! eventual final standard. Track the standard and re-pin the crate when FIPS 206 lands.
//!
//! Signing/keygen are **best-effort** constant-time: FN-DSA (Falcon) signing is a known hard target
//! for constant-time implementation because of its floating-point Gaussian sampler, and on
//! wasm32 (no native IEEE-754 ABI guarantee) `fn-dsa` uses a portable FP emulation that makes a best
//! effort at constant time. **Verification** — the PCA verifier's only use of this backend — is the
//! public-key operation: it touches no secret and uses no floating point.
//!
//! ## ABI (mirrors @atlasauth/pca-mpc-wasm)
//! `#![no_std]`, no allocator, no imports. All I/O is through fixed static buffers in linear memory
//! whose addresses the `ptr_*` exports return; the module instantiates with an empty import object
//! and is driven single-threaded (write inputs -> call op -> read an output buffer).

// no_std applies ONLY to the wasm32 artifact (the shipped module). On the host — including the
// `cargo test` KAT harness and the cdylib cargo also builds there — std is always available, so this
// never trips the "no allocator / panic_handler required" errors a host cdylib would otherwise hit.
#![cfg_attr(all(target_arch = "wasm32", not(feature = "capi")), no_std)]

use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, CryptoRng, KeyPairGenerator,
    KeyPairGeneratorStandard, RngCore, RngError, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_1024, FN_DSA_LOGN_512, HASH_ID_RAW, SHAKE256,
};

#[cfg(all(target_arch = "wasm32", not(feature = "capi")))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Reached only on a genuine internal bug (e.g. an unsupported degree slipping past the guards
    // below) — abort rather than unwind, matching the no_std/panic=abort ABI.
    core::arch::wasm32::unreachable()
}

// --- Global allocator: provably never invoked. ---
// `fn-dsa-kgen`/`fn-dsa-sign` keep ALL working state in fixed-size arrays inside the generator /
// key structs (no `Vec`/`Box` anywhere in their source), but the crate graph still *references* the
// `alloc` symbol at link time (unstrippable Drop/zeroize glue), so a `#![no_std]` cdylib must define
// a global allocator. No FN-DSA code path actually allocates: this `Abort` allocator traps on any
// call, and the full keygen→sign→verify round-trip (both FN-DSA-512 and -1024) runs green against it
// in WebAssembly, proving the allocator is never reached. It exists only to satisfy the linker; it is
// not a heap. (This is a linker requirement, NOT a dependency on `std`.)
#[cfg(all(target_arch = "wasm32", not(feature = "capi")))]
mod wasm_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    pub struct Abort;

    // SAFETY: trivially correct — every method diverges, so it never returns an invalid pointer.
    // It is sound precisely because no live FN-DSA code path allocates (verified end-to-end in wasm).
    unsafe impl GlobalAlloc for Abort {
        unsafe fn alloc(&self, _: Layout) -> *mut u8 {
            core::arch::wasm32::unreachable()
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
            core::arch::wasm32::unreachable()
        }
    }

    #[global_allocator]
    static ALLOCATOR: Abort = Abort;
}

// --- FN-DSA degree tags (logn), the two standardized parameter sets. ---
const LOGN_512: u32 = FN_DSA_LOGN_512; // 9
const LOGN_1024: u32 = FN_DSA_LOGN_1024; // 10

// --- Maximum fixed-buffer sizes (the 1024 parameter set is the larger of the two). ---
const VK_CAP: usize = vrfy_key_size(LOGN_1024); // 1793
const SK_CAP: usize = sign_key_size(LOGN_1024); // 2369
const SIG_CAP: usize = signature_size(LOGN_1024); // 1280
const SEED_BYTES: usize = 32; // deterministic RNG seed
const MSG_CAP: usize = 8192; // message to sign / verify

/// Map a caller-supplied degree tag onto the FN-DSA `logn` for a supported parameter set.
#[inline]
fn logn_of(tag: i32) -> Option<u32> {
    match tag {
        512 => Some(LOGN_512),
        1024 => Some(LOGN_1024),
        _ => None,
    }
}

// ===================================================================================================
// Deterministic RNG: SHAKE256(seed) as an extendable output, exposed as a CryptoRng. Used ONLY to
// make keygen/signing reproducible for known-answer tests; production callers seed it from a CSPRNG.
// This is `fn-dsa`'s own re-exported SHAKE256 (fn-dsa-comm), not a hand-rolled hash.
// ===================================================================================================
struct SeededRng(SHAKE256);

impl SeededRng {
    fn new(seed: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        sh.flip();
        Self(sh)
    }
}

impl CryptoRng for SeededRng {}
impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.extract(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.extract(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.extract(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.0.extract(dest);
        Ok(())
    }
}

// ===================================================================================================
// Pure-Rust core (operates on slices; the extern "C" exports below drive it over the static buffers,
// and the native KAT tests call it directly).
// ===================================================================================================

/// Deterministic FN-DSA key generation (vetted `fn-dsa-kgen` via `KeyPairGeneratorStandard`). The
/// 32-byte `seed` seeds a SHAKE256 CryptoRng; `sk`/`vk` MUST be exactly the sizes for `logn`.
fn keygen_into(logn: u32, seed: &[u8], sk: &mut [u8], vk: &mut [u8]) {
    let mut rng = SeededRng::new(seed);
    let mut kg = KeyPairGeneratorStandard::default();
    kg.keygen(logn, &mut rng, sk, vk);
}

/// FN-DSA signing (vetted `fn-dsa-sign`): decode the signing key, sign `msg` (raw, no pre-hash) into
/// `sig` with a SHAKE256-seeded RNG. Returns false if the key fails to decode or signing fails.
fn sign_into(seed: &[u8], sk_bytes: &[u8], msg: &[u8], sig: &mut [u8]) -> bool {
    let mut rng = SeededRng::new(seed);
    match SigningKeyStandard::decode(sk_bytes) {
        Some(mut sk) => sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, sig).is_some(),
        None => false,
    }
}

/// FN-DSA verification (vetted `fn-dsa-vrfy`): decode the verifying key and check `sig` over `msg`
/// (raw, no pre-hash). Returns false if the key fails to decode or the signature is invalid.
fn verify_into(vk_bytes: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    match VerifyingKeyStandard::decode(vk_bytes) {
        Some(vk) => vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
        None => false,
    }
}

#[cfg(not(feature = "capi"))]
mod wasm_abi {
    use super::*;

    // --- Fixed linear-memory I/O buffers (stable for the life of the instance). ---
    static mut SEED: [u8; SEED_BYTES] = [0u8; SEED_BYTES];
    static mut VK: [u8; VK_CAP] = [0u8; VK_CAP];
    static mut SK: [u8; SK_CAP] = [0u8; SK_CAP];
    static mut SIG: [u8; SIG_CAP] = [0u8; SIG_CAP];
    static mut MSG: [u8; MSG_CAP] = [0u8; MSG_CAP];

    // ===================================================================================================
    // C-ABI exports (fixed static buffers; mirror @atlasauth/pca-mpc-wasm's ptr_* + op style).
    // ===================================================================================================

    #[no_mangle]
    pub extern "C" fn ptr_seed() -> *mut u8 {
        core::ptr::addr_of_mut!(SEED) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_vk() -> *mut u8 {
        core::ptr::addr_of_mut!(VK) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_sk() -> *mut u8 {
        core::ptr::addr_of_mut!(SK) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_sig() -> *mut u8 {
        core::ptr::addr_of_mut!(SIG) as *mut u8
    }
    #[no_mangle]
    pub extern "C" fn ptr_msg() -> *mut u8 {
        core::ptr::addr_of_mut!(MSG) as *mut u8
    }

    /// Verifying-key length (bytes) for a degree tag (512 / 1024); -1 if the tag is unsupported.
    #[no_mangle]
    pub extern "C" fn len_vk(tag: i32) -> i32 {
        match logn_of(tag) {
            Some(logn) => vrfy_key_size(logn) as i32,
            None => -1,
        }
    }
    /// Signing-key length (bytes) for a degree tag; -1 if unsupported.
    #[no_mangle]
    pub extern "C" fn len_sk(tag: i32) -> i32 {
        match logn_of(tag) {
            Some(logn) => sign_key_size(logn) as i32,
            None => -1,
        }
    }
    /// Signature length (bytes) for a degree tag; -1 if unsupported.
    #[no_mangle]
    pub extern "C" fn len_sig(tag: i32) -> i32 {
        match logn_of(tag) {
            Some(logn) => signature_size(logn) as i32,
            None => -1,
        }
    }
    /// Deterministic-RNG seed length (bytes).
    #[no_mangle]
    pub extern "C" fn len_seed() -> i32 {
        SEED_BYTES as i32
    }
    /// Message-buffer capacity (bytes).
    #[no_mangle]
    pub extern "C" fn cap_msg() -> i32 {
        MSG_CAP as i32
    }

    /// `(SK, VK) = FN-DSA.KeyGen(tag; SEED)` — deterministic in SEED. Returns 1 on success, 0 if the
    /// degree tag is unsupported.
    #[no_mangle]
    pub extern "C" fn fndsa_keygen(tag: i32) -> i32 {
        let logn = match logn_of(tag) {
            Some(l) => l,
            None => return 0,
        };
        let sk_len = sign_key_size(logn);
        let vk_len = vrfy_key_size(logn);
        let seed = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SEED) as *const u8, SEED_BYTES) };
        let sk = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(SK) as *mut u8, sk_len) };
        let vk = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(VK) as *mut u8, vk_len) };
        keygen_into(logn, seed, sk, vk);
        1
    }

    /// `SIG = FN-DSA.Sign(tag, SK, MSG[..msg_len]; SEED)`. Returns 1 on success, 0 on an unsupported
    /// tag, an over-long message, or a signing/decoding failure.
    #[no_mangle]
    pub extern "C" fn fndsa_sign(tag: i32, msg_len: i32) -> i32 {
        let logn = match logn_of(tag) {
            Some(l) => l,
            None => return 0,
        };
        let n = msg_len as usize;
        if msg_len < 0 || n > MSG_CAP {
            return 0;
        }
        let sk_len = sign_key_size(logn);
        let sig_len = signature_size(logn);
        let seed = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SEED) as *const u8, SEED_BYTES) };
        let sk = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SK) as *const u8, sk_len) };
        let msg = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(MSG) as *const u8, n) };
        let sig = unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(SIG) as *mut u8, sig_len) };
        i32::from(sign_into(seed, sk, msg, sig))
    }

    /// `FN-DSA.Verify(tag, VK, SIG, MSG[..msg_len])`. Returns 1 if the signature is valid, else 0 (also
    /// 0 for an unsupported tag or an over-long message).
    #[no_mangle]
    pub extern "C" fn fndsa_verify(tag: i32, msg_len: i32) -> i32 {
        let logn = match logn_of(tag) {
            Some(l) => l,
            None => return 0,
        };
        let n = msg_len as usize;
        if msg_len < 0 || n > MSG_CAP {
            return 0;
        }
        let vk_len = vrfy_key_size(logn);
        let sig_len = signature_size(logn);
        let vk = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(VK) as *const u8, vk_len) };
        let sig = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SIG) as *const u8, sig_len) };
        let msg = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(MSG) as *const u8, n) };
        i32::from(verify_into(vk, sig, msg))
    }

}

// ===================================================================================================
// Host C ABI (cargo feature "capi", libfndsa): caller-owned buffers, no global state, thread-safe.
// Mirrors the wasm exports one for one (same parameter tags, sizes, 32-byte SHAKE256 seeds, 8192-byte
// message cap, raw no-pre-hash FN-DSA). Every pointer carries its length; a null pointer or a length
// other than the exact fixed size is refused and nothing is written. See pca_fndsa.h.
// ===================================================================================================
#[cfg(feature = "capi")]
pub mod capi {
    use super::*;

    pub const FNDSA_OK: i32 = 0;
    pub const FNDSA_ERR_ARG: i32 = -1; // null pointer, wrong length, unsupported tag, over-long message
    pub const FNDSA_ERR_INTERNAL: i32 = -2; // key failed to decode / signing failed
    pub const FNDSA_ERR_INVALID: i32 = -3; // verify: well-formed input, signature does not verify

    unsafe fn rd<'a>(p: *const u8, len: usize, want: usize) -> Option<&'a [u8]> {
        if p.is_null() || len != want {
            return None;
        }
        Some(core::slice::from_raw_parts(p, len))
    }
    unsafe fn wr<'a>(p: *mut u8, len: usize, want: usize) -> Option<&'a mut [u8]> {
        if p.is_null() || len != want {
            return None;
        }
        Some(core::slice::from_raw_parts_mut(p, len))
    }
    // A message may be empty: a null pointer is accepted only with length 0.
    unsafe fn rd_msg<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
        if len > MSG_CAP || (p.is_null() && len != 0) {
            return None;
        }
        Some(if len == 0 { &[] } else { core::slice::from_raw_parts(p, len) })
    }

    #[no_mangle]
    pub extern "C" fn fndsa_len_vk(tag: i32) -> isize {
        logn_of(tag).map_or(-1, |l| vrfy_key_size(l) as isize)
    }
    #[no_mangle]
    pub extern "C" fn fndsa_len_sk(tag: i32) -> isize {
        logn_of(tag).map_or(-1, |l| sign_key_size(l) as isize)
    }
    #[no_mangle]
    pub extern "C" fn fndsa_len_sig(tag: i32) -> isize {
        logn_of(tag).map_or(-1, |l| signature_size(l) as isize)
    }
    #[no_mangle]
    pub extern "C" fn fndsa_len_seed() -> usize {
        SEED_BYTES
    }
    #[no_mangle]
    pub extern "C" fn fndsa_cap_msg() -> usize {
        MSG_CAP
    }

    /// `(sk, vk) = FN-DSA.KeyGen(tag; seed)`, deterministic in the 32-byte seed.
    #[no_mangle]
    pub unsafe extern "C" fn fndsa_c_keygen(
        tag: i32, seed: *const u8, seed_len: usize, sk: *mut u8, sk_len: usize, vk: *mut u8, vk_len: usize,
    ) -> i32 {
        let Some(logn) = logn_of(tag) else { return FNDSA_ERR_ARG };
        let (Some(seed), Some(sk), Some(vk)) = (
            rd(seed, seed_len, SEED_BYTES),
            wr(sk, sk_len, sign_key_size(logn)),
            wr(vk, vk_len, vrfy_key_size(logn)),
        ) else { return FNDSA_ERR_ARG };
        // keygen has no failure path past argument validation, so it writes the secret key in place.
        keygen_into(logn, seed, sk, vk);
        FNDSA_OK
    }

    /// `sig = FN-DSA.Sign(tag, sk, msg; seed)`, deterministic in the 32-byte seed (the caller supplies
    /// fresh randomness as the seed in production).
    #[no_mangle]
    pub unsafe extern "C" fn fndsa_c_sign(
        tag: i32, sk: *const u8, sk_len: usize, msg: *const u8, msg_len: usize, seed: *const u8, seed_len: usize,
        sig: *mut u8, sig_len: usize,
    ) -> i32 {
        let Some(logn) = logn_of(tag) else { return FNDSA_ERR_ARG };
        let (Some(sk), Some(msg), Some(seed), Some(sig)) = (
            rd(sk, sk_len, sign_key_size(logn)),
            rd_msg(msg, msg_len),
            rd(seed, seed_len, SEED_BYTES),
            wr(sig, sig_len, signature_size(logn)),
        ) else { return FNDSA_ERR_ARG };
        let mut sig_t = std::vec![0u8; sig.len()];
        if !sign_into(seed, sk, msg, &mut sig_t) {
            return FNDSA_ERR_INTERNAL;
        }
        sig.copy_from_slice(&sig_t);
        FNDSA_OK
    }

    /// `FN-DSA.Verify(tag, vk, sig, msg)`: 0 valid, -3 well-formed but invalid, -1 refused input.
    #[no_mangle]
    pub unsafe extern "C" fn fndsa_c_verify(
        tag: i32, vk: *const u8, vk_len: usize, sig: *const u8, sig_len: usize, msg: *const u8, msg_len: usize,
    ) -> i32 {
        let Some(logn) = logn_of(tag) else { return FNDSA_ERR_ARG };
        let (Some(vk), Some(sig), Some(msg)) = (
            rd(vk, vk_len, vrfy_key_size(logn)),
            rd(sig, sig_len, signature_size(logn)),
            rd_msg(msg, msg_len),
        ) else { return FNDSA_ERR_ARG };
        if verify_into(vk, sig, msg) { FNDSA_OK } else { FNDSA_ERR_INVALID }
    }
}

// ===================================================================================================
// Native KAT / correctness tests (run on the host with `cargo test`, which links std).
// ===================================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // tiny deterministic byte generator (test-only): SHAKE256(tag) -> n bytes, via fn-dsa's SHAKE256.
    fn gen(tag: &[u8], n: usize) -> std::vec::Vec<u8> {
        let mut sh = SHAKE256::new();
        sh.inject(tag);
        sh.flip();
        let mut out = std::vec![0u8; n];
        sh.extract(&mut out);
        out
    }

    #[test]
    fn standardized_sizes_match_fips206_parameter_sets() {
        // FN-DSA-512 (logn=9): vk 897, sk 1281+, sig 666. FN-DSA-1024 (logn=10): vk 1793, sig 1280.
        assert_eq!(vrfy_key_size(LOGN_512), 897);
        assert_eq!(signature_size(LOGN_512), 666);
        assert_eq!(vrfy_key_size(LOGN_1024), 1793);
        assert_eq!(signature_size(LOGN_1024), 1280);
        // The static buffers are sized for the larger (1024) set.
        assert_eq!(VK_CAP, 1793);
        assert_eq!(SIG_CAP, 1280);
    }

    // KAT 1 — full keygen/sign/verify round-trip for BOTH parameter sets, over several messages.
    // This is the end-to-end correctness property of the vetted FN-DSA implementation.
    fn roundtrip_for(logn: u32, tag: i32) {
        let sk_len = sign_key_size(logn);
        let vk_len = vrfy_key_size(logn);
        let sig_len = signature_size(logn);
        for t in 0u8..6 {
            let seed = gen(&[1, tag as u8, t], SEED_BYTES);
            let mut sk = std::vec![0u8; sk_len];
            let mut vk = std::vec![0u8; vk_len];
            keygen_into(logn, &seed, &mut sk, &mut vk);

            let msg = gen(&[2, tag as u8, t], 64 + t as usize);
            let sig_seed = gen(&[3, tag as u8, t], SEED_BYTES);
            let mut sig = std::vec![0u8; sig_len];
            assert!(sign_into(&sig_seed, &sk, &msg, &mut sig), "signing must succeed");

            assert!(verify_into(&vk, &sig, &msg), "a genuine signature must verify (tag={tag}, t={t})");

            // Tamper the signature -> must fail.
            let mut bad_sig = sig.clone();
            bad_sig[sig_len / 2] ^= 0x01;
            assert!(!verify_into(&vk, &bad_sig, &msg), "a tampered signature must not verify");

            // Tamper the message -> must fail.
            let mut bad_msg = msg.clone();
            bad_msg[0] ^= 0x01;
            assert!(!verify_into(&vk, &sig, &bad_msg), "a signature must not verify a modified message");

            // A different key must not verify this signature.
            let seed2 = gen(&[9, tag as u8, t], SEED_BYTES);
            let mut sk2 = std::vec![0u8; sk_len];
            let mut vk2 = std::vec![0u8; vk_len];
            keygen_into(logn, &seed2, &mut sk2, &mut vk2);
            assert!(!verify_into(&vk2, &sig, &msg), "a foreign key must not verify the signature");
        }
    }

    #[test]
    fn fndsa_512_roundtrip_and_tamper() {
        roundtrip_for(LOGN_512, 512);
    }

    #[test]
    fn fndsa_1024_roundtrip_and_tamper() {
        roundtrip_for(LOGN_1024, 1024);
    }

    // KAT 2 — keygen is deterministic in the seed: the same seed yields identical sk/vk bytes.
    #[test]
    fn keygen_is_deterministic_in_seed() {
        let seed = std::vec![7u8; SEED_BYTES];
        let (sk_len, vk_len) = (sign_key_size(LOGN_512), vrfy_key_size(LOGN_512));
        let mut sk1 = std::vec![0u8; sk_len];
        let mut vk1 = std::vec![0u8; vk_len];
        keygen_into(LOGN_512, &seed, &mut sk1, &mut vk1);
        let mut sk2 = std::vec![0u8; sk_len];
        let mut vk2 = std::vec![0u8; vk_len];
        keygen_into(LOGN_512, &seed, &mut sk2, &mut vk2);
        assert_eq!(sk1, sk2, "keygen signing key must be deterministic in the seed");
        assert_eq!(vk1, vk2, "keygen verifying key must be deterministic in the seed");
    }

    // Degree-tag mapping rejects unsupported parameter sets.
    #[test]
    fn unsupported_degree_tags_are_rejected() {
        assert_eq!(logn_of(512), Some(LOGN_512));
        assert_eq!(logn_of(1024), Some(LOGN_1024));
        assert_eq!(logn_of(256), None);
        assert_eq!(logn_of(768), None);
    }
}
