# @atlasauth/pca-fndsa-wasm

> Maturity: **hardened** (hardened, formally verified (model), awaiting final standard and independent audit). The engineering is done and evidenced by tests and a mutation gate; it awaits the final FIPS 206 text (the draft's key and signature encodings may change before the crate's 1.0) and an independent review of the wasm binding. It is never production until then, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The **FN-DSA (Falcon, FIPS 206) signature backend** for `@atlasauth/pca`'s post-quantum suite
registry. It provides key generation, signing and — the operation the PCA verifier actually performs
— **signature verification**, for the two standardized parameter sets:

| variant        | security | verifying key | signing key | signature |
| -------------- | -------- | ------------- | ----------- | --------- |
| `fn-dsa-512`   | cat. 1   | 897 B         | 1345 B      | 666 B     |
| `fn-dsa-1024`  | cat. 5   | 1793 B        | 2369 B      | 1280 B    |

## Install

```sh
npm i @atlasauth/pca-fndsa-wasm
```

This is the backend `@atlasauth/pca` uses for its FN-DSA suites; you normally get it as a dependency of `@atlasauth/pca`.

Node >= 20. The `.wasm` file ships inside the package and is loaded relative to the installed `dist/` directory; no build step or Rust toolchain is needed to use it.

## The vetted boundary (no hand-rolled crypto)

Every FN-DSA / Falcon operation — ntrugen key generation, the Falcon `sign_dyn` Gaussian sampler +
FFT, and NTT signature verification — runs through the pure-Rust **`fn-dsa` crate family by Thomas
Pornin** (the Falcon author), crates.io `0.4.0`, compiled to WebAssembly (`crate/`). This is the
[RustSec](https://rustsec.org/)-recommended successor to the unmaintained `pqcrypto-falcon`. The meta
crate ties together `fn-dsa-kgen` / `fn-dsa-sign` / `fn-dsa-vrfy` / `fn-dsa-comm`. **None** of the
lattice math, the FFT/NTT, the discrete-Gaussian sampler or the key/signature encodings is
reimplemented here.

This crate adds only non-cryptographic glue: a SHAKE256-seeded deterministic RNG (built from
`fn-dsa`'s own re-exported SHAKE256, so keygen/signing are reproducible for known-answer tests) and
the fixed-buffer C-ABI marshalling in `crate/src/lib.rs`.

> `fn-dsa` is `#![no_std]`, uses **no allocator** (all working state is in fixed-size arrays inside
> the key / generator structs — there is no `Vec`/`Box` anywhere in its source) and has no external
> deps beyond `rand_core` + `zeroize`, so it targets `wasm32-unknown-unknown` as pure Rust with no
> std and **no imports** (the module instantiates with an empty import object). Unlike `pqc_kyber`,
> no `[patch.crates-io]` vendor copy is needed. The `#![no_std]` cdylib must still *define* a global
> allocator because the crate graph references the `alloc` symbol (unstrippable Drop/zeroize glue);
> the shipped wasm defines an **abort-on-allocate** allocator that is provably never invoked — the
> full keygen → sign → verify round-trip runs green against it in WebAssembly for both parameter sets.

## API

```ts
import {
  keygen, sign, verify,            // FN-DSA keygen / sign / verify (per variant)
  sizes,                           // byte lengths for a variant's vk / sk / sig
  SEED_BYTES, MSG_CAP,             // 32; max message length
  type FnDsaVariant,               // 'fn-dsa-512' | 'fn-dsa-1024'
} from '@atlasauth/pca-fndsa-wasm';

const { verifyingKey, signingKey } = keygen('fn-dsa-512', seed /* 32 B */);
const sig = sign('fn-dsa-512', signingKey, message, sigSeed /* 32 B */);
const ok  = verify('fn-dsa-512', verifyingKey, message, sig); // -> boolean
```

The WASM is `no_std`, allocator-free at runtime, instantiates with an **empty import object**, and is
driven through fixed static buffers in linear memory (mirrors `@atlasauth/pca-mpc-wasm` /
`@atlasauth/pca-mpc-lwe-ot-wasm`). Messages and signatures are the raw FN-DSA scheme with
`DOMAIN_NONE` and `HASH_ID_RAW` (no caller pre-hash).

## Build & test

```sh
pnpm build:wasm   # cargo build --release --target wasm32-unknown-unknown + copy artifact + cargo clean
pnpm build        # tsc
pnpm test         # vitest: round-trips, cross-implementation vectors and negative cases through the wasm binding
```

Native round-trip and tamper tests for the FN-DSA arithmetic live in `crate/src/lib.rs` (`cargo test`).

## Fail-closed table

Each row is pinned by a test that asserts the exact outcome.

| Missing or wrong | Result |
|---|---|
| Unknown parameter set | `FnDsaError` "unsupported FN-DSA variant: ..." |
| Seed, signing key, verifying key or signature of the wrong size | `FnDsaError` naming the field, expected and actual size |
| Message longer than `MSG_CAP` | `FnDsaError` (sign and verify); exactly `MSG_CAP` is accepted |
| Well-sized but undecodable verifying key, all-zero or all-0xFF signature | `verify` false |
| Well-sized but undecodable signing key | `FnDsaError` "wasm sign failed" |
| `.wasm` file missing or corrupt | importing the package throws; there is no JavaScript fallback |
| Signature from the other parameter set | `FnDsaError` (size mismatch) |

## Standard status (honest note)

FN-DSA is **FIPS 206, finalized-pending**: NIST has not yet published the final standard text. The
`fn-dsa` crate tracks the draft and warns that **key encodings, message pre-hashing and domain
separation MAY change before its 1.0 release**, so keys and signatures produced here are not
guaranteed interoperable with the eventual final FN-DSA standard. **Track the standard and re-pin the
crate when FIPS 206 lands.**

- **Signing / keygen** are **best-effort constant-time**: FN-DSA (Falcon) signing is a known-hard
  target for constant-time implementation because of its floating-point discrete-Gaussian sampler,
  and on `wasm32` (no native IEEE-754 ABI guarantee) `fn-dsa` uses a portable FP emulation that makes
  a best effort at constant time. This is a documented side-channel boundary of the primitive, not a
  break of its security.
- **Verification** — the PCA verifier's only use of this backend — is the **public-key operation**:
  it touches no secret and uses no floating point.

## What is validated, and what is not

**No official test vectors exist for FN-DSA yet.** As checked on 2026-10-09, the NIST ACVP-Server
repository has no FN-DSA/Falcon/FIPS 206 test files (it has ML-DSA and SLH-DSA), and FIPS 206 is still a
draft, so no official FN-DSA vectors are used. Nothing in this package is claimed to be validated against
NIST FN-DSA vectors.

What the official **Falcon round-3** known-answer files (the original Falcon submission to the NIST PQC
archive, 100 entries each for 512 and 1024, pinned by sha256 in `test-vectors/falcon-round3/`) do cover,
and what they cannot:

- **Keys: usable after transcoding.** Original Falcon and the FN-DSA draft encode the same key material
  differently (bit order of the packed coefficients, the public key in coefficient form versus the NTT
  domain, an extra public-key hash in the FN-DSA signing key). Each official key pair is transcoded, a
  signature is produced through this backend and it verifies under the transcoded original public key, for
  all 200 entries. The untranscoded round-3 encodings are rejected.
- **Signatures: not compatible.** Round-3 signatures hash a different input and use a variable-length
  container, so FN-DSA verification rejects them. The test asserts this rather than assuming it.
- **Key generation from the KAT seeds: not tested.**

What the tests do cover:

- **Cross-implementation, both directions.** Signatures produced by an independent implementation of the
  same draft (the C library `pornin/c-fn-dsa` at a pinned commit; a separate code base and language from
  the Rust `fn-dsa` crate in the wasm) verify in the wasm, and signatures produced by the wasm are accepted
  by the C implementation. Both FN-DSA-512 and FN-DSA-1024, with empty, short and 1000-byte messages.
  The vectors are generated, not official, and are labelled as such in the fixture.
- **Negative cases.** For every cross-implementation signature, every single-bit flip of the signature is
  rejected, as are a modified message, a different verifying key, a wrong header byte, non-zero padding
  and a malformed verifying key. Wrong-size inputs throw an error that names the field and the expected
  size.
- **Determinism.** Keys and signatures reproduce bit-for-bit from their seeds.

Limits:

- The C implementation shares its author (and its reading of the draft) with the Rust crate, so agreement
  shows the two code bases implement the same draft correctly, not that the draft is what NIST will publish.
- Original-Falcon libraries (for example liboqs 0.16.0) use different secret-key encodings and message
  hashing from the FN-DSA draft: they reject FN-DSA secret keys and this backend rejects theirs. They cannot
  be used to cross-check signatures.
- Seeded key generation is not specified by the draft; the C and Rust implementations derive different keys
  from the same seed, so keys are compared by interoperability, not equality.
- Constant-time behavior of signing and key generation on wasm has not been measured.

## Use with @atlasauth/pca

`@atlasauth/pca` registers `fn-dsa-512` and `fn-dsa-1024` as signature suites and loads this package as its verification and signing backend. If the backend cannot be loaded, FN-DSA verification fails closed.

## Build provenance

The shipped `wasm/pca_fndsa_wasm.wasm` is built from the Rust source in `crate/` (with its `Cargo.lock`) and is bit-for-bit reproducible.

| | |
| --- | --- |
| artifact | `wasm/pca_fndsa_wasm.wasm` |
| sha256 | `95c1cd16fb135c4a524a5ff19548d5d1a5ce43fc1f00e19f4465b5111d8903ad` |
| target | `wasm32-unknown-unknown`, `--release --locked` via `crate/build-wasm.sh` (path-remapped; opt-level `s`, LTO, `panic = "abort"`, stripped) |
| toolchain | rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0 |
| locked crates | fn-dsa 0.4.0 (and its locked transitive crates) |

Verify: `bash crate/build-wasm.sh && shasum -a 256 wasm/pca_fndsa_wasm.wasm` (needs `rustup target add wasm32-unknown-unknown`). The script passes `--remap-path-prefix` for the crate, home, cargo registry and rustc sysroot and `-Cdebuginfo=0`, so the build is path-independent: no host path is embedded, and the same sha256 results from any checkout location.

## Formal evidence

Suite pinning, `PcaComp/Wrap.lean`. What a machine checked, and what it did not.

- Proved: the verifier takes the suite from the pinned key, never from the signature, so a signature claiming another suite is rejected and no two suites verify one key (`pinned_accepts_only_pinned_suite`, `no_downgrade`); the hybrid wrapper accepts only if both components accept (`hybrid_needs_both`), and the EasyCrypt AND-combiner results H-1, H-3 and H-4 carry the security argument; the pinned-key rule is PIN / PIN-2.
- Assumed (named): NA-PQ (FN-DSA security, FIPS 206 draft), NA-ED.
- Not modelled: FN-DSA itself, floating-point and timing behaviour, the wasm binding.

Reproduce: `formal/computational/check.sh lean` (core Lean 4, no Mathlib; it also prints the axioms each theorem uses, only `propext`, `Classical.choice` and `Quot.sound`). The models are hand-written from the code and are NOT statements about the shipped implementation: the independent audit of the implementation is still required, and this package stays hardened until then.

## License

MIT - see LICENSE.
