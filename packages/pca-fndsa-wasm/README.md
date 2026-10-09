# @atlasauth/pca-fndsa-wasm

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
pnpm test         # vitest (KATs through the wasm binding)
```

Native KATs for the FN-DSA arithmetic (keygen/sign/verify round-trip + tamper/foreign-key rejection,
deterministic keygen, size and degree-tag checks for both parameter sets) live in `crate/src/lib.rs`
(`cargo test`).

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

## Use with @atlasauth/pca

`@atlasauth/pca` registers `fn-dsa-512` and `fn-dsa-1024` as signature suites and loads this package as its verification and signing backend. If the backend cannot be loaded, FN-DSA verification fails closed.

## Build provenance

The shipped `wasm/pca_fndsa_wasm.wasm` is built from the Rust source in `crate/` (with its `Cargo.lock`) and is bit-for-bit reproducible.

| | |
| --- | --- |
| artifact | `wasm/pca_fndsa_wasm.wasm` |
| sha256 | `48e322e3a92be37c53f6c37b894b4cf1cab659269396b5d28c6929b67e678abe` |
| target | `wasm32-unknown-unknown`, `--release --locked` (opt-level `s`, LTO, `panic = "abort"`, stripped) |
| toolchain | rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0 |
| locked crates | fn-dsa 0.4.0 (and its locked transitive crates) |

Verify: `cd crate && cargo build --release --locked --target wasm32-unknown-unknown && shasum -a 256 target/wasm32-unknown-unknown/release/pca_fndsa_wasm.wasm` (needs `rustup target add wasm32-unknown-unknown`).

## License

MIT - see LICENSE.
