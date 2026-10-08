# @atlasauth/pca-fndsa-wasm

The **FN-DSA (Falcon, FIPS 206) signature backend** for `@atlasauth/pca`'s post-quantum suite
registry. It provides key generation, signing and — the operation the PCA verifier actually performs
— **signature verification**, for the two standardized parameter sets:

| variant        | security | verifying key | signing key | signature |
| -------------- | -------- | ------------- | ----------- | --------- |
| `fn-dsa-512`   | cat. 1   | 897 B         | 1345 B      | 666 B     |
| `fn-dsa-1024`  | cat. 5   | 1793 B        | 2369 B      | 1280 B    |

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

## Suite-registry wiring (next pass)

This package is self-contained and ready for a **separate** later pass to register `fn-dsa-512` and
`fn-dsa-1024` as signature suites in `@atlasauth/pca`'s `pq.ts` suite registry. That wiring is out of
scope here; this crate owns only the vetted FN-DSA backend + its binding and tests.
