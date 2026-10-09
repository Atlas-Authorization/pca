# @atlasauth/pca-mpc-wasm

A **constant-time** Ed25519 base-OT curve core for `@atlasauth/pca-mpc`, compiled to WebAssembly.

`@atlasauth/pca-mpc` ships a correct, malicious-hardened pure-JS prime-order group, but its BigInt modular arithmetic is **not** constant-time and cannot be in pure JS (a language/runtime boundary); the pure-JS path remains the fallback. The base OT multiplies **secret**
scalars into the curve (`S = y·B`, `T = y·S`, `R = x·B (+S)`, `y·R`, `x·S`), which is exactly where a
timing side-channel would leak the receiver's choice bit or the sender's `y`.

This package compiles those operations from [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek)
(audited, constant-time field + scalar multiplication) to a tiny, import-free WebAssembly module
(`wasm/pca_mpc_wasm.wasm`, ~45 KB) and re-exposes the base-OT curve-op surface of the pure-JS curve module on top of it.

## Install

```sh
npm i @atlasauth/pca-mpc-wasm
```

Node >= 20. The `.wasm` file ships inside the package and is loaded relative to the installed `dist/` directory; no build step or Rust toolchain is needed to use it.

## Ops exposed (drop-in for the pure-JS curve module)

`mulBase(k)` · `mul(k, P)` · `add(A, B)` · `sub(A, B)` · `neg(P)` · `encodePoint` / `decodePoint` ·
`isOnCurve` · `isIdentity` · `isInSubgroup` · `assertInSubgroup` · `equal` · `BASE` · `IDENTITY` ·
`L` · `Q`.

The constant-time, secret-dependent operations — `mulBase` and `mul` — run entirely inside the wasm.

## Point encoding

A point is its **canonical 32-byte compressed Ed25519 encoding** (little-endian `y`, sign of `x` in
the top bit): the bytes `@noble/curves` emits from `point.toRawBytes()` and the only serialization
`curve25519-dalek` exposes (it has no public affine accessor). This is more standard than the pure-JS curve module's
bespoke 64-byte affine `x‖y` form; the two carry the same point and are inter-convertible. The
parity test cross-checks this 32-byte form against `@noble/curves` for **byte-identical** output.

Scalars are `bigint`, reduced `mod L` exactly as the pure-JS curve module does, then handed to the wasm as
32-byte little-endian.

## Build

```sh
rustup target add wasm32-unknown-unknown   # once
pnpm --filter @atlasauth/pca-mpc-wasm build:wasm   # rebuild wasm/pca_mpc_wasm.wasm
pnpm --filter @atlasauth/pca-mpc-wasm test         # WASM-vs-@noble parity
```

## Status

Experimental; the constant-time claim covers the secret-scalar operations inside the wasm module and has not been independently audited.

## Build provenance

The shipped `wasm/pca_mpc_wasm.wasm` is built from the Rust source in `crate/` (with its `Cargo.lock`) and is bit-for-bit reproducible.

| | |
| --- | --- |
| artifact | `wasm/pca_mpc_wasm.wasm` |
| sha256 | `ee37878d3b7955e774be0f6771b2e680c2e2c2d555fa5f870aedbfb636bc2407` |
| target | `wasm32-unknown-unknown`, `--release --locked` (opt-level `s`, LTO, `panic = "abort"`, stripped) |
| toolchain | rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0 |
| locked crates | curve25519-dalek 4.1.3 (and its locked transitive crates) |

Verify: `cd crate && cargo build --release --locked --target wasm32-unknown-unknown && shasum -a 256 target/wasm32-unknown-unknown/release/pca_mpc_wasm.wasm` (needs `rustup target add wasm32-unknown-unknown`).

## License

MIT - see LICENSE.
