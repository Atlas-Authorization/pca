# @atlasauth/pca-mpc-wasm

A **genuinely constant-time** Ed25519 base-OT curve core — the "fix the lang limit" companion to
[`@atlasauth/pca-mpc`](../pca-mpc).

`pca-mpc`'s `ec.ts` is a correct, malicious-hardened prime-order group, but its BigInt modular
arithmetic is **not** constant-time and cannot be in pure JS — a real language/runtime boundary
(docs §7.1), the JS `@noble`/BigInt path being the fallback. The base OT multiplies **secret**
scalars into the curve (`S = y·B`, `T = y·S`, `R = x·B (+S)`, `y·R`, `x·S`), which is exactly where a
timing side-channel would leak the receiver's choice bit or the sender's `y`.

This package compiles those operations from [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek)
(audited, constant-time field + scalar multiplication) to a tiny, import-free WebAssembly module
(`wasm/pca_mpc_wasm.wasm`, ~45 KB) and re-exposes the base-OT curve-op surface of `ec.ts` on top of
it (`src/index.ts`).

## Ops exposed (drop-in for `ec.ts`)

`mulBase(k)` · `mul(k, P)` · `add(A, B)` · `sub(A, B)` · `neg(P)` · `encodePoint` / `decodePoint` ·
`isOnCurve` · `isIdentity` · `isInSubgroup` · `assertInSubgroup` · `equal` · `BASE` · `IDENTITY` ·
`L` · `Q`.

The constant-time, secret-dependent operations — `mulBase` and `mul` — run entirely inside the wasm.

## Point encoding

A point is its **canonical 32-byte compressed Ed25519 encoding** (little-endian `y`, sign of `x` in
the top bit): the bytes `@noble/curves` emits from `point.toRawBytes()` and the only serialization
`curve25519-dalek` exposes (it has no public affine accessor). This is more standard than `ec.ts`'s
bespoke 64-byte affine `x‖y` form; the two carry the same point and are inter-convertible. The
parity test cross-checks this 32-byte form against `@noble/curves` for **byte-identical** output.

Scalars are `bigint`, reduced `mod L` exactly as `ec.ts::mul` does, then handed to the wasm as
32-byte little-endian.

## Build

```sh
rustup target add wasm32-unknown-unknown   # once
pnpm --filter @atlasauth/pca-mpc-wasm build:wasm   # rebuild wasm/pca_mpc_wasm.wasm
pnpm --filter @atlasauth/pca-mpc-wasm test         # WASM-vs-@noble parity
```

The built `.wasm` is committed (small, reproducible artifact); `crate/` holds its Rust source.
