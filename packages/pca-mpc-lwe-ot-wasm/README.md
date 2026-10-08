# @atlasauth/pca-mpc-lwe-ot-wasm

The **post-quantum, maliciously-secure endemic base-OT lattice core** for `@atlasauth/pca-mpc`.

`@atlasauth/pca-mpc`'s `kem-ot.ts` is a *semi-honest* ML-KEM base OT: a malicious receiver can keep
both ML-KEM secret keys and learn both messages, and an opaque KEM cannot detect it. This package
removes that residue by exposing exactly the Kyber-768 **IND-CPA (K-PKE)** primitives the **endemic
OT of Masny–Rindal (ePrint 2019/706)** needs, so that the non-chosen branch's public key is forced to
be a **uniform ring element** — provably undecryptable under **decisional Module-LWE**. The full
protocol lives in `@atlasauth/pca-mpc`'s `endemic-ot.ts`; this package is just the lattice core.

## The vetted boundary (no hand-rolled Kyber)

Every Module-LWE / Kyber operation — K-PKE key generation, CPA encryption, CPA decryption, and
therefore the NTT, matrix expansion, CBD noise, polynomial multiplication, compression and modular
reduction — runs through the **audited `pqc_kyber` reference implementation** (crates.io 0.7.1),
reached via its `hazmat` / `indcpa` surface and compiled to WebAssembly (`crate/`). The FO transform
is bypassed, which is exactly what an endemic OT requires.

This crate adds only three **non-cryptographic** pieces `pqc_kyber` does not re-export:

1. 12-bit (de)serialization of a public-key ring vector `t̂` (a byte-for-byte copy of the Kyber
   reference `poly_{to,from}bytes` packing);
2. coefficient-wise `t̂` addition / subtraction modulo the public prime `q = 3329` (plain modular
   vector arithmetic — NTT linearity makes this the ring sum, used for the additive endemic trick);
3. a random oracle into the ring: SHAKE128 + the standard FIPS-203 / Kyber `SampleNTT` rejection
   sampler, yielding a **uniform** `t̂` vector.

None of these is the Kyber PKE, its NTT, its noise sampler or its compression.

> `vendor/pqc_kyber` is `pqc_kyber` 0.7.1 with a **manifest-only** change (`crate-type = ["rlib"]`,
> so cargo does not try to build a std-less `cdylib` for `wasm32-unknown-unknown`). The algorithm
> source is byte-identical to the crates.io release; the `[patch.crates-io]` in `crate/Cargo.toml`
> wires it in. The package still pins `pqc_kyber = "0.7.1"` as the dependency of record.

## API

```ts
import {
  kpkeKeygen, kpkeEnc, kpkeDec, // Kyber-768 K-PKE (IND-CPA): deterministic keygen, CPA enc/dec
  ringAdd, ringSub,             // (a ± b) mod q over a serialized t̂
  hashToRing,                   // SHAKE128 -> uniform ring vector
  PK_BYTES, SK_BYTES, CT_BYTES, TVEC_BYTES, SYM_BYTES, // 1184 / 1152 / 1088 / 1152 / 32
} from '@atlasauth/pca-mpc-lwe-ot-wasm';
```

The WASM is `no_std`, allocator-free, instantiates with an **empty import object**, and is driven
through fixed static buffers in linear memory (mirrors `@atlasauth/pca-mpc-wasm`).

## Build & test

```sh
pnpm build:wasm   # cargo build --release --target wasm32-unknown-unknown + copy artifact + cargo clean
pnpm build        # tsc
pnpm test         # vitest (parity / KATs through the wasm binding)
```

Native KATs for the Kyber arithmetic (decryption correctness, deterministic regression vector, the
ring homomorphism, the uniform-branch endemic property) live in `crate/src/lib.rs`
(`cargo test --features hoststd`).

## Security achieved

- **Sender privacy (endemic):** a (even malicious) receiver cannot learn `m_{1−c}` — its branch has a
  uniform public key, so recovering the payload reduces to IND-CPA of K-PKE under a uniform key, i.e.
  **decisional Module-LWE**; and it cannot make both branches decryptable (Module-SIS).
- **Receiver choice privacy:** computational under **decisional Module-LWE**, even vs a quantum sender.
- **Post-quantum:** rests only on Module-LWE (ML-KEM-768, NIST category 3) + a random oracle.

Composed with the KOS correlation check in `@atlasauth/pca-mpc`'s `ot.ts`, `κ` endemic base OTs become
many **maliciously-secure, post-quantum** OTs.

**Honest residual:** the Kyber core is a prototype and is **not** claimed constant-time (a documented
side-channel boundary, not a break of the MLWE/ROM security); K-PKE has a negligible (~2⁻¹³⁹)
decryption-failure probability inherited from the primitive.
