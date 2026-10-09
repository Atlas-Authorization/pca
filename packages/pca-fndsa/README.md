# @atlasauth/pca-fndsa

FN-DSA (Falcon, FIPS 206 draft) signature suites for Proof-Carrying Authority. It defines the suite ids, the fixed wire sizes, strict length enforcement and the PCA leaf-signature framing (pure and hybrid with Ed25519). The Falcon arithmetic itself is delegated to a pluggable backend, because a constant-time Falcon is not something to hand-roll in TypeScript. Use [`@atlasauth/pca-fndsa-wasm`](https://www.npmjs.com/package/@atlasauth/pca-fndsa-wasm) as the backend.

FN-DSA keys and signatures are much smaller than ML-DSA's, which helps on bandwidth-bound surfaces.

| suite id | public key | signature |
| --- | --- | --- |
| `fn-dsa-512` | 897 B | 666 B (padded) |
| `fn-dsa-1024` | 1793 B | 1280 B (padded) |
| `hybrid-ed25519-fn-dsa-512` / `-1024` | as above | Ed25519 in `sig`, FN-DSA in `pq_sig`; both must verify |

## Install

```sh
npm i @atlasauth/pca-fndsa @atlasauth/pca-fndsa-wasm
```

Depends on `@atlasauth/pca`. No backend is bundled: without one, signing and verification throw a clear error.

## Usage

Register a backend once, then sign and verify. The backend receives raw bytes, so pick the variant from the key length.

```ts
import { randomBytes } from 'node:crypto';
import * as wasm from '@atlasauth/pca-fndsa-wasm';
import { setFalconBackend, getFalconBackend, fndsaSign, fndsaVerify } from '@atlasauth/pca-fndsa';

const variantOf = (n: number) => (n === 897 || n === 1345 ? 'fn-dsa-512' : 'fn-dsa-1024');

setFalconBackend({
  keygen: () => {
    const { verifyingKey, signingKey } = wasm.keygen('fn-dsa-512', randomBytes(wasm.SEED_BYTES));
    return { pk: verifyingKey, sk: signingKey };
  },
  sign: (sk, msg) => wasm.sign(variantOf(sk.length), sk, msg, randomBytes(wasm.SEED_BYTES)),
  verify: (pk, msg, sig) => wasm.verify(variantOf(pk.length), pk, msg, sig),
});

const { pk, sk } = getFalconBackend().keygen!();
const msg = new TextEncoder().encode('hello');
const sig = fndsaSign('fn-dsa-512', sk, msg);      // 666-byte padded signature
fndsaVerify('fn-dsa-512', pk, msg, sig);           // true
```

For PCA artifacts, `signPcaWithFndsa({ alg, leaf, fnDsa, edSecret? })` returns the wire fields (`sig`, `alg`, `pq_pk`, and `pq_sig` for hybrid suites) and `verifyPcaFndsa({ alg, leaf, holder, pq_pk, sig, pq_sig })` checks them. Verification fails closed on an unknown suite, wrong key or signature length, a tampered action or a suite downgrade, and a hybrid suite needs both halves to verify.

## API

`FN_DSA_SUITES`, `isKnownFnDsaAlg`, `resolveFnDsaAlg`, `setFalconBackend`, `getFalconBackend`, `resetFalconBackend`, `fndsaSign`, `fndsaVerify`, `signPcaWithFndsa`, `verifyPcaFndsa`, `fndsaLeafMessage`, and the size constants. `registerTestBackend` and `mockKeypair` install a deterministic mock for tests only; never use them in production.

## Status

Experimental and unaudited. The suite wiring (wire format, length checks, hybrid composition, PCActn leaf framing) is tested against the real `@atlasauth/pca-fndsa-wasm` backend for both parameter sets, with tampered action, swapped key, forged signature and missing/forged hybrid half rejected. The deterministic mock backend is kept only for wiring and negative-plumbing tests. The FN-DSA primitive itself has no official test vectors (none exist yet); see the backend package for what is cross-checked. FIPS 206 is still a draft, so key and signature encodings may change before the final standard. Signatures use the fixed-length padded encoding only. The core `@atlasauth/pca` verifier does not itself recognise these suite ids; verify FN-DSA artifacts with `verifyPcaFndsa`.

## License

MIT - see LICENSE
