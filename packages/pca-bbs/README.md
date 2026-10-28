# @atlasauth/pca-bbs

> Maturity: **hardened** (hardened, awaiting independent audit and final standard). The engineering is done and evidenced by the official draft fixtures, an independent implementation, abuse tests and a mutation gate; it awaits an independent review (O-1) and the final, published CFRG BBS standard (O-6), since the draft may still change. It is never production until both are done, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

BBS signatures (BLS12-381-SHA-256, following the IRTF CFRG BBS draft) for Proof-Carrying Authority (PCA). A PCA capability is issued as a multi-message BBS credential, then presented with selective disclosure and an unlinkable zero-knowledge proof of possession. An agent can reveal only the attributes a tool needs (for example the scope caveat) while hiding the rest (holder, budget, expiry), and two presentations of the same credential cannot be correlated.

There are two layers:

- the BBS core: `keyGen`, `createGenerators`, `messagesToScalars`, `sign`, `verify`, `proofGen`, `proofVerify`;
- the PCA layer: map a capability to an ordered attribute vector (`iss`, `sub`, then `cav:<i>:<type>` per caveat), issue it, present a subset, verify the presentation.

## Install

```sh
npm i @atlasauth/pca-bbs
```

Depends on `@atlasauth/pca`, `@noble/curves` and `@noble/hashes` (installed automatically).

## Usage

```ts
import {
  generateKeyPair, issueCapabilityCredential, presentCredential, verifyCredential, verifyPresentation,
} from '@atlasauth/pca-bbs';

const bytes = (s: string) => new TextEncoder().encode(s);

const capability = {
  issuer: 'issuer-public-key',
  holder: 'agent-public-key',
  caveats: [
    { type: 'scope', actions: ['search:read'] },
    { type: 'budget_alloc', limit: 100 },
  ],
};

const { sk, pk } = generateKeyPair();
const cred = issueCapabilityCredential(capability, { sk, pk });
verifyCredential(cred); // true: every attribute is signed by the issuer

// Reveal only the scope caveat, bound to one action so the proof cannot be replayed elsewhere.
const pres = presentCredential(cred, {
  disclose: ['cav:0:scope'],
  presentationHeader: bytes('action:search?q=atlas'),
});

verifyPresentation(pres); // true
verifyPresentation(pres, { pk, presentationHeader: bytes('action:search?q=atlas') }); // pin issuer + context
```

`presentCredential` throws if a requested attribute name does not exist. Pass a pinned `pk` and your own `presentationHeader` to `verifyPresentation` so the verifier asserts its own expectations rather than trusting the values carried in the presentation.

## Fail-closed behavior

Every row is pinned by a test that asserts the exact outcome or rejection reason.

| Missing or malformed input | Result |
|---|---|
| Signature not 80 octets, point A the identity or off the subgroup, scalar e zero or not below the group order | `verifyDetailed` returns `malformed-signature` |
| Public key the identity, off the subgroup, wrong length or flag-corrupted | `malformed-public-key` |
| Proof wrong length, an identity or off-subgroup point, or a scalar out of range | `malformed-proof` |
| Disclosed messages and indexes differ in count | `disclosed-length-mismatch` |
| Disclosed index duplicated, negative, fractional, NaN or out of range | `invalid-disclosed-indexes` (and `proofGen` throws) |
| Wrong header, presentation header, issuer key, disclosed value or disclosed index | `challenge-mismatch` or `pairing-mismatch`; never accepted |
| More than the maximum number of messages | signing and generator creation throw; verification rejects cheaply |
| Secret key zero, equal to or above the group order, or not 32 octets | `skFromBytes` throws; key material under 32 octets makes `keyGen` throw |
| Zero blinding scalar r1 or r2 supplied to `proofGen` | throws; no degenerate proof is produced |
| Entropy source returns all zeros | key generation throws |
| Attribute name containing the separator byte, or an unknown attribute at presentation | encoding or presentation throws |
| Malformed credential or presentation object | `verifyCredential` / `verifyPresentation` return false, never throw |

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). **Hardened, awaiting independent audit and final standard (the CFRG BBS draft).** The CFRG draft is not a final standard, and BBS on BLS12-381 is not post-quantum.

What is validated (ciphersuite BLS12-381-SHA-256 only):

- **Official fixture set** of draft-irtf-cfrg-bbs-signatures, vendored in `test-vectors/` with repository commit and per-file SHA-256: key generation, `hash_to_scalar`, message-to-scalar mapping, generators, all 10 signature cases (valid and invalid) and all 15 proof cases (valid and invalid). Signing reproduces the published signatures byte-for-byte, and proof generation with the published randomness reproduces the published proofs byte-for-byte. The fixtures are byte-identical across draft revisions -06 to -12.
- **Independent implementation**: the Rust crate `zkryptium` 0.7.1 (draft -12, on `bls12_381_plus`). Keys and signatures it produces are reproduced exactly, its randomized proofs verify here, and proofs and signatures produced here (including no-disclosure and full-disclosure selections) verify there. Tampered proofs and signatures are rejected on both sides. The runner source is in `test-vectors/xcheck-zkryptium`.
- **Rejection reasons** are asserted: `verifyDetailed` and `proofVerifyDetailed` report why something failed (malformed signature, public key or proof, pairing mismatch, challenge mismatch, bad disclosed indexes).

What is not validated:

- The SHAKE-256 ciphersuite, pseudonyms and blind signatures are not implemented.
- The credential layer (`issueCapabilityCredential`, `presentCredential`) is PCA-specific and has no external standard to test against; it is covered by this package's own tests only.
- Secret-scalar point multiplications (signing key, `1/(SK+e)`, signed messages, the prover's blinding scalars) use the library's fixed-window multiply with a fake point (`Point.multiply`), and secret inversions use Fermat exponentiation; `multiplyUnsafe` remains only for public verifier scalars. A dudect-style test (`ct.test.ts`: Welch t on interleaved weight-1 versus weight-253 scalars, fail at `|t| >= 10` with a median shift over 5%) passes, and a positive control with the variable-time multiply is detected. This is **not** a constant-time guarantee: JavaScript BigInt arithmetic and the JIT/GC have data-dependent timing, and the library's window method indexes a precomputed table by secret digits (a cache-timing channel). Use a native or WebAssembly constant-time implementation, or an HSM, for long-lived issuer keys facing a co-resident attacker. No independent audit.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
