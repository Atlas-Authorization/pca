# @atlasauth/pca-bbs

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

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). **Experimental and unaudited.** The CFRG draft is not a final standard, and BBS on BLS12-381 is not post-quantum.

What is validated (ciphersuite BLS12-381-SHA-256 only):

- **Official fixture set** of draft-irtf-cfrg-bbs-signatures, vendored in `test-vectors/` with repository commit and per-file SHA-256: key generation, `hash_to_scalar`, message-to-scalar mapping, generators, all 10 signature cases (valid and invalid) and all 15 proof cases (valid and invalid). Signing reproduces the published signatures byte-for-byte, and proof generation with the published randomness reproduces the published proofs byte-for-byte. The fixtures are byte-identical across draft revisions -06 to -12.
- **Independent implementation**: the Rust crate `zkryptium` 0.7.1 (draft -12, on `bls12_381_plus`). Keys and signatures it produces are reproduced exactly, its randomized proofs verify here, and proofs and signatures produced here (including no-disclosure and full-disclosure selections) verify there. Tampered proofs and signatures are rejected on both sides. The runner source is in `test-vectors/xcheck-zkryptium`.
- **Rejection reasons** are asserted: `verifyDetailed` and `proofVerifyDetailed` report why something failed (malformed signature, public key or proof, pairing mismatch, challenge mismatch, bad disclosed indexes).

What is not validated:

- The SHAKE-256 ciphersuite, pseudonyms and blind signatures are not implemented.
- The credential layer (`issueCapabilityCredential`, `presentCredential`) is PCA-specific and has no external standard to test against; it is covered by this package's own tests only.
- Point arithmetic is variable-time; there is no constant-time guarantee and no independent audit.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
