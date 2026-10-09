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

Cryptography is unaudited. The BBS implementation follows the CFRG draft and is checked against its test vectors, but the draft is not a final standard. BBS on BLS12-381 is not post-quantum.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
