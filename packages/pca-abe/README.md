# @atlasauth/pca-abe

Proof-carrying encryption for Proof-Carrying Authority (PCA). Tool payloads or results are sealed under an access policy over capability attributes (`holder:`, `verb:`, `resource:`, `scope:`), so they decrypt only for an agent whose PCA capability satisfies the policy. The construction is a Boneh-Franklin identity-based KEM on BLS12-381 composed over a monotone AND/OR/threshold tree by Shamir secret sharing, with the payload sealed by AES-256-GCM.

## Install

```sh
npm i @atlasauth/pca-abe
```

Depends on `@atlasauth/pca`, `@noble/curves` and `@noble/hashes` (installed transitively).

## Usage

```ts
import { generateKeyPair, mintGrant, b64u, DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import {
  setup, keygenForCapability, encryptToolPayload, decryptWithCapability, Attr,
} from '@atlasauth/pca-abe';

// A capability bound to an agent, authorising `read` on /tickets/*.
const principal = generateKeyPair();
const agentPub = b64u(generateKeyPair().publicKey);
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: b64u(principal.publicKey),
  holder: agentPub,
  goal: 'read tickets',
  envelope: {
    predicates: [{ verb: 'read', resource: '/tickets/*' }],
    caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY,
  },
});

// The issuer holds the master key; the encryptor only needs the public half.
const { mpk, msk } = setup();
const policy = { allOf: [{ attr: Attr.holder(agentPub) }, { attr: Attr.verb('read') }] };
const { ciphertext } = encryptToolPayload(mpk, policy, { ticket: 'T-42' });

// The issuer derives a key from the capability and hands it to the agent.
const key = keygenForCapability(msk, grant);
decryptWithCapability(key, ciphertext); // { ok: true, payload: { ticket: 'T-42' } }
```

A key derived from a capability that does not satisfy the policy gets `{ ok: false, reason }`.

## API

- Keys: `setup`, `keygenForAttributes`, `keygenForCapability`.
- Raw bytes/text: `encryptForPolicy`, `decrypt`, `decryptText`, `parseCiphertext`.
- Tool payloads: `encryptToolPayload`, `decryptWithCapability`.
- Policies: `Policy` (`{ attr }`, `{ allOf }`, `{ anyOf }`, `{ threshold, of }`), `normalizePolicy`, `satisfies`, `policyAttributes`.
- Attributes: `Attr`, `capabilityAttributes`.

## Status

Experimental and unaudited. Confidentiality rests on the Bilinear Diffie-Hellman assumption (random-oracle model); integrity on AES-256-GCM. Policies are monotone (no negation). This binds confidentiality to possession of capability-derived keys, not to a zero-knowledge proof, and collusion resistance holds only within a single issued key: two separately issued keys could pool attributes. Issue one key per capability. The scheme is not post-quantum.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
