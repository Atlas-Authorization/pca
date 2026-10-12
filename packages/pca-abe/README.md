# @atlasauth/pca-abe

Proof-carrying encryption for Proof-Carrying Authority (PCA). Tool payloads or results are sealed under an access policy over capability attributes (`holder:`, `verb:`, `resource:`, `scope:`, and bound `act:` verb-on-resource pairs), so they decrypt only for an agent whose PCA capability satisfies the policy. The construction is Bethencourt-Sahai-Waters ciphertext-policy ABE (IEEE S&P 2007, ePrint 2006/309) with a per-key randomiser, adapted to the asymmetric (type-3) pairing on BLS12-381, over a monotone AND/OR/threshold tree shared by Shamir secret sharing, with the payload sealed by AES-256-GCM. Keys issued to different holders cannot be pooled to satisfy a policy neither satisfies.

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

- Keys: `setup`, `keygenForAttributes`, `keygenForCapability`, `rerandomizeKey` (re-randomise a key, optionally to a subset of its attributes; needs only the public key).
- Raw bytes/text: `encryptForPolicy`, `decrypt`, `decryptText`, `parseCiphertext`.
- Tool payloads: `encryptToolPayload`, `decryptWithCapability`.
- Policies: `Policy` (`{ attr }`, `{ allOf }`, `{ anyOf }`, `{ threshold, of }`), `normalizePolicy`, `satisfies`, `policyAttributes`.
- Attributes: `Attr`, `capabilityAttributes`. A capability with ONE predicate yields flat `verb:`/`resource:` tokens plus `act:` pair tokens; a capability with TWO OR MORE predicates yields only `act:["verb","resource"]` pairs (plus `holder:`/`scope:`), so `read /public/*` + `write /acct/42` can never open a `read /acct/42` ciphertext (red-team RT-08; breaking: policies over flat tokens for multi-predicate capabilities must move to `Attr.act`). Predicate `where` conditions and other caveats are not encoded in any token. `scope:` tokens come only from the ROOT capability's caveats: a delegated hop's own `scope` caveats are restrictions, not grants (R2-07, breaking). For a delegated capability pass the chain, `capabilityAttributes(cap, { chain, principal })` / `keygenForCapability(msk, cap, [], { chain, principal })`; without a verified chain it gets no `scope:` tokens, and (R3-09, breaking) no `act:`/`verb:`/`resource:` tokens either, because the envelope is also read from the ROOT only (a delegatee-appended `envelope` caveat is a restriction and can no longer self-grant attributes); a chain that fails verification yields no attributes.

## Status

Research-grade, unaudited. Do not make it the only control for high-value data.

What holds, and under what assumptions:

- Collusion resistance. Every key carries a fresh randomiser `r`, so components of different keys do not combine; pooling two holders' keys (whole, or component by component) fails. This is tested, including against a py_ecc oracle for the key and ciphertext components and the pairing equations.
- The security notion of BSW07 is selective chosen-plaintext security (the adversary names the challenge policy before seeing the public key) in the generic bilinear group model, with the attribute hash as a random oracle. That proof is for the paper's symmetric pairing.

What is not established:

- The type-3 adaptation used here (which elements live in G1 and which in G2) is this package's own; it has no proof. No reduction to a standard assumption, no standard-model security.
- No adaptive security, and no CCA security of the ABE layer. AES-256-GCM over the whole header makes tampering detectable (integrity); that is not a CCA proof.
- The policy is public in the ciphertext (no attribute hiding). No key revocation. Whoever holds the master secret can decrypt everything. Policies are monotone (no negation).
- Not a zero-knowledge proof: confidentiality is bound to possession of capability-derived keys. Not post-quantum (pairing based). Not constant-time (JavaScript).
- Decryption costs one multi-pairing over the satisfied leaves; it is slower than the earlier per-attribute scheme.

Breaking change from earlier 0.x: key, public key, master key and ciphertext formats changed; old material is not readable.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
